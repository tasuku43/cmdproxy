package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tasuku43/cmdproxy/internal/buildinfo"
	"github.com/tasuku43/cmdproxy/internal/config"
	"github.com/tasuku43/cmdproxy/internal/doctor"
	"github.com/tasuku43/cmdproxy/internal/domain/policy"
	"github.com/tasuku43/cmdproxy/internal/input"
)

const (
	exitAllow  = 0
	exitError  = 1
	exitReject = 2
)

type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type Env struct {
	Cwd           string
	Home          string
	XDGConfigHome string
	XDGCacheHome  string
}

func Run(args []string, streams Streams, env Env) int {
	if len(args) == 0 {
		writeUsage(streams.Stdout)
		return exitError
	}

	switch args[0] {
	case "hook":
		return runHook(args[1:], streams, env)
	case "check":
		return runCheck(args[1:], streams, env)
	case "test":
		return runTest(args[1:], streams, env)
	case "doctor":
		return runDoctor(args[1:], streams, env)
	case "verify":
		return runVerify(args[1:], streams, env)
	case "init":
		return runInit(args[1:], streams, env)
	case "version":
		return runVersion(args[1:], streams)
	case "-h", "--help", "help":
		if len(args) > 1 {
			writeCommandHelp(streams.Stdout, args[1])
		} else {
			writeUsage(streams.Stdout)
		}
		return exitAllow
	default:
		writeErr(streams.Stderr, "unknown command: "+args[0])
		return exitError
	}
}

func runHook(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "hook")
		return exitAllow
	}
	useRTK := false
	switch {
	case len(args) == 1 && args[0] == "claude":
	case len(args) == 2 && args[0] == "claude" && args[1] == "--rtk":
		useRTK = true
	default:
		writeCommandHelp(streams.Stderr, "hook")
		return exitError
	}
	raw, err := io.ReadAll(streams.Stdin)
	if err != nil {
		return emitClaudeHookError(streams, "runtime_error", err.Error())
	}

	req, err := input.Normalize(raw)
	if err != nil {
		return emitClaudeHookError(streams, "invalid_input", err.Error())
	}
	return runClaudeHook(req, useRTK, streams, env)
}

func runCheck(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "check")
		return exitAllow
	}
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) == 0 {
		writeCommandHelp(streams.Stderr, "check")
		return exitError
	}
	req := input.ExecRequest{Action: "exec", Command: strings.Join(rest, " ")}
	return evaluateRequest(req, format, streams, env)
}

func runTest(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "test")
		return exitAllow
	}
	if len(args) != 0 {
		writeCommandHelp(streams.Stderr, "test")
		return exitError
	}
	loaded := config.LoadEffective(env.Home, env.XDGConfigHome)
	if len(loaded.Errors) > 0 {
		for _, msg := range policy.ErrorStrings(loaded.Errors) {
			writeErr(streams.Stderr, msg)
		}
		return exitError
	}

	report := doctor.Run(loaded, env.Home)
	for _, check := range report.Checks {
		if check.ID == "tests.pass" && check.Status == doctor.StatusFail {
			writeErr(streams.Stderr, check.Message)
			return exitError
		}
	}

	rewriteCount := len(loaded.Pipeline.Rewrite)
	permissionCount := len(loaded.Pipeline.Permission.Deny) + len(loaded.Pipeline.Permission.Ask) + len(loaded.Pipeline.Permission.Allow)
	testCount := 0
	for _, step := range loaded.Pipeline.Rewrite {
		testCount += len(step.Test)
	}
	for _, rule := range loaded.Pipeline.Permission.Deny {
		testCount += len(rule.Test.Deny) + len(rule.Test.Pass)
	}
	for _, rule := range loaded.Pipeline.Permission.Ask {
		testCount += len(rule.Test.Ask) + len(rule.Test.Pass)
	}
	for _, rule := range loaded.Pipeline.Permission.Allow {
		testCount += len(rule.Test.Allow) + len(rule.Test.Pass)
	}
	testCount += len(loaded.Pipeline.Test)
	fmt.Fprintf(streams.Stdout, "ok: %d rewrite steps, %d permission rules, %d tests checked\n", rewriteCount, permissionCount, testCount)
	return exitAllow
}

func runDoctor(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "doctor")
		return exitAllow
	}
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) != 0 {
		writeCommandHelp(streams.Stderr, "doctor")
		return exitError
	}
	loaded := config.LoadEffective(env.Home, env.XDGConfigHome)
	report := doctor.Run(loaded, env.Home)

	if format == "json" {
		enc := json.NewEncoder(streams.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
	} else {
		for _, check := range report.Checks {
			fmt.Fprintf(streams.Stdout, "[%s] %s: %s\n", strings.ToUpper(string(check.Status)), check.ID, check.Message)
		}
	}

	if doctor.HasFailures(report) {
		return exitError
	}
	return exitAllow
}

func runVerify(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "verify")
		return exitAllow
	}
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) != 0 {
		writeCommandHelp(streams.Stderr, "verify")
		return exitError
	}
	loaded := config.LoadEffective(env.Home, env.XDGConfigHome)
	report := doctor.Run(loaded, env.Home)
	info := buildinfo.Read()
	ok, reasons := verifyStatus(report, info)
	artifactBuilt := false
	if ok {
		for _, src := range config.ConfigPaths(env.Home, env.XDGConfigHome) {
			rules, err := config.VerifyFileToAllCaches(src, config.HookCacheDirs(env.Home, env.XDGCacheHome), info.Version)
			if err != nil {
				ok = false
				reasons = append(reasons, err.Error())
				break
			}
			if len(rules.Rewrite) > 0 || !policy.IsZeroPermissionSpec(rules.Permission) || len(rules.Test) > 0 {
				artifactBuilt = true
			}
		}
	}

	if format == "json" {
		payload := map[string]any{
			"verified":       ok,
			"build_info":     info,
			"report":         report,
			"artifact_built": artifactBuilt,
			"artifact_cache": config.HookCacheDirs(env.Home, env.XDGCacheHome),
		}
		if len(reasons) > 0 {
			payload["failures"] = reasons
		}
		enc := json.NewEncoder(streams.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
	} else {
		fmt.Fprintf(streams.Stdout, "cmdproxy %s\n", info.Version)
		if info.VCSRevision != "" {
			fmt.Fprintf(streams.Stdout, "vcs.revision: %s\n", info.VCSRevision)
		} else {
			fmt.Fprintln(streams.Stdout, "vcs.revision: <missing>")
		}
		for _, check := range report.Checks {
			fmt.Fprintf(streams.Stdout, "[%s] %s: %s\n", strings.ToUpper(string(check.Status)), check.ID, check.Message)
		}
		if ok {
			fmt.Fprintln(streams.Stdout, "verified: true")
			if artifactBuilt {
				fmt.Fprintf(streams.Stdout, "artifact: %s\n", strings.Join(config.HookCacheDirs(env.Home, env.XDGCacheHome), ", "))
			}
		} else {
			fmt.Fprintln(streams.Stdout, "verified: false")
			for _, reason := range reasons {
				fmt.Fprintf(streams.Stdout, "failure: %s\n", reason)
			}
		}
	}

	if !ok {
		return exitError
	}
	return exitAllow
}

func runInit(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "init")
		return exitAllow
	}
	if len(args) != 0 {
		writeCommandHelp(streams.Stderr, "init")
		return exitError
	}
	configDir := filepath.Join(userConfigBase(env.Home, env.XDGConfigHome), "cmdproxy")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		writeErr(streams.Stderr, err.Error())
		return exitError
	}
	configPath := filepath.Join(configDir, "cmdproxy.yml")
	created := false
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(configPath, []byte(starterConfig), 0o644); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
		created = true
	}

	if created {
		fmt.Fprintf(streams.Stdout, "created %s\n", configPath)
	} else {
		fmt.Fprintf(streams.Stdout, "exists %s\n", configPath)
	}
	fmt.Fprintf(streams.Stdout, "user config: %s\n", configPath)

	claudeSettings := filepath.Join(env.Home, ".claude", "settings.json")
	if _, err := os.Stat(claudeSettings); err == nil {
		fmt.Fprintf(streams.Stdout, "detected Claude Code settings: %s\n", claudeSettings)
	} else {
		fmt.Fprintf(streams.Stdout, "Claude Code settings not found: %s\n", claudeSettings)
	}

	fmt.Fprintln(streams.Stdout, "hook snippet:")
	fmt.Fprintln(streams.Stdout, `{"matcher":"Bash","hooks":[{"type":"command","command":"cmdproxy hook claude --rtk"}]}`)
	return exitAllow
}

func runVersion(args []string, streams Streams) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "version")
		return exitAllow
	}
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) != 0 {
		writeCommandHelp(streams.Stderr, "version")
		return exitError
	}
	info := buildinfo.Read()
	if format == "json" {
		enc := json.NewEncoder(streams.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
		return exitAllow
	}
	fmt.Fprintf(streams.Stdout, "cmdproxy %s\n", info.Version)
	fmt.Fprintf(streams.Stdout, "module: %s\n", info.Module)
	if info.GoVersion != "" {
		fmt.Fprintf(streams.Stdout, "go: %s\n", info.GoVersion)
	}
	if info.VCSRevision != "" {
		fmt.Fprintf(streams.Stdout, "vcs.revision: %s\n", info.VCSRevision)
	}
	if info.VCSTime != "" {
		fmt.Fprintf(streams.Stdout, "vcs.time: %s\n", info.VCSTime)
	}
	if info.VCSModified != "" {
		fmt.Fprintf(streams.Stdout, "vcs.modified: %s\n", info.VCSModified)
	}
	return exitAllow
}

func verifyStatus(report doctor.Report, info buildinfo.Info) (bool, []string) {
	var reasons []string

	for _, check := range report.Checks {
		if check.Status == doctor.StatusFail {
			reasons = append(reasons, check.ID+": "+check.Message)
			continue
		}
		if check.ID == "install.claude-registered" && check.Status == doctor.StatusWarn && strings.Contains(check.Message, "settings found but") {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
		if check.ID == "install.claude-hook-path" && check.Status == doctor.StatusWarn {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
		if (check.ID == "install.claude-hook-target" || check.ID == "install.claude-hook-binary-match") && check.Status == doctor.StatusWarn {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
	}
	if info.VCSRevision == "" {
		reasons = append(reasons, "build metadata missing: prefer a binary built with embedded VCS info")
	}

	return len(reasons) == 0, reasons
}

func evaluateRequest(req input.ExecRequest, format string, streams Streams, env Env) int {
	decision, err := evaluateDecision(req, env)
	if err != nil {
		return emitError(streams, format, "runtime_error", err.Error())
	}
	return emitDecision(streams, format, decision)
}

func evaluateDecision(req input.ExecRequest, env Env) (policy.Decision, error) {
	loaded := config.LoadEffectiveForHook(env.Home, env.XDGConfigHome, env.XDGCacheHome)
	if len(loaded.Errors) > 0 {
		if shouldAttemptImplicitVerify(loaded.Errors) {
			if err := ensureVerifiedArtifacts(env); err == nil {
				loaded = config.LoadEffectiveForHook(env.Home, env.XDGConfigHome, env.XDGCacheHome)
			}
		}
		if len(loaded.Errors) > 0 {
			return policy.Decision{}, errors.New(strings.Join(policy.ErrorStrings(loaded.Errors), "; "))
		}
	}

	decision, err := policy.Evaluate(loaded.Pipeline, req.Command)
	if err != nil {
		return policy.Decision{}, err
	}
	return decision, nil
}

func shouldAttemptImplicitVerify(errs []error) bool {
	if len(errs) == 0 {
		return false
	}
	for _, msg := range policy.ErrorStrings(errs) {
		if strings.Contains(msg, "verified artifact not found") || strings.Contains(msg, "changed since last verify") {
			return true
		}
	}
	return false
}

func ensureVerifiedArtifacts(env Env) error {
	info := buildinfo.Read()
	for _, src := range config.ConfigPaths(env.Home, env.XDGConfigHome) {
		if _, err := config.VerifyFileToAllCaches(src, config.HookCacheDirs(env.Home, env.XDGCacheHome), info.Version); err != nil {
			return err
		}
	}
	return nil
}

func emitDecision(streams Streams, format string, decision policy.Decision) int {
	if format == "json" {
		payload := map[string]any{
			"decision":         decision.Outcome,
			"command":          decision.Command,
			"original_command": decision.OriginalCommand,
			"message":          decision.Message,
			"trace":            decision.Trace,
		}
		_ = json.NewEncoder(streams.Stdout).Encode(payload)
	} else {
		fmt.Fprintf(streams.Stdout, "%s: %s\n", decision.Outcome, decision.Command)
	}
	if decision.Outcome == "deny" {
		return exitReject
	}
	return exitAllow
}

func runClaudeHook(req input.ExecRequest, useRTK bool, streams Streams, env Env) int {
	decision, err := evaluateDecision(req, env)
	if err != nil {
		return emitClaudeHookError(streams, "invalid_config", err.Error())
	}
	if useRTK && decision.Outcome != "deny" {
		decision = applyRTKRewrite(decision)
	}

	switch decision.Outcome {
	case "allow", "ask":
		reason := "cmdproxy permission evaluated"
		hookOutput := map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecisionReason": reason,
		}
		if decision.Command != req.Command {
			hookOutput["updatedInput"] = map[string]any{"command": decision.Command}
		}
		if decision.Outcome == "allow" {
			hookOutput["permissionDecision"] = "allow"
		}
		payload := map[string]any{
			"systemMessage":      buildRewriteSystemMessage(decision),
			"hookSpecificOutput": hookOutput,
			"cmdproxy": map[string]any{
				"outcome": decision.Outcome,
				"trace":   decision.Trace,
			},
		}
		_ = json.NewEncoder(streams.Stdout).Encode(payload)
		return exitAllow
	case "deny":
		reason := decision.Message
		if strings.TrimSpace(reason) == "" {
			reason = "cmdproxy denied by policy"
		}
		payload := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
			"cmdproxy": map[string]any{
				"outcome": "deny",
				"trace":   decision.Trace,
			},
		}
		_ = json.NewEncoder(streams.Stdout).Encode(payload)
		return exitAllow
	default:
		return emitClaudeHookError(streams, "runtime_error", "unsupported decision outcome")
	}
}

func emitClaudeHookError(streams Streams, code string, message string) int {
	payload := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": "cmdproxy " + code + ": " + message,
		},
	}
	_ = json.NewEncoder(streams.Stdout).Encode(payload)
	return exitAllow
}

func applyRTKRewrite(decision policy.Decision) policy.Decision {
	rewritten, ok := runRTKRewrite(decision.Command)
	if !ok || rewritten == decision.Command {
		return decision
	}
	decision.Trace = append(decision.Trace, policy.TraceStep{
		Action: "rewrite",
		Name:   "rtk",
		From:   decision.Command,
		To:     rewritten,
	})
	decision.Command = rewritten
	return decision
}

func runRTKRewrite(command string) (string, bool) {
	out, err := exec.Command("rtk", "rewrite", command).CombinedOutput()
	if err != nil && len(out) == 0 {
		return "", false
	}
	rewritten := strings.TrimSpace(string(out))
	if rewritten == "" || rewritten == command {
		return "", false
	}
	return rewritten, true
}

func buildRewriteSystemMessage(decision policy.Decision) string {
	if len(decision.Trace) == 0 {
		return "cmdproxy: rewrote -> " + decision.Command
	}
	ruleIDs := make([]string, 0, len(decision.Trace))
	for _, step := range decision.Trace {
		if step.Action != "rewrite" {
			continue
		}
		ruleIDs = append(ruleIDs, step.Name)
	}
	if len(ruleIDs) == 0 {
		return "cmdproxy: rewrote -> " + decision.Command
	}
	return fmt.Sprintf("cmdproxy: rewrote [%s] -> %s", strings.Join(ruleIDs, " -> "), decision.Command)
}

func emitError(streams Streams, format string, code string, message string) int {
	if format == "json" {
		_ = json.NewEncoder(streams.Stdout).Encode(map[string]any{
			"decision": "error",
			"error": map[string]string{
				"code":    code,
				"message": message,
			},
		})
	} else {
		writeErr(streams.Stderr, message)
	}
	return exitError
}

func parseCommonFlags(args []string) (string, []string, error) {
	format := ""
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 >= len(args) {
				return "", nil, errors.New("missing --format value")
			}
			format = args[i+1]
			i++
		default:
			rest = append(rest, args[i])
		}
	}
	if format != "" && format != "json" {
		return "", nil, fmt.Errorf("unsupported format %q", format)
	}
	return format, rest, nil
}

func writeUsage(w io.Writer) {
	fmt.Fprint(w, `cmdproxy

Declarative, testable command policy for AI-agent shell commands.

Typical workflow:
  1. Edit ~/.config/cmdproxy/cmdproxy.yml
  2. Add rewrite, permission, and E2E tests
  3. Run cmdproxy test
  4. Use cmdproxy check for spot checks
  5. Let Claude Code call cmdproxy hook claude --rtk from PreToolUse

Usage:
  cmdproxy <command> [flags]

Commands:
  init     create the user config and print the Claude Code hook snippet
  test     validate every rule example; this is the main authoring command
  check    evaluate one command string interactively
  doctor   inspect config quality and installation state
  verify   verify local trust-critical setup and build metadata
  version  print build and source metadata for the running binary
  hook     Claude Code hook entrypoint

Help:
  cmdproxy help <command>
  cmdproxy <command> --help
  cmdproxy help config
  cmdproxy help rewrite
  cmdproxy help match

Examples:
  cmdproxy init
  cmdproxy test
  cmdproxy check --format json 'git -C repo status'
  cmdproxy verify --format json
  cmdproxy version --format json
  cmdproxy hook claude --rtk
  cmdproxy doctor --format json
`)
}

func writeCommandHelp(w io.Writer, command string) {
	switch command {
	case "init":
		fmt.Fprint(w, `cmdproxy init

Create ~/.config/cmdproxy/cmdproxy.yml when it does not exist and print the
Claude Code PreToolUse hook snippet.

Usage:
  cmdproxy init

Typical use:
  cmdproxy init
`)
	case "test":
		fmt.Fprint(w, `cmdproxy test

Validate the full pipeline in ~/.config/cmdproxy/cmdproxy.yml.
This is the main command to run after editing policy.

Usage:
  cmdproxy test

What it checks:
  - every rewrite step test expect/pass case
  - every permission rule test expect/pass case
  - every top-level E2E test expect case

Typical use:
  $EDITOR ~/.config/cmdproxy/cmdproxy.yml
  cmdproxy test
`)
	case "check":
		fmt.Fprint(w, `cmdproxy check

Evaluate one command string against the current rule set.
Use this while authoring rules before relying on Claude Code hooks.

Usage:
  cmdproxy check [--format json] <command>

Examples:
  cmdproxy check 'git -C repo status'
  cmdproxy check --format json 'AWS_PROFILE=read-only-profile aws s3 ls'
`)
	case "doctor":
		fmt.Fprint(w, `cmdproxy doctor

Inspect config validity, pipeline quality, and Claude Code hook registration.

Usage:
  cmdproxy doctor [--format json]

Examples:
  cmdproxy doctor
  cmdproxy doctor --format json
`)
	case "verify":
		fmt.Fprint(w, `cmdproxy verify

Verify the local trust-critical cmdproxy setup.
This command is stricter than doctor: it fails when the config is broken, when
Claude settings point somewhere unexpected, or when build metadata is missing.

Usage:
  cmdproxy verify [--format json]

Examples:
  cmdproxy verify
  cmdproxy verify --format json
`)
	case "hook":
		fmt.Fprint(w, `cmdproxy hook claude

Claude Code hook entrypoint.
Reads stdin JSON, evaluates the configured rewrite and permission pipeline, and
returns Claude Code hook JSON for allow, ask, deny, or error outcomes.

Usage:
  cmdproxy hook claude [--rtk]

Options:
  --rtk   run "rtk rewrite" once after cmdproxy policy evaluation and return
          the final rewritten command if it changes

Note:
  You usually do not run this manually. Edit rules and use cmdproxy test or
  cmdproxy check instead.
`)
	case "version":
		fmt.Fprint(w, `cmdproxy version

Print build metadata for the running binary. Use this to inspect the module,
Go toolchain, and VCS information embedded in the installed executable.

Usage:
  cmdproxy version [--format json]

Examples:
  cmdproxy version
  cmdproxy version --format json
`)
	case "config":
		fmt.Fprint(w, `cmdproxy help config

Config files live at ~/.config/cmdproxy/cmdproxy.yml.

Top-level sections are:
  - rewrite: ordered rewrite pipeline
  - permission: deny / ask / allow buckets
  - test: end-to-end expect cases

Rewrite step example:
  rewrite:
    - match:
        command: aws
        args_contains:
          - "--profile"
      move_flag_to_env:
        flag: "--profile"
        env: "AWS_PROFILE"
      strict: true
      continue: true
      test:
        - in: "aws --profile read-only-profile s3 ls"
          out: "AWS_PROFILE=read-only-profile aws s3 ls"
        - pass: "AWS_PROFILE=read-only-profile aws s3 ls"

Permission rule example:
  permission:
    allow:
      - match:
          command: aws
          subcommand: sts
          env_requires:
            - "AWS_PROFILE"
        test:
          allow:
            - "AWS_PROFILE=read-only-profile aws sts get-caller-identity"
          pass:
            - "AWS_PROFILE=read-only-profile aws s3 ls"

E2E test example:
  test:
    - in: "aws --profile read-only-profile sts get-caller-identity"
      rewritten: "AWS_PROFILE=read-only-profile aws sts get-caller-identity"
      decision: allow

For matcher fields, run:
  cmdproxy help match

For rewrite primitives, run:
  cmdproxy help rewrite
`)
	case "match":
		fmt.Fprint(w, `cmdproxy help match

Supported match fields:
  - command: exact executable name
  - command_in: executable must be one of these names
  - subcommand: exact first subcommand
  - args_contains: exact arg tokens that must exist
  - args_prefixes: arg tokens that must start with these prefixes
  - env_requires: env vars that must be present
  - env_missing: env vars that must be absent

Example:
  match:
    command: aws
    args_prefixes:
      - "--profile"

Pattern is still supported when shell-shape matching is easier than argv
matching.

Example:
  pattern: '^\s*cd\s+[^&;|]+\s*(&&|;|\|)'
`)
	case "rewrite":
		fmt.Fprint(w, `cmdproxy help rewrite

Supported rewrite primitives:
  - unwrap_shell_dash_c: unwrap safe "bash -c 'single command'" payloads
  - unwrap_wrapper: strip safe wrappers such as env, command, exec, nohup
  - move_flag_to_env: move a flag value into an env assignment
  - move_env_to_flag: move an env assignment into a flag
  - strip_command_path: convert an absolute-path command token into its basename
  - continue: after a successful rewrite, restart evaluation from the top

Each rewrite step is an element in the top-level rewrite array and may add an
optional match block. If match is omitted, the step is considered for every
command.

Example:
  rewrite:
    - match:
        command: aws
        args_contains:
          - "--profile"
      move_flag_to_env:
        flag: "--profile"
        env: "AWS_PROFILE"
      strict: true
      continue: true
      test:
        - in: "aws --profile read-only-profile s3 ls"
          out: "AWS_PROFILE=read-only-profile aws s3 ls"
        - pass: "AWS_PROFILE=read-only-profile aws s3 ls"

Each step may set exactly one rewrite primitive.
`)
	default:
		writeUsage(w)
	}
}

func wantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func writeErr(w io.Writer, msg string) {
	fmt.Fprintln(w, msg)
}

func userConfigBase(home string, xdgConfigHome string) string {
	if xdgConfigHome != "" {
		return xdgConfigHome
	}
	return filepath.Join(home, ".config")
}

const starterConfig = `permission:
  deny:
    - match:
        command: git
        args_contains:
          - "-C"
      message: "git -C is blocked. Change into the target directory and rerun the command."
      test:
        deny:
          - "git -C repos/foo status"
        pass:
          - "git status"
test:
  - in: "git -C repos/foo status"
    decision: deny
`
