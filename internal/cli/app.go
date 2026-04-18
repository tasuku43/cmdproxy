package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tasuku43/cmdguard/internal/doctor"
	"github.com/tasuku43/cmdguard/internal/engine"
	"github.com/tasuku43/cmdguard/internal/input"
	"github.com/tasuku43/cmdguard/internal/rule"
)

const (
	exitAllow = 0
	exitError = 1
	exitDeny  = 2
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
}

func Run(args []string, streams Streams, env Env) int {
	if len(args) == 0 {
		writeErr(streams.Stderr, "usage: cmdguard <eval|check|test|doctor|init|add> [flags]")
		return exitError
	}

	switch args[0] {
	case "eval":
		return runEval(args[1:], streams, env)
	case "check":
		return runCheck(args[1:], streams, env)
	case "test":
		return runTest(args[1:], streams, env)
	case "doctor":
		return runDoctor(args[1:], streams, env)
	case "init":
		return runInit(args[1:], streams, env)
	case "add":
		writeErr(streams.Stderr, "cmdguard add is not implemented yet")
		return exitError
	case "-h", "--help", "help":
		writeUsage(streams.Stdout)
		return exitAllow
	default:
		writeErr(streams.Stderr, "unknown command: "+args[0])
		return exitError
	}
}

func runEval(args []string, streams Streams, env Env) int {
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) != 0 {
		writeErr(streams.Stderr, "usage: cmdguard eval [--format json]")
		return exitError
	}
	raw, err := io.ReadAll(streams.Stdin)
	if err != nil {
		return emitError(streams, format, "runtime_error", err.Error())
	}

	req, err := input.Normalize(raw)
	if err != nil {
		return emitError(streams, format, "invalid_input", err.Error())
	}
	return evaluateRequest(req, format, streams, env)
}

func runCheck(args []string, streams Streams, env Env) int {
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) == 0 {
		writeErr(streams.Stderr, "usage: cmdguard check [--format json] <command>")
		return exitError
	}
	req := input.ExecRequest{Action: "exec", Command: strings.Join(rest, " ")}
	return evaluateRequest(req, format, streams, env)
}

func runTest(args []string, streams Streams, env Env) int {
	if len(args) != 0 {
		writeErr(streams.Stderr, "usage: cmdguard test")
		return exitError
	}
	loaded := rule.LoadEffective(env.Cwd, env.Home, env.XDGConfigHome)
	if len(loaded.Errors) > 0 {
		for _, msg := range rule.ErrorStrings(loaded.Errors) {
			writeErr(streams.Stderr, msg)
		}
		return exitError
	}

	report := doctor.Run(loaded, env.Home)
	for _, check := range report.Checks {
		if check.ID == "rules.examples-pass" && check.Status == doctor.StatusFail {
			writeErr(streams.Stderr, check.Message)
			return exitError
		}
	}

	ruleCount := len(loaded.Rules)
	exampleCount := 0
	for _, r := range loaded.Rules {
		exampleCount += len(r.BlockExamples) + len(r.AllowExamples)
	}
	fmt.Fprintf(streams.Stdout, "ok: %d rules, %d examples checked\n", ruleCount, exampleCount)
	return exitAllow
}

func runDoctor(args []string, streams Streams, env Env) int {
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) != 0 {
		writeErr(streams.Stderr, "usage: cmdguard doctor [--format json]")
		return exitError
	}
	loaded := rule.LoadEffective(env.Cwd, env.Home, env.XDGConfigHome)
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

func runInit(args []string, streams Streams, env Env) int {
	if len(args) != 0 {
		writeErr(streams.Stderr, "usage: cmdguard init")
		return exitError
	}
	configPath := filepath.Join(env.Cwd, ".cmdguard.yml")
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
	fmt.Fprintf(streams.Stdout, "user config: %s\n", filepath.Join(userConfigBase(env.Home, env.XDGConfigHome), "cmdguard", "cmdguard.yml"))

	claudeSettings := filepath.Join(env.Home, ".claude", "settings.json")
	if _, err := os.Stat(claudeSettings); err == nil {
		fmt.Fprintf(streams.Stdout, "detected Claude Code settings: %s\n", claudeSettings)
	} else {
		fmt.Fprintf(streams.Stdout, "Claude Code settings not found: %s\n", claudeSettings)
	}

	fmt.Fprintln(streams.Stdout, "hook snippet:")
	fmt.Fprintln(streams.Stdout, `{"matcher":"Bash","hooks":[{"type":"command","command":"cmdguard eval"}]}`)
	return exitAllow
}

func evaluateRequest(req input.ExecRequest, format string, streams Streams, env Env) int {
	loaded := rule.LoadEffective(env.Cwd, env.Home, env.XDGConfigHome)
	if len(loaded.Errors) > 0 {
		return emitError(streams, format, "invalid_config", strings.Join(rule.ErrorStrings(loaded.Errors), "; "))
	}

	decision, err := engine.Evaluate(loaded.Rules, req)
	if err != nil {
		return emitError(streams, format, "runtime_error", err.Error())
	}
	if decision.Allowed {
		if format == "json" {
			_ = json.NewEncoder(streams.Stdout).Encode(map[string]any{"decision": "allow"})
		}
		return exitAllow
	}

	if format == "json" {
		payload := map[string]any{
			"decision": "deny",
			"rule_id":  decision.Rule.ID,
			"message":  decision.Rule.Message,
			"command":  decision.Command,
			"source":   decision.Rule.Source,
		}
		_ = json.NewEncoder(streams.Stdout).Encode(payload)
	} else {
		fmt.Fprintf(streams.Stderr, "[%s] %s\n", decision.Rule.ID, decision.Rule.Message)
	}
	return exitDeny
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
	fmt.Fprintln(w, "usage: cmdguard <eval|check|test|doctor|init|add> [flags]")
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

const starterConfig = `version: 1
rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    message: "git -C は禁止。cd で移動してから実行してください。"
    block_examples:
      - "git -C repos/foo status"
    allow_examples:
      - "git status"
      - "# git -C in comment"
`
