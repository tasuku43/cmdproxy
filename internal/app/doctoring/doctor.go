package doctoring

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tasuku43/cc-bash-guard/internal/adapter/claude"
	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
	"github.com/tasuku43/cc-bash-guard/internal/infra/buildinfo"
	configrepo "github.com/tasuku43/cc-bash-guard/internal/infra/config"
)

type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

type Check struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Status   Status `json:"status"`
	Message  string `json:"message"`
}

type Report struct {
	Tool                       string              `json:"tool,omitempty"`
	ConfigSources              []configrepo.Source `json:"config_sources,omitempty"`
	SettingsPaths              []string            `json:"settings_paths,omitempty"`
	EffectiveFingerprint       string              `json:"effective_fingerprint,omitempty"`
	VerifiedArtifactExists     bool                `json:"verified_artifact_exists"`
	VerifiedArtifactCompatible bool                `json:"verified_artifact_compatible"`
	Checks                     []Check             `json:"checks"`
}

func Run(loaded configrepo.Loaded, tool string, cwd string, home string) Report {
	var checks []Check

	if len(loaded.Errors) == 0 {
		checks = append(checks,
			Check{ID: "config.parse", Category: "config", Status: StatusPass, Message: "configuration files parsed"},
			Check{ID: "config.schema", Category: "config", Status: StatusPass, Message: "configuration schema is valid"},
			Check{ID: "permission.tests-present", Category: "permission", Status: StatusPass, Message: "permission tests are present"},
			Check{ID: "test.e2e-present", Category: "test", Status: StatusPass, Message: "end-to-end tests are present"},
		)
	} else {
		msg := strings.Join(policy.ErrorStrings(loaded.Errors), "; ")
		checks = append(checks,
			Check{ID: "config.parse", Category: "config", Status: StatusFail, Message: msg},
			Check{ID: "config.schema", Category: "config", Status: StatusFail, Message: msg},
			Check{ID: "permission.tests-present", Category: "permission", Status: StatusFail, Message: msg},
			Check{ID: "test.e2e-present", Category: "test", Status: StatusFail, Message: msg},
		)
		if strings.Contains(msg, "top-level rewrite is no longer supported") {
			checks = append(checks, Check{
				ID:       "config.rewrite-migration",
				Category: "config",
				Status:   StatusFail,
				Message:  "rewrite migration: unwrap_shell_dash_c is now built-in CommandPlan parsing; strip_command_path is basename command normalization; move_flag_to_env is no longer supported, use AWS semantic profile matching and document preferred command style in CLAUDE.md or user docs",
			})
		}
	}

	if len(loaded.Errors) == 0 {
		if err := testsPass(loaded.Pipeline, tool, cwd, home); err != nil {
			checks = append(checks, Check{ID: "tests.pass", Category: "test", Status: StatusFail, Message: err.Error()})
		} else {
			checks = append(checks, Check{ID: "tests.pass", Category: "test", Status: StatusPass, Message: "permission and end-to-end tests match expectations"})
		}
	} else {
		checks = append(checks, Check{ID: "tests.pass", Category: "test", Status: StatusFail, Message: "skipped because configuration is invalid"})
	}

	if ids := envOnlyAllowNames(loaded.Pipeline); len(ids) > 0 {
		checks = append(checks, Check{ID: "permission.env-only-allow", Category: "permission", Status: StatusWarn, Message: "env-only allow rules are broad: " + strings.Join(ids, ", ")})
	} else {
		checks = append(checks, Check{ID: "permission.env-only-allow", Category: "permission", Status: StatusPass, Message: "no env-only allow rules"})
	}

	if ids := broadAllowNames(loaded.Pipeline); len(ids) > 0 {
		checks = append(checks, Check{ID: "permission.broad-allow", Category: "permission", Status: StatusWarn, Message: "broad allow rules found: " + strings.Join(ids, ", ") + "; move broad namespaces to permission.ask and keep permission.allow semantic or narrow"})
	} else {
		checks = append(checks, Check{ID: "permission.broad-allow", Category: "permission", Status: StatusPass, Message: "no broad allow rules detected"})
	}

	if tool == claude.Tool {
		checks = append(checks, Check{ID: "permission.source-merge-rule", Category: "permission", Status: StatusPass, Message: "permission sources are merged using deny > ask > allow > abstain"})
	}

	if path, err := exec.LookPath("cc-bash-guard"); err == nil {
		checks = append(checks, Check{ID: "install.binary-on-path", Category: "install", Status: StatusPass, Message: "cc-bash-guard found on PATH at " + path})
	} else {
		checks = append(checks, Check{ID: "install.binary-on-path", Category: "install", Status: StatusWarn, Message: "cc-bash-guard not found on PATH"})
	}

	if exe, err := os.Executable(); err == nil {
		checks = append(checks, Check{ID: "install.binary-executable", Category: "install", Status: StatusPass, Message: "running binary: " + exe})
	} else {
		checks = append(checks, Check{ID: "install.binary-executable", Category: "install", Status: StatusWarn, Message: "running binary path could not be determined"})
	}

	bi := buildinfo.Read()
	if bi.VCSRevision != "" {
		msg := "build metadata available"
		if bi.VCSModified != "" {
			msg += " (vcs.modified=" + bi.VCSModified + ")"
		}
		checks = append(checks, Check{ID: "install.binary-build-info", Category: "install", Status: StatusPass, Message: msg})
	} else {
		checks = append(checks, Check{ID: "install.binary-build-info", Category: "install", Status: StatusWarn, Message: "build metadata missing; prefer binaries built with VCS info embedded"})
	}

	if tool == claude.Tool {
		claudeSettings := filepath.Join(home, ".claude", "settings.json")
		checks = append(checks, claudeHookRegistrationCheck(claudeSettings))
	}

	return Report{Checks: checks}
}

func AddVerifiedArtifactCheck(report Report, status configrepo.EffectiveArtifactStatus) Report {
	report.VerifiedArtifactExists = status.Exists
	report.VerifiedArtifactCompatible = status.Compatible
	if status.Compatible {
		report.Checks = append(report.Checks, Check{ID: "artifact.evaluation-semantics", Category: "artifact", Status: StatusPass, Message: status.Message})
		return report
	}
	if status.Exists {
		report.Checks = append(report.Checks, Check{ID: "artifact.evaluation-semantics", Category: "artifact", Status: StatusFail, Message: status.Message})
		return report
	}
	report.Checks = append(report.Checks, Check{ID: "artifact.evaluation-semantics", Category: "artifact", Status: StatusWarn, Message: status.Message + "; hook enforcement requires a current verified artifact"})
	return report
}

func HasFailures(report Report) bool {
	for _, check := range report.Checks {
		if check.Status == StatusFail {
			return true
		}
	}
	return false
}

func testsPass(p policy.Pipeline, tool string, cwd string, home string) error {
	failures := CollectTestFailures(p, tool, cwd, home, false)
	if len(failures) > 0 {
		return failures[0]
	}
	return nil
}

type TestFailure struct {
	Scope       string
	Name        string
	Kind        string
	Example     string
	Source      policy.Source
	Expected    string
	Got         string
	Reason      string
	Decision    policy.Decision
	Policy      string
	Claude      string
	Final       string
	MatchedRule *policy.TraceStep
}

func (e TestFailure) Error() string {
	return (&exampleError{
		Scope:    e.Scope,
		Name:     e.Name,
		Kind:     e.Kind,
		Example:  e.Example,
		Source:   e.Source,
		Expected: e.Expected,
		Got:      e.Got,
	}).Error()
}

func CollectTestFailures(p policy.Pipeline, tool string, cwd string, home string, all bool) []TestFailure {
	var failures []TestFailure
	add := func(f TestFailure) bool {
		failures = append(failures, f)
		return !all
	}
	checkPermission := func(scope string, rules []policy.PermissionRuleSpec, effect string) error {
		for i, rule := range rules {
			var expect []string
			switch effect {
			case "deny":
				expect = rule.Test.Deny
			case "ask":
				expect = rule.Test.Ask
			case "allow":
				expect = rule.Test.Allow
			}
			for _, ex := range expect {
				if !permissionRuleMatchesEffect(rule, ex, effect) {
					if add(TestFailure{Scope: scope, Name: scopeName(scope, i), Kind: "expect", Example: ex, Source: rule.Source, Expected: effect}) {
						return errStopTests
					}
				}
			}
			for _, ex := range append(append([]string{}, rule.Test.Abstain...), rule.Test.Pass...) {
				if permissionRuleMatchesEffect(rule, ex, effect) {
					if add(TestFailure{Scope: scope, Name: scopeName(scope, i), Kind: "abstain", Example: ex, Source: rule.Source, Expected: "abstain", Got: effect}) {
						return errStopTests
					}
				}
			}
		}
		return nil
	}
	if err := checkPermission("permission.deny", p.Permission.Deny, "deny"); err != nil {
		return failures
	}
	if err := checkPermission("permission.ask", p.Permission.Ask, "ask"); err != nil {
		return failures
	}
	if err := checkPermission("permission.allow", p.Permission.Allow, "allow"); err != nil {
		return failures
	}

	for _, ex := range p.Test {
		decision, err := policy.Evaluate(p, ex.In)
		if err != nil {
			if add(TestFailure{Scope: "test", Name: scopeName("test", ex.Source.Index), Kind: "evaluate", Example: ex.In, Source: ex.Source, Expected: ex.Decision, Got: "error", Reason: err.Error()}) {
				return failures
			}
			continue
		}
		policyOutcome := decision.Outcome
		if ex.AssertPolicyOutcome {
			if policyOutcome != ex.Decision {
				f := TestFailure{
					Scope:    "test",
					Name:     scopeName("test", ex.Source.Index),
					Kind:     "policy_outcome",
					Example:  ex.In,
					Source:   ex.Source,
					Expected: ex.Decision,
					Got:      policyOutcome,
					Reason:   decisionReason(decision),
					Decision: decision,
					Policy:   policyOutcome,
				}
				if add(f) {
					return failures
				}
			}
			continue
		}
		decision = claude.ApplyPermissionBridge(tool, decision, cwd, home)
		if decision.Outcome != ex.Decision {
			claudeOutcome, finalOutcome := traceDecisions(decision.Trace, decision.Outcome)
			f := TestFailure{
				Scope:       "test",
				Name:        scopeName("test", ex.Source.Index),
				Kind:        "decision",
				Example:     ex.In,
				Source:      ex.Source,
				Expected:    ex.Decision,
				Got:         decision.Outcome,
				Reason:      decisionReason(decision),
				Decision:    decision,
				Policy:      policyOutcome,
				Claude:      claudeOutcome,
				Final:       finalOutcome,
				MatchedRule: matchedRuleTrace(decision.Trace),
			}
			if add(f) {
				return failures
			}
		}
	}
	return failures
}

var errStopTests = errors.New("stop after first test failure")

func traceDecisions(trace []policy.TraceStep, fallback string) (string, string) {
	claudeOutcome := "abstain"
	finalOutcome := fallback
	for _, step := range trace {
		if step.Action != "permission" {
			continue
		}
		switch step.Name {
		case "claude_settings":
			if step.Effect != "" {
				claudeOutcome = step.Effect
			}
		case "permission_sources_merge":
			if step.Effect != "" {
				finalOutcome = step.Effect
			}
		}
	}
	return claudeOutcome, finalOutcome
}

func decisionReason(decision policy.Decision) string {
	switch decision.Reason {
	case "rule_match":
		return "cc-bash-guard policy " + decision.Outcome
	case "claude_settings":
		return "Claude settings " + decision.Outcome
	case "default_fallback":
		return "all permission sources abstained; fallback ask"
	case "":
		return decision.Outcome
	default:
		return decision.Reason
	}
}

func matchedRuleTrace(trace []policy.TraceStep) *policy.TraceStep {
	for i := len(trace) - 1; i >= 0; i-- {
		step := trace[i]
		if step.Action != "permission" || step.Source == nil {
			continue
		}
		return &step
	}
	return nil
}

func envOnlyAllowNames(p policy.Pipeline) []string {
	var ids []string
	for i, rule := range p.Permission.Allow {
		if policy.IsZeroPermissionCommandSpec(rule.Command) && len(rule.Patterns) == 0 && !policy.IsZeroPermissionEnvSpec(rule.Env) {
			ids = append(ids, scopeName("permission.allow", i))
		}
	}
	return ids
}

func broadAllowNames(p policy.Pipeline) []string {
	var ids []string
	for i, rule := range p.Permission.Allow {
		name := scopeName("permission.allow", i)
		if strings.TrimSpace(rule.Name) != "" {
			name += " " + strconv.Quote(rule.Name)
		}
		if policy.IsZeroPermissionCommandSpec(rule.Command) && len(rule.Patterns) == 0 && !policy.IsZeroPermissionEnvSpec(rule.Env) {
			ids = append(ids, name)
			continue
		}
		if cmd := strings.TrimSpace(rule.Command.Name); cmd != "" && rule.Command.Semantic == nil {
			if _, ok := semanticpkg.Lookup(cmd); ok || isScriptRunnerOrInterpreter(cmd) {
				ids = append(ids, name)
				continue
			}
		}
		if len(rule.Command.NameIn) > 0 && rule.Command.Semantic == nil {
			for _, raw := range rule.Command.NameIn {
				cmd := strings.TrimSpace(raw)
				if _, ok := semanticpkg.Lookup(cmd); ok || isScriptRunnerOrInterpreter(cmd) {
					ids = append(ids, name)
					break
				}
			}
		}
		for _, pattern := range rule.Patterns {
			if isBroadAllowPattern(pattern) {
				ids = append(ids, name)
				break
			}
		}
	}
	return ids
}

func isScriptRunnerOrInterpreter(cmd string) bool {
	switch cmd {
	case "bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl", "make", "npm", "yarn", "pnpm", "npx", "xargs", "ssh":
		return true
	default:
		return false
	}
}

func isBroadAllowPattern(pattern string) bool {
	p := strings.TrimSpace(pattern)
	if p == ".*" || p == "^.*" || p == "^.*$" || !strings.HasPrefix(p, "^") {
		return true
	}
	for _, cmd := range []string{"git", "aws", "kubectl", "gh", "gws", "helm", "helmfile", "argocd", "terraform", "docker", "bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl", "make", "npm", "yarn", "pnpm", "npx", "xargs", "ssh"} {
		if strings.HasPrefix(p, "^"+cmd+`\s+.*`) || strings.HasPrefix(p, "^"+cmd+`\b`) || strings.HasPrefix(p, "^"+cmd+".*") {
			return true
		}
	}
	return false
}

func permissionRuleMatchesEffect(rule policy.PermissionRuleSpec, command string, effect string) bool {
	if effect == "allow" {
		return policy.PermissionAllowRuleMatches(rule, command)
	}
	return policy.PermissionRuleMatches(rule, command)
}

type exampleError struct {
	Scope    string
	Name     string
	Kind     string
	Example  string
	Source   policy.Source
	Expected string
	Got      string
}

func (e *exampleError) Error() string {
	prefix := ""
	if e.Source.Path != "" {
		prefix = e.Source.Path + " "
	}
	if e.Expected != "" || e.Got != "" {
		return prefix + e.Name + " expected " + e.Expected + ", got " + e.Got + ": " + e.Example
	}
	return prefix + e.Scope + " " + e.Name + " has failing " + e.Kind + " example: " + e.Example
}

func scopeName(prefix string, idx int) string {
	return prefix + "[" + fmtInt(idx) + "]"
}

func fmtInt(v int) string {
	return strconv.Itoa(v)
}

func claudeHookRegistrationCheck(path string) Check {
	check := Check{ID: "install.claude-registered", Category: "install", Status: StatusWarn}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			check.Message = "Claude Code settings.json not found"
			return check
		}
		check.Message = "Claude Code settings.json could not be read: " + err.Error()
		return check
	}

	registration, err := inspectClaudeHookRegistration(data)
	if err != nil {
		check.Message = "Claude Code settings.json is malformed JSON: " + err.Error()
		return check
	}
	if registration.BashHookCommand != "" {
		if registration.BashHookCount > 1 {
			check.Message = "multiple Claude Code Bash hooks detected; ensure cc-bash-guard is installed once and RTK is not also registered as a separate Bash hook"
			return check
		}
		check.Status = StatusPass
		check.Message = "Claude Code Bash hook registration detected"
		return check
	}
	if registration.NonBashHookCommand != "" {
		check.Message = "cc-bash-guard hook exists but matcher is not Bash"
		return check
	}
	if registration.BashMatcher {
		check.Message = "Bash matcher exists but cc-bash-guard hook is missing"
		return check
	}
	check.Message = "Claude Code settings found but cc-bash-guard hook not detected"
	return check
}

type claudeHookRegistration struct {
	BashHookCommand    string
	NonBashHookCommand string
	BashMatcher        bool
	BashHookCount      int
}

func inspectClaudeHookRegistration(data []byte) (claudeHookRegistration, error) {
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return claudeHookRegistration{}, err
	}
	return findClaudeHookRegistration(payload, ""), nil
}

func extractClaudeHookCommand(raw string) (string, bool) {
	var payload any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "", false
	}
	command := findHookCommand(payload)
	return command, strings.HasPrefix(command, "/")
}

func findHookCommand(node any) string {
	switch v := node.(type) {
	case map[string]any:
		if command, ok := v["command"].(string); ok && strings.Contains(command, "cc-bash-guard hook") {
			return command
		}
		for _, value := range v {
			if command := findHookCommand(value); command != "" {
				return command
			}
		}
	case []any:
		for _, value := range v {
			if command := findHookCommand(value); command != "" {
				return command
			}
		}
	}
	return ""
}

func findClaudeHookRegistration(node any, inheritedMatcher string) claudeHookRegistration {
	var result claudeHookRegistration
	switch v := node.(type) {
	case map[string]any:
		matcher := inheritedMatcher
		if value, ok := v["matcher"].(string); ok {
			matcher = value
			if value == "Bash" {
				result.BashMatcher = true
			}
		}
		if command, ok := v["command"].(string); ok && strings.Contains(command, "cc-bash-guard hook") {
			if matcher == "Bash" {
				result.BashHookCommand = command
			} else {
				result.NonBashHookCommand = command
			}
		}
		if command, ok := v["command"].(string); ok && matcher == "Bash" && strings.TrimSpace(command) != "" {
			result.BashHookCount++
		}
		for _, value := range v {
			result = mergeClaudeHookRegistration(result, findClaudeHookRegistration(value, matcher))
		}
	case []any:
		for _, value := range v {
			result = mergeClaudeHookRegistration(result, findClaudeHookRegistration(value, inheritedMatcher))
		}
	}
	return result
}

func mergeClaudeHookRegistration(a claudeHookRegistration, b claudeHookRegistration) claudeHookRegistration {
	if a.BashHookCommand == "" {
		a.BashHookCommand = b.BashHookCommand
	}
	if a.NonBashHookCommand == "" {
		a.NonBashHookCommand = b.NonBashHookCommand
	}
	a.BashMatcher = a.BashMatcher || b.BashMatcher
	a.BashHookCount += b.BashHookCount
	return a
}
