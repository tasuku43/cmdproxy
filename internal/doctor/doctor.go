package doctor

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tasuku43/cmdproxy/internal/buildinfo"
	"github.com/tasuku43/cmdproxy/internal/config"
	"github.com/tasuku43/cmdproxy/internal/domain/policy"
	"github.com/tasuku43/cmdproxy/internal/integration"
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
	Checks []Check `json:"checks"`
}

func Run(loaded config.Loaded, tool string, cwd string, home string) Report {
	var checks []Check

	if len(loaded.Errors) == 0 {
		checks = append(checks,
			Check{ID: "config.parse", Category: "config", Status: StatusPass, Message: "configuration files parsed"},
			Check{ID: "config.schema", Category: "config", Status: StatusPass, Message: "configuration schema is valid"},
			Check{ID: "rewrite.matcher-validate", Category: "rewrite", Status: StatusPass, Message: "rewrite matchers are valid"},
			Check{ID: "rewrite.tests-present", Category: "rewrite", Status: StatusPass, Message: "rewrite tests are present"},
			Check{ID: "permission.tests-present", Category: "permission", Status: StatusPass, Message: "permission tests are present"},
			Check{ID: "test.e2e-present", Category: "test", Status: StatusPass, Message: "end-to-end tests are present"},
		)
	} else {
		msg := strings.Join(policy.ErrorStrings(loaded.Errors), "; ")
		checks = append(checks,
			Check{ID: "config.parse", Category: "config", Status: StatusFail, Message: msg},
			Check{ID: "config.schema", Category: "config", Status: StatusFail, Message: msg},
			Check{ID: "rewrite.matcher-validate", Category: "rewrite", Status: StatusFail, Message: msg},
			Check{ID: "rewrite.tests-present", Category: "rewrite", Status: StatusFail, Message: msg},
			Check{ID: "permission.tests-present", Category: "permission", Status: StatusFail, Message: msg},
			Check{ID: "test.e2e-present", Category: "test", Status: StatusFail, Message: msg},
		)
	}

	if len(loaded.Errors) == 0 {
		if err := testsPass(loaded.Pipeline, tool, cwd, home); err != nil {
			checks = append(checks, Check{ID: "tests.pass", Category: "test", Status: StatusFail, Message: err.Error()})
		} else {
			checks = append(checks, Check{ID: "tests.pass", Category: "test", Status: StatusPass, Message: "rewrite, permission, and end-to-end tests match expectations"})
		}
	} else {
		checks = append(checks, Check{ID: "tests.pass", Category: "test", Status: StatusFail, Message: "skipped because configuration is invalid"})
	}

	if ids := relaxedRewriteNames(loaded.Pipeline); len(ids) > 0 {
		checks = append(checks, Check{ID: "rewrite.relaxed-contracts", Category: "rewrite", Status: StatusWarn, Message: "relaxed rewrite contracts enabled: " + strings.Join(ids, ", ")})
	} else {
		checks = append(checks, Check{ID: "rewrite.relaxed-contracts", Category: "rewrite", Status: StatusPass, Message: "all rewrite contracts use strict validation"})
	}

	if warning := broadnessWarning(loaded.Pipeline); warning != "" {
		checks = append(checks, Check{ID: "rewrite.pattern-broadness", Category: "diagnostics", Status: StatusWarn, Message: warning})
	} else {
		checks = append(checks, Check{ID: "rewrite.pattern-broadness", Category: "diagnostics", Status: StatusPass, Message: "rewrite matches are not obviously broad"})
	}

	if path, err := exec.LookPath("cmdproxy"); err == nil {
		checks = append(checks, Check{ID: "install.binary-on-path", Category: "install", Status: StatusPass, Message: "cmdproxy found on PATH at " + path})
	} else {
		checks = append(checks, Check{ID: "install.binary-on-path", Category: "install", Status: StatusWarn, Message: "cmdproxy not found on PATH"})
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

	if tool == integration.ToolClaude {
		claudeSettings := filepath.Join(home, ".claude", "settings.json")
		if _, err := os.Stat(claudeSettings); err == nil {
			data, readErr := os.ReadFile(claudeSettings)
			if readErr == nil && strings.Contains(string(data), "cmdproxy hook claude") && strings.Contains(string(data), "\"matcher\": \"Bash\"") {
				checks = append(checks, Check{ID: "install.claude-registered", Category: "install", Status: StatusPass, Message: "Claude Code hook registration detected"})
			} else {
				checks = append(checks, Check{ID: "install.claude-registered", Category: "install", Status: StatusWarn, Message: "Claude Code settings found but cmdproxy hook claude not detected"})
			}
		} else {
			checks = append(checks, Check{ID: "install.claude-registered", Category: "install", Status: StatusWarn, Message: "Claude Code settings.json not found"})
		}
	}

	return Report{Checks: checks}
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
	for i, step := range p.Rewrite {
		for _, ex := range step.Test {
			if strings.TrimSpace(ex.Pass) != "" {
				if rewritten, ok := policyTestApplyRewrite(step, ex.Pass); ok && rewritten != "" {
					return &exampleError{Scope: "rewrite", Name: stepName(step, i), Kind: "pass", Example: ex.Pass}
				}
				continue
			}
			rewritten, ok := policyTestApplyRewrite(step, ex.In)
			if !ok || rewritten != ex.Out {
				return &exampleError{Scope: "rewrite", Name: stepName(step, i), Kind: "expect", Example: ex.In}
			}
		}
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
				if !policy.PermissionRuleMatches(rule, ex) {
					return &exampleError{Scope: scope, Name: scopeName(scope, i), Kind: "expect", Example: ex}
				}
			}
			for _, ex := range rule.Test.Pass {
				if policy.PermissionRuleMatches(rule, ex) {
					return &exampleError{Scope: scope, Name: scopeName(scope, i), Kind: "pass", Example: ex}
				}
			}
		}
		return nil
	}
	if err := checkPermission("permission.deny", p.Permission.Deny, "deny"); err != nil {
		return err
	}
	if err := checkPermission("permission.ask", p.Permission.Ask, "ask"); err != nil {
		return err
	}
	if err := checkPermission("permission.allow", p.Permission.Allow, "allow"); err != nil {
		return err
	}

	for i, ex := range p.Test {
		decision, err := policy.Evaluate(p, ex.In)
		if err != nil {
			return err
		}
		decision = integration.ApplyPermissionBridge(tool, decision, cwd, home)
		if decision.Outcome != ex.Decision {
			return &exampleError{Scope: "test", Name: scopeName("e2e", i), Kind: "decision", Example: ex.In}
		}
		if strings.TrimSpace(ex.Rewritten) != "" && decision.Command != ex.Rewritten {
			return &exampleError{Scope: "test", Name: scopeName("e2e", i), Kind: "rewritten", Example: ex.In}
		}
	}
	return nil
}

func policyTestApplyRewrite(step policy.RewriteStepSpec, command string) (string, bool) {
	if !policy.RewriteStepMatches(step, command) {
		return "", false
	}
	return policy.ApplyRewriteStepForTest(step, command)
}

func broadnessWarning(p policy.Pipeline) string {
	for i, step := range p.Rewrite {
		if policy.IsZeroMatchSpec(step.Match) && strings.TrimSpace(step.Pattern) == "" && len(step.Patterns) == 0 {
			return "rewrite[" + scopeName("global", i) + "] applies to all commands"
		}
	}
	return ""
}

func relaxedRewriteNames(p policy.Pipeline) []string {
	var ids []string
	for i, step := range p.Rewrite {
		if !policy.RewriteStrict(step) {
			ids = append(ids, stepName(step, i))
		}
	}
	return ids
}

type exampleError struct {
	Scope   string
	Name    string
	Kind    string
	Example string
}

func (e *exampleError) Error() string {
	return e.Scope + " " + e.Name + " has failing " + e.Kind + " example: " + e.Example
}

func scopeName(prefix string, idx int) string {
	return prefix + "[" + fmtInt(idx) + "]"
}

func stepName(step policy.RewriteStepSpec, idx int) string {
	name := policy.RewriteStepName(step)
	if name == "" {
		return scopeName("rewrite", idx)
	}
	return name
}

func fmtInt(v int) string {
	return strconv.Itoa(v)
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
		if command, ok := v["command"].(string); ok && strings.Contains(command, "cmdproxy hook claude") {
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
