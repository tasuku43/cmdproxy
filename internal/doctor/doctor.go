package doctor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tasuku43/cmdguard/internal/rule"
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

func Run(loaded rule.Loaded, home string) Report {
	var checks []Check

	if len(loaded.Errors) == 0 {
		checks = append(checks,
			Check{ID: "config.parse", Category: "config", Status: StatusPass, Message: "configuration files parsed"},
			Check{ID: "config.schema", Category: "config", Status: StatusPass, Message: "configuration schema is valid"},
			Check{ID: "rules.unique-id", Category: "rules", Status: StatusPass, Message: "rule IDs are unique"},
			Check{ID: "rules.matcher-validate", Category: "rules", Status: StatusPass, Message: "rule matchers are valid"},
			Check{ID: "rules.examples-present", Category: "rules", Status: StatusPass, Message: "examples are present"},
		)
	} else {
		msg := strings.Join(rule.ErrorStrings(loaded.Errors), "; ")
		checks = append(checks,
			Check{ID: "config.parse", Category: "config", Status: StatusFail, Message: msg},
			Check{ID: "config.schema", Category: "config", Status: StatusFail, Message: msg},
			Check{ID: "rules.unique-id", Category: "rules", Status: StatusFail, Message: msg},
			Check{ID: "rules.matcher-validate", Category: "rules", Status: StatusFail, Message: msg},
			Check{ID: "rules.examples-present", Category: "rules", Status: StatusFail, Message: msg},
		)
	}

	if len(loaded.Errors) == 0 {
		if err := examplesPass(loaded.Rules); err != nil {
			checks = append(checks, Check{ID: "rules.examples-pass", Category: "rules", Status: StatusFail, Message: err.Error()})
		} else {
			checks = append(checks, Check{ID: "rules.examples-pass", Category: "rules", Status: StatusPass, Message: "examples match expectations"})
		}
	} else {
		checks = append(checks, Check{ID: "rules.examples-pass", Category: "rules", Status: StatusFail, Message: "skipped because configuration is invalid"})
	}

	if warning := broadnessWarning(loaded.Rules); warning != "" {
		checks = append(checks, Check{ID: "rules.pattern-broadness", Category: "diagnostics", Status: StatusWarn, Message: warning})
	} else {
		checks = append(checks, Check{ID: "rules.pattern-broadness", Category: "diagnostics", Status: StatusPass, Message: "patterns are not obviously broad"})
	}

	if warning := shadowingWarning(loaded.Rules); warning != "" {
		checks = append(checks, Check{ID: "rules.shadowing", Category: "diagnostics", Status: StatusWarn, Message: warning})
	} else {
		checks = append(checks, Check{ID: "rules.shadowing", Category: "diagnostics", Status: StatusPass, Message: "no obvious shadowing detected"})
	}

	if path, err := exec.LookPath("cmdguard"); err == nil {
		checks = append(checks, Check{ID: "install.binary-on-path", Category: "install", Status: StatusPass, Message: "cmdguard found on PATH at " + path})
	} else {
		checks = append(checks, Check{ID: "install.binary-on-path", Category: "install", Status: StatusWarn, Message: "cmdguard not found on PATH"})
	}

	claudeSettings := filepath.Join(home, ".claude", "settings.json")
	if _, err := os.Stat(claudeSettings); err == nil {
		data, readErr := os.ReadFile(claudeSettings)
		if readErr == nil && strings.Contains(string(data), "cmdguard eval") && strings.Contains(string(data), "\"matcher\": \"Bash\"") {
			checks = append(checks, Check{ID: "install.claude-registered", Category: "install", Status: StatusPass, Message: "Claude Code hook registration detected"})
		} else {
			checks = append(checks, Check{ID: "install.claude-registered", Category: "install", Status: StatusWarn, Message: "Claude Code settings found but cmdguard eval hook not detected"})
		}
	} else {
		checks = append(checks, Check{ID: "install.claude-registered", Category: "install", Status: StatusWarn, Message: "Claude Code settings.json not found"})
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

func examplesPass(rules []rule.Rule) error {
	for _, r := range rules {
		for _, ex := range r.BlockExamples {
			matched, err := r.Match(ex)
			if err != nil {
				return err
			}
			if !matched {
				return &exampleError{RuleID: r.ID, Kind: "block", Example: ex}
			}
		}
		for _, ex := range r.AllowExamples {
			matched, err := r.Match(ex)
			if err != nil {
				return err
			}
			if matched {
				return &exampleError{RuleID: r.ID, Kind: "allow", Example: ex}
			}
		}
	}
	return nil
}

type exampleError struct {
	RuleID  string
	Kind    string
	Example string
}

func (e *exampleError) Error() string {
	return "rule " + e.RuleID + " has failing " + e.Kind + " example: " + e.Example
}

func broadnessWarning(rules []rule.Rule) string {
	for _, r := range rules {
		if r.Pattern == "" {
			continue
		}
		if r.Pattern == ".*" || r.Pattern == "^.*$" || r.Pattern == ".+" || r.Pattern == "^.+$" {
			return "rule " + r.ID + " pattern is extremely broad"
		}
	}
	return ""
}

func shadowingWarning(rules []rule.Rule) string {
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			for _, ex := range rules[j].BlockExamples {
				matched, err := rules[i].Match(ex)
				if err != nil {
					continue
				}
				if matched {
					return "rule " + rules[i].ID + " likely shadows later rule " + rules[j].ID
				}
			}
		}
	}
	return ""
}
