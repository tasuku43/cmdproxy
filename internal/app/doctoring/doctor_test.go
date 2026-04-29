package doctoring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
	configrepo "github.com/tasuku43/cc-bash-guard/internal/infra/config"
)

func TestRunPassesWhenPipelineTestsMatch(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Command: policy.PermissionCommandSpec{Name: "git", Semantic: &policy.SemanticMatchSpec{Verb: "status"}},
					Test:    policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
				}},
			},
			Test: policy.PipelineTestSpec{{In: "git status", Decision: "allow"}},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if !hasCheck(report, "tests.pass", StatusPass) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunReportsPermissionSourceMergeRule(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Command: policy.PermissionCommandSpec{Name: "git", Semantic: &policy.SemanticMatchSpec{Verb: "status"}},
					Test:    policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
				}},
			},
			Test: policy.PipelineTestSpec{{In: "git status", Decision: "allow"}},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if !hasCheck(report, "permission.source-merge-rule", StatusPass) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunReportsIncludedTestSourceOnFailure(t *testing.T) {
	src := policy.Source{Layer: "user", Path: "/repo/.cc-bash-guard/tests/git.yml", Section: "test", Index: 1}
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Command: policy.PermissionCommandSpec{Name: "git", Semantic: &policy.SemanticMatchSpec{Verb: "status"}},
					Test:    policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
				}},
			},
			Test: policy.PipelineTestSpec{{In: "git status", Decision: "deny", Source: src}},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	check := findCheck(report, "tests.pass")
	if check.Status != StatusFail || !strings.Contains(check.Message, src.Path+" test[1] expected deny, got allow") {
		t.Fatalf("check = %+v", check)
	}
}

func TestRunWarnsOnEnvOnlyAllow(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Env:  policy.PermissionEnvSpec{Requires: []string{"AWS_PROFILE"}},
					Test: policy.PermissionTestSpec{Allow: []string{"AWS_PROFILE=dev git status"}, Pass: []string{"git status"}},
				}},
			},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if !hasCheck(report, "permission.env-only-allow", StatusWarn) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunWarnsOnBroadAllow(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Name:    "all git",
					Command: policy.PermissionCommandSpec{Name: "git"},
					Test:    policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"kubectl get pods"}},
				}},
			},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	check := findCheck(report, "permission.broad-allow")
	if check.Status != StatusWarn || !strings.Contains(check.Message, "permission.allow[0]") || !strings.Contains(check.Message, "permission.ask") {
		t.Fatalf("check = %+v", check)
	}
}

func TestClaudeHookRegistrationCheckDetectsStructuredSettings(t *testing.T) {
	tests := []struct {
		name        string
		settings    string
		wantStatus  Status
		wantMessage string
	}{
		{
			name:        "compact JSON passes",
			settings:    `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"cc-bash-guard hook"}]}]}}`,
			wantStatus:  StatusPass,
			wantMessage: "registration detected",
		},
		{
			name: "pretty JSON passes",
			settings: `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "cc-bash-guard hook"
          }
        ]
      }
    ]
  }
}`,
			wantStatus:  StatusPass,
			wantMessage: "registration detected",
		},
		{
			name:        "reordered keys pass",
			settings:    `{"hooks":{"PreToolUse":[{"hooks":[{"command":"cc-bash-guard hook","type":"command","extra":true}],"matcher":"Bash","note":"ok"}]}}`,
			wantStatus:  StatusPass,
			wantMessage: "registration detected",
		},
		{
			name:        "wrong matcher warns",
			settings:    `{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"cc-bash-guard hook"}]}]}}`,
			wantStatus:  StatusWarn,
			wantMessage: "matcher is not Bash",
		},
		{
			name:        "Bash matcher with no cc-bash-guard hook warns",
			settings:    `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo ok"}]}]}}`,
			wantStatus:  StatusWarn,
			wantMessage: "Bash matcher exists but cc-bash-guard hook is missing",
		},
		{
			name:        "multiple Bash hooks warn",
			settings:    `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"cc-bash-guard hook"},{"type":"command","command":"rtk rewrite"}]}]}}`,
			wantStatus:  StatusWarn,
			wantMessage: "multiple Claude Code Bash hooks detected",
		},
		{
			name:        "malformed JSON gives clear warning",
			settings:    `{"hooks":`,
			wantStatus:  StatusWarn,
			wantMessage: "malformed JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeClaudeSettingsFile(t, tt.settings)
			check := claudeHookRegistrationCheck(path)
			if check.Status != tt.wantStatus || !strings.Contains(check.Message, tt.wantMessage) {
				t.Fatalf("check = %+v, want status=%s message containing %q", check, tt.wantStatus, tt.wantMessage)
			}
		})
	}
}

func TestClaudeHookRegistrationCheckWarnsWhenSettingsMissing(t *testing.T) {
	check := claudeHookRegistrationCheck(filepath.Join(t.TempDir(), ".claude", "settings.json"))
	if check.Status != StatusWarn || !strings.Contains(check.Message, "settings.json not found") {
		t.Fatalf("check = %+v", check)
	}
}

func hasCheck(report Report, id string, status Status) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}

func findCheck(report Report, id string) Check {
	for _, check := range report.Checks {
		if check.ID == id {
			return check
		}
	}
	return Check{}
}

func writeClaudeSettingsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
