package doctoring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
	configrepo "github.com/tasuku43/cc-bash-proxy/internal/infra/config"
)

func TestRunWarnsOnRelaxedRewriteContracts(t *testing.T) {
	strict := false
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Rewrite: []policy.RewriteStepSpec{{
				Match: policy.MatchSpec{Command: "kubectl"},
				MoveFlagToEnv: policy.MoveFlagToEnvSpec{
					Flag: "--kubeconfig",
					Env:  "KUBECONFIG",
				},
				Strict: &strict,
				Test: policy.RewriteTestSpec{
					{In: "kubectl --kubeconfig /tmp/dev get pods", Out: "KUBECONFIG=/tmp/dev kubectl get pods"},
					{Pass: "KUBECONFIG=/tmp/dev kubectl get pods"},
				},
			}},
			Test: policy.PipelineTestSpec{{In: "kubectl --kubeconfig /tmp/dev get pods", Decision: "ask"}},
		}, policy.Source{}),
	}

	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if !hasCheck(report, "rewrite.relaxed-contracts", StatusWarn) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunPassesWhenPipelineTestsMatch(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Match: policy.MatchSpec{Command: "git", Subcommand: "status"},
					Test:  policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
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

func TestRunDefaultsToStrictClaudeMergeMode(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Match: policy.MatchSpec{Command: "git", Subcommand: "status"},
					Test:  policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
				}},
			},
			Test: policy.PipelineTestSpec{{In: "git status", Decision: "allow"}},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if report.ClaudePermissionMergeMode != "strict" {
		t.Fatalf("mode=%q", report.ClaudePermissionMergeMode)
	}
	if !hasCheck(report, "permission.claude-merge-mode", StatusPass) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunWarnsOnMigrationCompatClaudeMergeMode(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			ClaudePermissionMergeMode: "migration_compat",
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Match: policy.MatchSpec{Command: "git", Subcommand: "status"},
					Test:  policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
				}},
			},
			Test: policy.PipelineTestSpec{{In: "git status", Decision: "allow"}},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if report.ClaudePermissionMergeMode != "migration_compat" {
		t.Fatalf("mode=%q", report.ClaudePermissionMergeMode)
	}
	if !hasCheck(report, "permission.claude-merge-mode", StatusWarn) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunPassesOnStrictClaudeMergeMode(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			ClaudePermissionMergeMode: "strict",
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Match: policy.MatchSpec{Command: "git", Subcommand: "status"},
					Test:  policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
				}},
			},
			Test: policy.PipelineTestSpec{{In: "git status", Decision: "allow"}},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if report.ClaudePermissionMergeMode != "strict" {
		t.Fatalf("mode=%q", report.ClaudePermissionMergeMode)
	}
	if !hasCheck(report, "permission.claude-merge-mode", StatusPass) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunWarnsOnExplicitUnsafeAllow(t *testing.T) {
	loaded := configrepo.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Pattern:          `^\s*git\s+status\s*\|\s*sh$`,
					AllowUnsafeShell: true,
					Message:          "allow trusted pipeline",
					Test: policy.PermissionTestSpec{
						Allow: []string{"git status | sh"},
						Pass:  []string{"git status"},
					},
				}},
			},
			Test: policy.PipelineTestSpec{{In: "git status | sh", Decision: "allow"}},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if !hasCheck(report, "permission.unsafe-shell-allow", StatusWarn) {
		t.Fatalf("checks = %+v", report.Checks)
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
			settings:    `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"cc-bash-proxy hook"}]}]}}`,
			wantStatus:  StatusPass,
			wantMessage: "without --rtk",
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
            "command": "cc-bash-proxy hook"
          }
        ]
      }
    ]
  }
}`,
			wantStatus:  StatusPass,
			wantMessage: "without --rtk",
		},
		{
			name:        "reordered keys pass",
			settings:    `{"hooks":{"PreToolUse":[{"hooks":[{"command":"cc-bash-proxy hook","type":"command","extra":true}],"matcher":"Bash","note":"ok"}]}}`,
			wantStatus:  StatusPass,
			wantMessage: "without --rtk",
		},
		{
			name:        "wrong matcher warns",
			settings:    `{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"cc-bash-proxy hook"}]}]}}`,
			wantStatus:  StatusWarn,
			wantMessage: "matcher is not Bash",
		},
		{
			name:        "Bash matcher with no cc-bash-proxy hook warns",
			settings:    `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo ok"}]}]}}`,
			wantStatus:  StatusWarn,
			wantMessage: "Bash matcher exists but cc-bash-proxy hook is missing",
		},
		{
			name:        "cc-bash-proxy hook with --rtk is detected correctly",
			settings:    `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"cc-bash-proxy hook --rtk"}]}]}}`,
			wantStatus:  StatusPass,
			wantMessage: "with --rtk",
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
