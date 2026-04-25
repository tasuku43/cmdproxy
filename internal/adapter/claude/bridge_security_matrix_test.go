package claude

import (
	"path/filepath"
	"testing"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
)

func TestSecurityRegressionMatrixClaudeMergeModes(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		baseOutcome   string
		claudeAllow   []string
		claudeAsk     []string
		claudeDeny    []string
		want          string
		wantModeTrace string
		wantSettings  string
	}{
		{
			name:          "strict keeps deny over settings allow",
			mode:          MergeModeStrict,
			baseOutcome:   "deny",
			claudeAllow:   []string{"git status"},
			want:          "deny",
			wantModeTrace: MergeModeStrict,
			wantSettings:  "allow",
		},
		{
			name:          "strict does not upgrade ask to settings allow",
			mode:          MergeModeStrict,
			baseOutcome:   "ask",
			claudeAllow:   []string{"git status"},
			want:          "ask",
			wantModeTrace: MergeModeStrict,
			wantSettings:  "allow",
		},
		{
			name:          "strict applies settings ask over allow",
			mode:          MergeModeStrict,
			baseOutcome:   "allow",
			claudeAsk:     []string{"git status"},
			want:          "ask",
			wantModeTrace: MergeModeStrict,
			wantSettings:  "ask",
		},
		{
			name:          "strict applies settings allow when cc-bash-proxy abstains",
			mode:          MergeModeStrict,
			baseOutcome:   "abstain",
			claudeAllow:   []string{"git status"},
			want:          "allow",
			wantModeTrace: MergeModeStrict,
			wantSettings:  "allow",
		},
		{
			name:          "strict applies settings ask when cc-bash-proxy abstains",
			mode:          MergeModeStrict,
			baseOutcome:   "abstain",
			claudeAsk:     []string{"git status"},
			want:          "ask",
			wantModeTrace: MergeModeStrict,
			wantSettings:  "ask",
		},
		{
			name:          "strict applies settings deny when cc-bash-proxy abstains",
			mode:          MergeModeStrict,
			baseOutcome:   "abstain",
			claudeDeny:    []string{"git status"},
			want:          "deny",
			wantModeTrace: MergeModeStrict,
			wantSettings:  "deny",
		},
		{
			name:          "migration compat upgrades ask to settings allow",
			mode:          MergeModeMigrationCompat,
			baseOutcome:   "ask",
			claudeAllow:   []string{"git status"},
			want:          "allow",
			wantModeTrace: MergeModeMigrationCompat,
			wantSettings:  "allow",
		},
		{
			name:          "migration compat still keeps deny",
			mode:          MergeModeMigrationCompat,
			baseOutcome:   "deny",
			claudeAllow:   []string{"git status"},
			want:          "deny",
			wantModeTrace: MergeModeMigrationCompat,
			wantSettings:  "",
		},
		{
			name:          "authoritative ignores settings ask",
			mode:          MergeModeCCBashProxyAuthoritative,
			baseOutcome:   "allow",
			claudeAsk:     []string{"git status"},
			want:          "allow",
			wantModeTrace: MergeModeCCBashProxyAuthoritative,
			wantSettings:  "ask",
		},
		{
			name:          "authoritative ignores settings allow",
			mode:          MergeModeCCBashProxyAuthoritative,
			baseOutcome:   "ask",
			claudeAllow:   []string{"git status"},
			want:          "ask",
			wantModeTrace: MergeModeCCBashProxyAuthoritative,
			wantSettings:  "allow",
		},
		{
			name:          "authoritative still honors settings deny",
			mode:          MergeModeCCBashProxyAuthoritative,
			baseOutcome:   "allow",
			claudeDeny:    []string{"git status"},
			want:          "deny",
			wantModeTrace: MergeModeCCBashProxyAuthoritative,
			wantSettings:  "deny",
		},
		{
			name:          "unknown mode normalizes to strict",
			mode:          "unknown",
			baseOutcome:   "ask",
			claudeAllow:   []string{"git status"},
			want:          "ask",
			wantModeTrace: MergeModeStrict,
			wantSettings:  "allow",
		},
		{
			name:          "both abstain ask by default",
			mode:          MergeModeStrict,
			baseOutcome:   "abstain",
			want:          "ask",
			wantModeTrace: MergeModeStrict,
			wantSettings:  "abstain",
		},
	}

	for _, tt := range tests {
		t.Run("merge_mode/"+tt.name, func(t *testing.T) {
			home := t.TempDir()
			cwd := t.TempDir()
			writeSettings(t, filepath.Join(home, ".claude", "settings.json"), claudeSettingsJSON(tt.claudeDeny, tt.claudeAsk, tt.claudeAllow))

			decision := ApplyPermissionBridgeWithMode(Tool, policy.Decision{
				Outcome: tt.baseOutcome,
				Command: "git status",
			}, cwd, home, tt.mode)
			if decision.Outcome != tt.want {
				t.Fatalf("Outcome = %q, want %q; decision=%+v", decision.Outcome, tt.want, decision)
			}
			if !bridgeTraceContains(decision.Trace, "claude_permission_merge_mode", tt.wantModeTrace) {
				t.Fatalf("trace missing merge mode %q; trace=%+v", tt.wantModeTrace, decision.Trace)
			}
			if tt.wantSettings != "" && !bridgeTraceContains(decision.Trace, "claude_settings", tt.wantSettings) {
				t.Fatalf("trace missing claude_settings %q; trace=%+v", tt.wantSettings, decision.Trace)
			}
			if tt.baseOutcome == "deny" && decision.Outcome == "allow" {
				t.Fatalf("deny widened to allow; decision=%+v", decision)
			}
		})
	}
}

func claudeSettingsJSON(deny []string, ask []string, allow []string) string {
	return `{"permissions":{"deny":` + bashPatternsJSON(deny) + `,"ask":` + bashPatternsJSON(ask) + `,"allow":` + bashPatternsJSON(allow) + `}}`
}

func bashPatternsJSON(patterns []string) string {
	if len(patterns) == 0 {
		return `[]`
	}
	out := `[`
	for i, pattern := range patterns {
		if i > 0 {
			out += `,`
		}
		out += `"Bash(` + pattern + `)"`
	}
	return out + `]`
}

func bridgeTraceContains(trace []policy.TraceStep, name string, effect string) bool {
	for _, step := range trace {
		if step.Name == name && step.Effect == effect {
			return true
		}
	}
	return false
}
