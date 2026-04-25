package claude

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckCommandAllowFromHomeSettings(t *testing.T) {
	home := t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude", "settings.json"), `{
  "permissions": {
    "allow": ["Bash(AWS_PROFILE=dev aws:*)"]
  }
}`)

	got := CheckCommand("AWS_PROFILE=dev aws s3 ls", t.TempDir(), home)
	if got != PermissionAllow {
		t.Fatalf("got %q", got)
	}
}

func TestCheckCommandAskOverridesAllow(t *testing.T) {
	home := t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude", "settings.json"), `{
  "permissions": {
    "ask": ["Bash(git push)"],
    "allow": ["Bash(git:*)"]
  }
}`)

	got := CheckCommand("git push origin main", t.TempDir(), home)
	if got != PermissionAsk {
		t.Fatalf("got %q", got)
	}
}

func TestCheckCommandDenyHighestPriority(t *testing.T) {
	home := t.TempDir()
	writeSettings(t, filepath.Join(home, ".claude", "settings.json"), `{
  "permissions": {
    "deny": ["Bash(rm -rf)"],
    "allow": ["Bash(*)"]
  }
}`)

	got := CheckCommand("rm -rf /tmp/x", t.TempDir(), home)
	if got != PermissionDeny {
		t.Fatalf("got %q", got)
	}
}

func TestCheckCommandClaudeCompatibleCompoundComposition(t *testing.T) {
	tests := []struct {
		name  string
		cmd   string
		allow []string
		deny  []string
		want  PermissionVerdict
	}{
		{
			name:  "left allow does not authorize right side",
			cmd:   "git status && rm -rf /tmp/x",
			allow: []string{"git status"},
			want:  PermissionDefault,
		},
		{
			name:  "and list allows when every command is allowed",
			cmd:   "git status && git diff && git log",
			allow: []string{"git status", "git diff", "git log"},
			want:  PermissionAllow,
		},
		{
			name:  "sequence allows when every command is allowed",
			cmd:   "git status; git diff; git log; git branch",
			allow: []string{"git status", "git diff", "git log", "git branch"},
			want:  PermissionAllow,
		},
		{
			name:  "or list allows when every command is allowed",
			cmd:   "git status || git diff",
			allow: []string{"git status", "git diff"},
			want:  PermissionAllow,
		},
		{
			name:  "pipeline allows when every command is allowed",
			cmd:   "git status | sh",
			allow: []string{"git status", "sh"},
			want:  PermissionAllow,
		},
		{
			name:  "pipe all uses pipeline policy",
			cmd:   "git status |& sh",
			allow: []string{"git status", "sh"},
			want:  PermissionAllow,
		},
		{
			name:  "deny wins in compound command",
			cmd:   "git status && rm -rf /tmp/x",
			allow: []string{"git status"},
			deny:  []string{"rm -rf"},
			want:  PermissionDeny,
		},
		{
			name:  "background is not allowed by simple left rule",
			cmd:   "git status &",
			allow: []string{"git status"},
			want:  PermissionDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkCommandWithRules(tt.cmd, tt.deny, nil, tt.allow)
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckCommandUsesProjectSettingsFirst(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	writeSettings(t, filepath.Join(project, ".claude", "settings.local.json"), `{
  "permissions": {
    "allow": ["Bash(git status)"]
  }
}`)

	got := CheckCommand("git status", project, home)
	if got != PermissionAllow {
		t.Fatalf("got %q", got)
	}
}

func writeSettings(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
