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
