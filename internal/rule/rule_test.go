package rule

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileIfPresentValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cmdguard.yml")
	if err := os.WriteFile(path, []byte("version: 1\nrules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFileIfPresent(Source{Layer: LayerProject, Path: path})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestLoadEffectiveProjectBeforeUser(t *testing.T) {
	cwd := t.TempDir()
	home := t.TempDir()
	projectPath := filepath.Join(cwd, ".cmdguard.yml")
	userPath := filepath.Join(home, ".config", "cmdguard", "cmdguard.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	project := `version: 1
rules:
  - id: project-rule
    pattern: "^git"
    message: "project"
    block_examples: ["git status"]
    allow_examples: ["echo ok"]
`
	user := `version: 1
rules:
  - id: user-rule
    pattern: "^echo"
    message: "user"
    block_examples: ["echo hi"]
    allow_examples: ["git status"]
`
	if err := os.WriteFile(projectPath, []byte(project), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(user), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffective(cwd, home, "")
	if len(loaded.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", loaded.Errors)
	}
	if len(loaded.Rules) != 2 {
		t.Fatalf("got %d rules", len(loaded.Rules))
	}
	if loaded.Rules[0].ID != "project-rule" {
		t.Fatalf("first rule = %s", loaded.Rules[0].ID)
	}
}
