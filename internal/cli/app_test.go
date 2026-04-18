package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEvalJSONDeny(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `version: 1
rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    message: "git -C は禁止。cd で移動してから実行してください。"
    block_examples: ["git -C foo status"]
    allow_examples: ["git status"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"eval", "--format", "json"}, Streams{
		Stdin:  strings.NewReader(`{"action":"exec","command":"git -C foo status"}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: dir, Home: t.TempDir()})
	if code != 2 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v", err)
	}
	if payload["decision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunCheckAllow(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `version: 1
rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    message: "git -C は禁止。cd で移動してから実行してください。"
    block_examples: ["git -C foo status"]
    allow_examples: ["git status"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"check", "git", "status"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: dir, Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunTest(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `version: 1
rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    message: "git -C は禁止。cd で移動してから実行してください。"
    block_examples: ["git -C foo status"]
    allow_examples: ["git status"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"test"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: dir, Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok: 1 rules, 2 examples checked") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestRunInitCreatesStarterConfig(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"init"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: dir, Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(dir, ".cmdguard.yml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "version: 1") {
		t.Fatalf("config=%q", string(data))
	}
}

func writeConfig(t *testing.T, dir string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".cmdguard.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
