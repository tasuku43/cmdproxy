package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cmdproxy/internal/buildinfo"
	"github.com/tasuku43/cmdproxy/internal/config"
	"github.com/tasuku43/cmdproxy/internal/doctor"
)

func TestRunHookClaudeAllowReturnsAllowAndUpdatedInput(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rewrite:
  - match:
      command: aws
      args_contains: ["--profile"]
    move_flag_to_env:
      flag: "--profile"
      env: "AWS_PROFILE"
    test:
      - in: "aws --profile dev sts get-caller-identity"
        out: "AWS_PROFILE=dev aws sts get-caller-identity"
      - pass: "AWS_PROFILE=dev aws sts get-caller-identity"
permission:
  allow:
    - match:
        command: aws
        subcommand: sts
        env_requires: ["AWS_PROFILE"]
      test:
        allow:
          - "AWS_PROFILE=dev aws sts get-caller-identity"
        pass:
          - "AWS_PROFILE=dev aws s3 ls"
test:
  - in: "aws --profile dev sts get-caller-identity"
    rewritten: "AWS_PROFILE=dev aws sts get-caller-identity"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"aws --profile dev sts get-caller-identity"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v", err)
	}
	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["permissionDecision"] != "allow" {
		t.Fatalf("payload = %+v", payload)
	}
	updatedInput := hookOut["updatedInput"].(map[string]any)
	if updatedInput["command"] != "AWS_PROFILE=dev aws sts get-caller-identity" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeAskOmitsPermissionDecision(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  ask:
    - match:
        command: aws
        subcommand: s3
      test:
        ask:
          - "aws s3 ls"
        pass:
          - "aws sts get-caller-identity"
test:
  - in: "aws s3 ls"
    decision: ask
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"aws s3 ls"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v", err)
	}
	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if _, ok := hookOut["permissionDecision"]; ok {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeDenyReturnsDeny(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  deny:
    - match:
        command: rm
      message: "rm blocked"
      test:
        deny:
          - "rm -rf /tmp/x"
        pass:
          - "pwd"
test:
  - in: "rm -rf /tmp/x"
    decision: deny
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v", err)
	}
	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeImplicitlyVerifiesWhenArtifactMissing(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rewrite:
  - match:
      command_in: ["bash", "sh"]
      args_contains: ["-c"]
    unwrap_shell_dash_c: true
    test:
      - in: "bash -c 'git status'"
        out: "git status"
      - pass: "bash script.sh"
permission:
  allow:
    - match:
        command: git
        subcommand: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "bash -c 'git status'"
    rewritten: "git status"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"bash -c 'git status'"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	entries, err := os.ReadDir(config.HookCacheDir(home, ""))
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected implicit verify artifact, err=%v entries=%v", err, entries)
	}
}

func TestRunTest(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - match:
        command: git
        subcommand: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"test"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok: 0 rewrite steps, 1 permission rules, 3 tests checked") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestVerifyStatus(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Check{
			{ID: "config.parse", Status: doctor.StatusPass},
			{ID: "tests.pass", Status: doctor.StatusPass},
		},
	}
	ok, reasons := verifyStatus(report, buildinfo.Info{Version: "dev", Module: "github.com/tasuku43/cmdproxy", VCSRevision: "abc123"})
	if !ok || len(reasons) != 0 {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
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
	data, err := os.ReadFile(filepath.Join(home, ".config", "cmdproxy", "cmdproxy.yml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "permission:") {
		t.Fatalf("config=%q", string(data))
	}
}

func writeUserConfig(t *testing.T, home string, body string) {
	t.Helper()
	path := filepath.Join(home, ".config", "cmdproxy", "cmdproxy.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
