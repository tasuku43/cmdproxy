package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fullUserConfig = `version: 1
rules:
  - id: no-git-dash-c
    match:
      command: git
      args_contains:
        - "-C"
    message: "git -C is blocked. Change into the target directory and rerun the command."
    block_examples:
      - "git -C repos/foo status"
      - "  git -C . log"
    allow_examples:
      - "git status"
      - "# git -C in comment"
  - id: no-git-diff-three-dot
    pattern: '^\s*git\s+diff\s+.*\.\.\.'
    message: "git diff <base>...<head> is blocked because it can produce very large output. Use gh pr diff instead."
    block_examples:
      - "git diff main...HEAD"
      - "git diff origin/main...feature"
    allow_examples:
      - "git diff HEAD~1"
      - "gh pr diff"
  - id: no-shell-dash-c
    match:
      command_in:
        - bash
        - sh
        - zsh
        - dash
        - ksh
      args_contains:
        - "-c"
    message: "shell -c is blocked because it can bypass command chaining guards. Run cd separately, then run the next command."
    block_examples:
      - "bash -c 'git status && git diff'"
      - "sh -c 'echo hi'"
      - "/bin/bash -c 'git status'"
      - "/bin/sh -c 'echo hi'"
      - "env bash -c 'git status'"
      - "/usr/bin/env bash -c 'git status'"
      - "command bash -c 'git status'"
      - "exec sh -c 'echo hi'"
      - "zsh -c 'echo hi'"
      - "dash -c 'echo hi'"
    allow_examples:
      - "bash script.sh"
      - "sh script.sh"
      - "git status"
      - "env bash script.sh"
  - id: no-aws-profile-flag
    pattern: '(^|[^A-Za-z0-9_-])aws\s+[^|;&]*--profile[ =]'
    message: "aws --profile is blocked. Use AWS_PROFILE=<profile> aws ... instead, for example AWS_PROFILE=read-only-profile aws s3 ls."
    block_examples:
      - "aws s3 ls --profile read-only-profile"
      - "aws --profile read-only-profile s3 ls"
    allow_examples:
      - "AWS_PROFILE=read-only-profile aws s3 ls"
      - "echo docs mention profile flag"
  - id: require-aws-profile-env
    match:
      command: aws
      env_missing:
        - AWS_PROFILE
    message: "aws commands must start with AWS_PROFILE=<profile>, for example AWS_PROFILE=read-only-profile aws s3 ls."
    block_examples:
      - "aws s3 ls"
      - "  aws sts get-caller-identity"
    allow_examples:
      - "AWS_PROFILE=read-only-profile aws s3 ls"
      - "AWS_PROFILE=dev-profile aws sts get-caller-identity"
  - id: no-cd-one-liner
    pattern: '^\s*cd\s+[^&;|]+\s*(&&|;|\|)'
    message: "One-liners that start with cd are blocked because prefix-based permission rules can miss the chained command. Run cd separately, then run the next command."
    block_examples:
      - "cd repo && git status"
      - "cd repo; make test"
      - "cd repo | cat"
    allow_examples:
      - "cd repo"
      - "git status"
  - id: no-git-git-dir
    match:
      command: git
      args_prefixes:
        - "--git-dir"
    message: "git --git-dir is blocked. Change into the target directory and rerun the command."
    block_examples:
      - "git --git-dir=.git status"
      - "git --git-dir ../repo/.git log"
    allow_examples:
      - "git status"
      - "git --version"
`

func TestRunEvalJSONDeny(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `version: 1
rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    message: "git -C is blocked. Change into the target directory and rerun the command."
    block_examples: ["git -C foo status"]
    allow_examples: ["git status"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"eval", "--format", "json"}, Streams{
		Stdin:  strings.NewReader(`{"action":"exec","command":"git -C foo status"}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
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
	home := t.TempDir()
	writeUserConfig(t, home, `version: 1
rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    message: "git -C is blocked. Change into the target directory and rerun the command."
    block_examples: ["git -C foo status"]
    allow_examples: ["git status"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"check", "git", "status"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunTest(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `version: 1
rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    message: "git -C is blocked. Change into the target directory and rerun the command."
    block_examples: ["git -C foo status"]
    allow_examples: ["git status"]
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
	data, err := os.ReadFile(filepath.Join(home, ".config", "cmdguard", "cmdguard.yml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "version: 1") {
		t.Fatalf("config=%q", string(data))
	}
}

func TestRunRootHelpMentionsEditingAndTest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--help"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Edit ~/.config/cmdguard/cmdguard.yml") {
		t.Fatalf("stdout=%q", out)
	}
	if !strings.Contains(out, "cmdguard test") {
		t.Fatalf("stdout=%q", out)
	}
}

func TestRunTestHelpMentionsMainAuthoringCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"test", "--help"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "main command to run after editing rules") {
		t.Fatalf("stdout=%q", out)
	}
}

func TestRunUnknownCommandReturnsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"unknown"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: t.TempDir()})
	if code != 1 {
		t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "unknown command: unknown") {
		t.Fatalf("stderr=%q", errOut)
	}
}

func TestRunCheckFullGuardDenyCases(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, fullUserConfig)

	tests := []struct {
		name       string
		command    string
		wantRuleID string
	}{
		{name: "cd and and", command: "cd repo && git status", wantRuleID: "no-cd-one-liner"},
		{name: "cd semicolon", command: "cd repo; make test", wantRuleID: "no-cd-one-liner"},
		{name: "cd pipe", command: "cd repo | cat", wantRuleID: "no-cd-one-liner"},
		{name: "bash dash c", command: "bash -c 'git status && git diff'", wantRuleID: "no-shell-dash-c"},
		{name: "sh dash c", command: "sh -c 'echo hi'", wantRuleID: "no-shell-dash-c"},
		{name: "bin bash dash c", command: "/bin/bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "usr bin env bash dash c", command: "/usr/bin/env bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "env bash dash c", command: "env bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "command bash dash c", command: "command bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "exec sh dash c", command: "exec sh -c 'echo hi'", wantRuleID: "no-shell-dash-c"},
		{name: "zsh dash c", command: "zsh -c 'echo hi'", wantRuleID: "no-shell-dash-c"},
		{name: "dash dash c", command: "dash -c 'echo hi'", wantRuleID: "no-shell-dash-c"},
		{name: "aws profile flag", command: "aws --profile read-only-profile s3 ls", wantRuleID: "no-aws-profile-flag"},
		{name: "bare aws", command: "aws s3 ls", wantRuleID: "require-aws-profile-env"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"check", "--format", "json"}, strings.Fields(tt.command)...)
			code := Run(args, Streams{
				Stdin:  strings.NewReader(""),
				Stdout: &stdout,
				Stderr: &stderr,
			}, Env{Cwd: t.TempDir(), Home: home})
			if code != 2 {
				t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}

			var payload struct {
				Decision string `json:"decision"`
				RuleID   string `json:"rule_id"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
				t.Fatalf("json error: %v", err)
			}
			if payload.Decision != "deny" || payload.RuleID != tt.wantRuleID {
				t.Fatalf("payload = %+v", payload)
			}
		})
	}
}

func TestRunCheckFullGuardAllowCases(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, fullUserConfig)

	tests := []string{
		"cd repo",
		"git status",
		"AWS_PROFILE=read-only-profile aws s3 ls",
		"AWS_PROFILE=dev-profile aws sts get-caller-identity",
		"gh pr diff",
		"bash script.sh",
		"sh script.sh",
		"env bash script.sh",
	}

	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"check", "--format", "json"}, strings.Fields(command)...)
			code := Run(args, Streams{
				Stdin:  strings.NewReader(""),
				Stdout: &stdout,
				Stderr: &stderr,
			}, Env{Cwd: t.TempDir(), Home: home})
			if code != 0 {
				t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
				t.Fatalf("json error: %v", err)
			}
			if payload["decision"] != "allow" {
				t.Fatalf("payload = %+v", payload)
			}
		})
	}
}

func writeUserConfig(t *testing.T, home string, body string) {
	t.Helper()
	path := filepath.Join(home, ".config", "cmdguard", "cmdguard.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
