package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cmdproxy/internal/buildinfo"
	"github.com/tasuku43/cmdproxy/internal/doctor"
)

const fullUserConfig = `rules:
  - id: no-git-dash-c
    match:
      command: git
      args_contains:
        - "-C"
    reject:
      message: "git -C is blocked. Change into the target directory and rerun the command."
      test:
        expect:
          - "git -C repos/foo status"
          - "  git -C . log"
        pass:
          - "git status"
          - "# git -C in comment"
  - id: no-git-diff-three-dot
    pattern: '^\s*git\s+diff\s+.*\.\.\.'
    reject:
      message: "git diff <base>...<head> is blocked because it can produce very large output. Use gh pr diff instead."
      test:
        expect:
          - "git diff main...HEAD"
          - "git diff origin/main...feature"
        pass:
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
    reject:
      message: "shell -c is blocked because it can bypass command chaining guards. Run cd separately, then run the next command."
      test:
        expect:
          - "bash -c 'git status && git diff'"
          - "sh -c 'echo hi'"
          - "/bin/bash -c 'git status'"
          - "/bin/sh -c 'echo hi'"
          - "env bash -c 'git status'"
          - "/usr/bin/env bash -c 'git status'"
          - "command bash -c 'git status'"
          - "exec sh -c 'echo hi'"
          - "sudo bash -c 'git status'"
          - "sudo -u root bash -c 'git status'"
          - "nohup bash -c 'git status'"
          - "timeout 10 bash -c 'git status'"
          - "timeout --signal TERM 10 bash -c 'git status'"
          - "busybox sh -c 'echo hi'"
          - "zsh -c 'echo hi'"
          - "dash -c 'echo hi'"
        pass:
          - "bash script.sh"
          - "sh script.sh"
          - "git status"
          - "env bash script.sh"
  - id: no-aws-profile-flag
    pattern: '(^|[^A-Za-z0-9_-])aws\s+[^|;&]*--profile[ =]'
    reject:
      message: "aws --profile is blocked. Use AWS_PROFILE=<profile> aws ... instead, for example AWS_PROFILE=read-only-profile aws s3 ls."
      test:
        expect:
          - "aws s3 ls --profile read-only-profile"
          - "aws --profile read-only-profile s3 ls"
        pass:
          - "AWS_PROFILE=read-only-profile aws s3 ls"
          - "echo docs mention profile flag"
  - id: require-aws-profile-env
    match:
      command: aws
      env_missing:
        - AWS_PROFILE
    reject:
      message: "aws commands must start with AWS_PROFILE=<profile>, for example AWS_PROFILE=read-only-profile aws s3 ls."
      test:
        expect:
          - "aws s3 ls"
          - "  aws sts get-caller-identity"
        pass:
          - "AWS_PROFILE=read-only-profile aws s3 ls"
          - "AWS_PROFILE=dev-profile aws sts get-caller-identity"
  - id: no-cd-one-liner
    pattern: '^\s*cd\s+[^&;|]+\s*(&&|;|\|)'
    reject:
      message: "One-liners that start with cd are blocked because prefix-based permission rules can miss the chained command. Run cd separately, then run the next command."
      test:
        expect:
          - "cd repo && git status"
          - "cd repo; make test"
          - "cd repo | cat"
        pass:
          - "cd repo"
          - "git status"
  - id: no-git-git-dir
    match:
      command: git
      args_prefixes:
        - "--git-dir"
    reject:
      message: "git --git-dir is blocked. Change into the target directory and rerun the command."
      test:
        expect:
          - "git --git-dir=.git status"
          - "git --git-dir ../repo/.git log"
        pass:
          - "git status"
          - "git --version"
`

func TestRunHookClaudeReject(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    reject:
      message: "git -C is blocked. Change into the target directory and rerun the command."
      test:
        expect: ["git -C foo status"]
        pass: ["git status"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git -C foo status"}}`),
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
	hookOut, ok := payload["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	if hookOut["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
	if hookOut["permissionDecisionReason"] != "git -C is blocked. Change into the target directory and rerun the command." {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunVersionJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"version", "--format", "json"}, Streams{
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v", err)
	}
	if payload["module"] != "github.com/tasuku43/cmdproxy" {
		t.Fatalf("payload = %+v", payload)
	}
	if _, ok := payload["version"]; !ok {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestVerifyStatusFailsWithoutBuildMetadata(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Check{
			{ID: "config.parse", Category: "config", Status: doctor.StatusPass, Message: "ok"},
			{ID: "install.claude-registered", Category: "install", Status: doctor.StatusWarn, Message: "Claude Code settings.json not found"},
		},
	}
	ok, reasons := verifyStatus(report, buildinfo.Info{Version: "dev", Module: "github.com/tasuku43/cmdproxy"})
	if ok {
		t.Fatalf("expected verifyStatus to fail")
	}
	if len(reasons) == 0 {
		t.Fatalf("expected failure reasons")
	}
}

func TestVerifyStatusFailsWhenClaudeSettingsExistButHookMissing(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Check{
			{ID: "config.parse", Category: "config", Status: doctor.StatusPass, Message: "ok"},
			{ID: "install.claude-registered", Category: "install", Status: doctor.StatusWarn, Message: "Claude Code settings found but cmdproxy hook claude not detected"},
		},
	}
	ok, reasons := verifyStatus(report, buildinfo.Info{Version: "dev", Module: "github.com/tasuku43/cmdproxy", VCSRevision: "abc123"})
	if ok {
		t.Fatalf("expected verifyStatus to fail")
	}
	if len(reasons) == 0 {
		t.Fatalf("expected failure reasons")
	}
}

func TestVerifyStatusPassesWithBuildMetadataAndNoFatalChecks(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Check{
			{ID: "config.parse", Category: "config", Status: doctor.StatusPass, Message: "ok"},
			{ID: "install.claude-registered", Category: "install", Status: doctor.StatusWarn, Message: "Claude Code settings.json not found"},
		},
	}
	ok, reasons := verifyStatus(report, buildinfo.Info{Version: "dev", Module: "github.com/tasuku43/cmdproxy", VCSRevision: "abc123"})
	if !ok {
		t.Fatalf("expected verifyStatus to pass, reasons=%v", reasons)
	}
}

func TestVerifyStatusFailsWhenClaudeHookUsesPATHLookup(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Check{
			{ID: "config.parse", Category: "config", Status: doctor.StatusPass, Message: "ok"},
			{ID: "install.claude-registered", Category: "install", Status: doctor.StatusPass, Message: "Claude Code hook registration detected"},
			{ID: "install.claude-hook-path", Category: "install", Status: doctor.StatusWarn, Message: "Claude Code hook uses PATH lookup; prefer an absolute cmdproxy path"},
		},
	}
	ok, reasons := verifyStatus(report, buildinfo.Info{Version: "dev", Module: "github.com/tasuku43/cmdproxy", VCSRevision: "abc123"})
	if ok {
		t.Fatalf("expected verifyStatus to fail")
	}
	if len(reasons) == 0 {
		t.Fatalf("expected failure reasons")
	}
}

func TestRunHookClaudeRewrite(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rules:
  - id: unwrap-shell-dash-c
    match:
      command_in: ["bash", "sh"]
      args_contains: ["-c"]
    rewrite:
      unwrap_shell_dash_c: true
      test:
        expect:
          - in: "bash -c 'git status'"
            out: "git status"
        pass: ["bash script.sh"]
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

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v", err)
	}
	hookOut, ok := payload["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	if hookOut["permissionDecision"] != "allow" {
		t.Fatalf("payload = %+v", payload)
	}
	if payload["systemMessage"] != "cmdproxy: rewrote [unwrap-shell-dash-c] -> git status" {
		t.Fatalf("payload = %+v", payload)
	}
	updatedInput, ok := hookOut["updatedInput"].(map[string]any)
	if !ok || updatedInput["command"] != "git status" {
		t.Fatalf("payload = %+v", payload)
	}
	cmdproxyOut, ok := payload["cmdproxy"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	trace, ok := cmdproxyOut["trace"].([]any)
	if !ok || len(trace) != 1 {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeRewriteContinueThenReject(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rules:
  - id: unwrap-shell-dash-c
    match:
      command_in: ["bash", "sh"]
      args_contains: ["-c"]
    rewrite:
      unwrap_shell_dash_c: true
      continue: true
      test:
        expect:
          - in: "bash -c 'git -C repo status'"
            out: "git -C repo status"
        pass: ["bash script.sh"]
  - id: no-git-dash-c
    match:
      command: git
      args_contains: ["-C"]
    reject:
      message: "git -C is blocked. Change into the target directory and rerun the command."
      test:
        expect: ["git -C repo status"]
        pass: ["git status"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"bash -c 'git -C repo status'"}}`),
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
	hookOut, ok := payload["hookSpecificOutput"].(map[string]any)
	if !ok || hookOut["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
	if _, ok := payload["systemMessage"]; ok {
		t.Fatalf("payload = %+v", payload)
	}
	cmdproxyOut, ok := payload["cmdproxy"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	trace, ok := cmdproxyOut["trace"].([]any)
	if !ok || len(trace) != 2 {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeMoveFlagToEnvRewrite(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rules:
  - id: aws-profile-to-env
    match:
      command: aws
      args_contains: ["--profile"]
    rewrite:
      move_flag_to_env:
        flag: "--profile"
        env: "AWS_PROFILE"
      test:
        expect:
          - in: "aws --profile read-only-profile s3 ls"
            out: "AWS_PROFILE=read-only-profile aws s3 ls"
        pass: ["AWS_PROFILE=read-only-profile aws s3 ls"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"aws --profile read-only-profile s3 ls"}}`),
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
	hookOut, ok := payload["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	if payload["systemMessage"] != "cmdproxy: rewrote [aws-profile-to-env] -> AWS_PROFILE=read-only-profile aws s3 ls" {
		t.Fatalf("payload = %+v", payload)
	}
	updatedInput, ok := hookOut["updatedInput"].(map[string]any)
	if !ok || updatedInput["command"] != "AWS_PROFILE=read-only-profile aws s3 ls" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeMoveEnvToFlagRewrite(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rules:
  - id: aws-env-to-profile
    match:
      command: aws
      env_requires: ["AWS_PROFILE"]
    rewrite:
      move_env_to_flag:
        env: "AWS_PROFILE"
        flag: "--profile"
      test:
        expect:
          - in: "AWS_PROFILE=read-only-profile aws s3 ls"
            out: "aws --profile read-only-profile s3 ls"
        pass: ["aws --profile read-only-profile s3 ls"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"AWS_PROFILE=read-only-profile aws s3 ls"}}`),
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
	hookOut, ok := payload["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	updatedInput, ok := hookOut["updatedInput"].(map[string]any)
	if !ok || updatedInput["command"] != "aws --profile read-only-profile s3 ls" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeUnwrapWrapperRewrite(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rules:
  - id: unwrap-safe-wrappers
    pattern: '^\s*(env|command|exec)\b'
    rewrite:
      unwrap_wrapper:
        wrappers: ["env", "command", "exec"]
      test:
        expect:
          - in: "env AWS_PROFILE=dev command exec aws s3 ls"
            out: "AWS_PROFILE=dev aws s3 ls"
        pass: ["AWS_PROFILE=dev aws s3 ls"]
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"env AWS_PROFILE=dev command exec aws s3 ls"}}`),
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
	hookOut, ok := payload["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	updatedInput, ok := hookOut["updatedInput"].(map[string]any)
	if !ok || updatedInput["command"] != "AWS_PROFILE=dev aws s3 ls" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeWithRTKOptionAppliesFinalRewrite(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rules:
  - id: aws-profile-to-env
    match:
      command: aws
      args_prefixes: ["--profile"]
    rewrite:
      move_flag_to_env:
        flag: "--profile"
        env: "AWS_PROFILE"
      test:
        expect:
          - in: "aws --profile read-only-profile s3 ls"
            out: "AWS_PROFILE=read-only-profile aws s3 ls"
        pass: ["AWS_PROFILE=read-only-profile aws s3 ls"]
`)
	binDir := t.TempDir()
	rtkPath := filepath.Join(binDir, "rtk")
	script := "#!/bin/sh\nif [ \"$1\" = \"rewrite\" ] && [ \"$2\" = \"AWS_PROFILE=read-only-profile aws s3 ls\" ]; then\n  printf 'rtk aws s3 ls\\n'\n  exit 3\nfi\nexit 1\n"
	if err := os.WriteFile(rtkPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake rtk: %v", err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude", "--rtk"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"aws --profile read-only-profile s3 ls"}}`),
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
	hookOut, ok := payload["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	if payload["systemMessage"] != "cmdproxy: rewrote [aws-profile-to-env -> rtk] -> rtk aws s3 ls" {
		t.Fatalf("payload = %+v", payload)
	}
	updatedInput, ok := hookOut["updatedInput"].(map[string]any)
	if !ok || updatedInput["command"] != "rtk aws s3 ls" {
		t.Fatalf("payload = %+v", payload)
	}
	cmdproxyOut, ok := payload["cmdproxy"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %+v", payload)
	}
	trace, ok := cmdproxyOut["trace"].([]any)
	if !ok || len(trace) != 2 {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunCheckAllow(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    reject:
      message: "git -C is blocked. Change into the target directory and rerun the command."
      test:
        expect: ["git -C foo status"]
        pass: ["git status"]
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
	writeUserConfig(t, home, `rules:
  - id: no-git-dash-c
    pattern: '^\s*git\s+-C\b'
    reject:
      message: "git -C is blocked. Change into the target directory and rerun the command."
      test:
        expect: ["git -C foo status"]
        pass: ["git status"]
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
	if !strings.Contains(stdout.String(), "ok: 1 rules, 2 tests checked") {
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
	data, err := os.ReadFile(filepath.Join(home, ".config", "cmdproxy", "cmdproxy.yml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "rules:") {
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
	if !strings.Contains(out, "Edit ~/.config/cmdproxy/cmdproxy.yml") {
		t.Fatalf("stdout=%q", out)
	}
	if !strings.Contains(out, "cmdproxy test") {
		t.Fatalf("stdout=%q", out)
	}
	if !strings.Contains(out, "cmdproxy help config") {
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

func TestRunConfigHelpShowsRuleExamples(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"help", "config"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Rewrite rule example") || !strings.Contains(out, "Reject rule example") {
		t.Fatalf("stdout=%q", out)
	}
}

func TestRunRewriteHelpShowsPrimitives(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"help", "rewrite"}, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "move_flag_to_env") || !strings.Contains(out, "continue") {
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
		{name: "sudo bash dash c", command: "sudo bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "sudo user bash dash c", command: "sudo -u root bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "nohup bash dash c", command: "nohup bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "timeout bash dash c", command: "timeout 10 bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "timeout signal bash dash c", command: "timeout --signal TERM 10 bash -c 'git status'", wantRuleID: "no-shell-dash-c"},
		{name: "busybox sh dash c", command: "busybox sh -c 'echo hi'", wantRuleID: "no-shell-dash-c"},
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
			if payload.Decision != "reject" || payload.RuleID != tt.wantRuleID {
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
			if payload["decision"] != "pass" {
				t.Fatalf("payload = %+v", payload)
			}
		})
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
