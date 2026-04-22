package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cmdproxy/internal/buildinfo"
	"github.com/tasuku43/cmdproxy/internal/config"
	"github.com/tasuku43/cmdproxy/internal/doctor"
)

type hookPayload struct {
	HookSpecificOutput map[string]any `json:"hookSpecificOutput"`
	SystemMessage      string         `json:"systemMessage"`
	Cmdproxy           map[string]any `json:"cmdproxy"`
}

type hookEnvSpec struct {
	UserConfig          string
	LocalConfig         string
	ClaudeSettings      string
	ClaudeLocalSettings string
	Command             string
	UseRTK              bool
}

func runClaudeHookTest(t *testing.T, spec hookEnvSpec) hookPayload {
	t.Helper()
	home := t.TempDir()
	cwd := t.TempDir()

	if spec.UserConfig != "" {
		writeUserConfig(t, home, spec.UserConfig)
	}
	if spec.LocalConfig != "" {
		writeProjectConfig(t, cwd, spec.LocalConfig)
	}
	if spec.ClaudeSettings != "" {
		writeClaudeSettings(t, home, spec.ClaudeSettings)
	}
	if spec.ClaudeLocalSettings != "" {
		writeProjectClaudeLocalSettings(t, cwd, spec.ClaudeLocalSettings)
	}

	args := []string{"hook", "claude"}
	if spec.UseRTK {
		args = append(args, "--rtk")
	}

	var stdout, stderr bytes.Buffer
	code := Run(args, Streams{
		Stdin:  strings.NewReader(fmt.Sprintf(`{"tool_name":"Bash","tool_input":{"command":%q}}`, spec.Command)),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: cwd, Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}

	var payload hookPayload
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	return payload
}

func TestRunHookClaudeAllowReturnsAllowAndUpdatedInput(t *testing.T) {
	home := t.TempDir()
	writeClaudeSettings(t, home, `{
  "permissions": {
    "allow": ["Bash(AWS_PROFILE=dev aws sts:*)"]
  }
}`)
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

func TestRunHookClaudeAllowRemainsAllowWithoutClaudeSettingsMatch(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - match:
        command: git
        subcommand: diff
      test:
        allow:
          - "git diff goal.md"
        pass:
          - "git status"
test:
  - in: "git diff goal.md"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git diff goal.md"}}`),
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
}

func TestRunHookClaudeSettingsAllowUpgradesAskToAllow(t *testing.T) {
	home := t.TempDir()
	writeClaudeSettings(t, home, `{
  "permissions": {
    "allow": ["Bash(git status -s)"]
  }
}`)
	writeUserConfig(t, home, `permission:
  ask:
    - match:
        command: git
        args_contains:
          - "-s"
      test:
        ask:
          - "git status -s"
        pass:
          - "git status"
test:
  - in: "git status -s"
    decision: ask
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git status -s"}}`),
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
}

func TestRunHookClaudePermissionMergeMatrix(t *testing.T) {
	tests := []struct {
		name                string
		cmdproxyPermission  string
		claudeSettings      string
		command             string
		wantDecision        string
		wantPermissionField bool
	}{
		{
			name: "deny beats allow",
			cmdproxyPermission: `permission:
  deny:
    - match:
        command: git
        subcommand: status
      test:
        deny:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: deny
`,
			claudeSettings: `{
  "permissions": {
    "allow": ["Bash(git status)"]
  }
}`,
			command:             "git status",
			wantDecision:        "deny",
			wantPermissionField: true,
		},
		{
			name: "settings allow upgrades ask",
			cmdproxyPermission: `permission:
  ask:
    - match:
        command: git
        subcommand: status
      test:
        ask:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: ask
`,
			claudeSettings: `{
  "permissions": {
    "allow": ["Bash(git status)"]
  }
}`,
			command:             "git status",
			wantDecision:        "allow",
			wantPermissionField: true,
		},
		{
			name: "settings deny beats cmdproxy allow",
			cmdproxyPermission: `permission:
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
`,
			claudeSettings: `{
  "permissions": {
    "deny": ["Bash(git status)"]
  }
}`,
			command:             "git status",
			wantDecision:        "deny",
			wantPermissionField: true,
		},
		{
			name: "no explicit allow becomes ask",
			cmdproxyPermission: `permission:
  ask:
    - match:
        command: git
        subcommand: status
      test:
        ask:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: ask
`,
			claudeSettings:      `{ "permissions": {} }`,
			command:             "git status",
			wantDecision:        "ask",
			wantPermissionField: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := runClaudeHookTest(t, hookEnvSpec{
				UserConfig:     tt.cmdproxyPermission,
				ClaudeSettings: tt.claudeSettings,
				Command:        tt.command,
			})

			got, has := payload.HookSpecificOutput["permissionDecision"]
			if tt.wantPermissionField {
				if !has || got != tt.wantDecision {
					t.Fatalf("permissionDecision=%v has=%v payload=%+v", got, has, payload)
				}
				return
			}
			if has {
				t.Fatalf("unexpected permissionDecision=%v payload=%+v", got, payload)
			}
			if payload.Cmdproxy["outcome"] != tt.wantDecision {
				t.Fatalf("outcome=%v payload=%+v", payload.Cmdproxy["outcome"], payload)
			}
		})
	}
}

func TestRunHookClaudeMergesGlobalAndLocalPolicyAndSettings(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `rewrite:
  - match:
      command: aws
      args_contains: ["--profile"]
    move_flag_to_env:
      flag: "--profile"
      env: "AWS_PROFILE"
    test:
      - in: "aws --profile dev sts get-caller-identity"
        out: "AWS_PROFILE=dev aws sts get-caller-identity"
permission:
  ask:
    - match:
        command: aws
        subcommand: sts
      test:
        ask:
          - "AWS_PROFILE=dev aws sts get-caller-identity"
        pass:
          - "git status"
test:
  - in: "aws --profile dev sts get-caller-identity"
    rewritten: "AWS_PROFILE=dev aws sts get-caller-identity"
    decision: ask
`,
		LocalConfig: `permission:
  deny:
    - pattern: '^\s*git\s+push'
      message: "push blocked"
      test:
        deny:
          - "git push origin main"
        pass:
          - "git status"
test:
  - in: "git push origin main"
    decision: deny
`,
		ClaudeSettings: `{
  "permissions": {
    "ask": ["Bash(git status)"]
  }
}`,
		ClaudeLocalSettings: `{
  "permissions": {
    "allow": ["Bash(AWS_PROFILE=dev aws sts:*)"]
  }
}`,
		Command: "aws --profile dev sts get-caller-identity",
	})

	if payload.HookSpecificOutput["permissionDecision"] != "allow" {
		t.Fatalf("payload=%+v", payload)
	}
	updated := payload.HookSpecificOutput["updatedInput"].(map[string]any)
	if updated["command"] != "AWS_PROFILE=dev aws sts get-caller-identity" {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestRunHookClaudeRTKEvaluatesPermissionsBeforeRTKRewrite(t *testing.T) {
	home := t.TempDir()
	toolDir := t.TempDir()
	rtkPath := filepath.Join(toolDir, "rtk")
	script := "#!/bin/sh\nif [ \"$1\" = \"rewrite\" ]; then\n  printf 'rtk %s\\n' \"$2\"\n  exit 0\nfi\nexit 1\n"
	if err := os.WriteFile(rtkPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fmt.Sprintf("%s:%s", toolDir, os.Getenv("PATH")))

	writeClaudeSettings(t, home, `{
  "permissions": {
    "allow": ["Bash(git diff goal.md)"]
  }
}`)
	writeUserConfig(t, home, `permission:
  allow:
    - match:
        command: git
        subcommand: diff
      test:
        allow:
          - "git diff goal.md"
        pass:
          - "git status"
test:
  - in: "git diff goal.md"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "claude", "--rtk"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git diff goal.md"}}`),
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
	if updatedInput["command"] != "rtk git diff goal.md" {
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

func TestVerifyStatus(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Check{
			{ID: "config.parse", Status: doctor.StatusPass},
			{ID: "tests.pass", Status: doctor.StatusPass},
		},
	}
	ok, reasons := verifyStatus(report, buildinfo.Info{Version: "dev", Module: "github.com/tasuku43/cmdproxy", VCSRevision: "abc123"}, "claude")
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

func writeProjectConfig(t *testing.T, cwd string, body string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o755); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	path := filepath.Join(cwd, ".cmdproxy", "cmdproxy.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeClaudeSettings(t *testing.T, home string, body string) {
	t.Helper()
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeProjectClaudeLocalSettings(t *testing.T, cwd string, body string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o755); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	path := filepath.Join(cwd, ".claude", "settings.local.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
