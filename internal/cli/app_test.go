package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cc-bash-proxy/internal/app"
	"github.com/tasuku43/cc-bash-proxy/internal/app/doctoring"
	"github.com/tasuku43/cc-bash-proxy/internal/infra/buildinfo"
	configrepo "github.com/tasuku43/cc-bash-proxy/internal/infra/config"
)

type hookPayload struct {
	HookSpecificOutput map[string]any `json:"hookSpecificOutput"`
	SystemMessage      string         `json:"systemMessage"`
	Cmdproxy           map[string]any `json:"cc-bash-proxy"`
}

type hookEnvSpec struct {
	UserConfig          string
	LocalConfig         string
	ClaudeSettings      string
	ClaudeLocalSettings string
	Command             string
	UseRTK              bool
	DisableAutoVerify   bool
}

func runClaudeHookTest(t *testing.T, spec hookEnvSpec) hookPayload {
	t.Helper()
	payload := runClaudeHookMapTest(t, spec)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json marshal error: %v", err)
	}

	var typed hookPayload
	if err := json.Unmarshal(data, &typed); err != nil {
		t.Fatalf("json error: %v", err)
	}
	return typed
}

func traceHasEffect(trace any, name string, effect string) bool {
	steps, ok := trace.([]any)
	if !ok {
		return false
	}
	for _, step := range steps {
		entry, ok := step.(map[string]any)
		if !ok {
			continue
		}
		if entry["name"] == name && entry["effect"] == effect {
			return true
		}
	}
	return false
}

func runClaudeHookMapTest(t *testing.T, spec hookEnvSpec) map[string]any {
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

	args := []string{"hook"}
	if spec.UseRTK {
		args = append(args, "--rtk")
	}
	if !spec.DisableAutoVerify {
		args = append(args, "--auto-verify")
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

	var payload map[string]any
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
	code := Run([]string{"hook", "--auto-verify"}, Streams{
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
	code := Run([]string{"hook", "--auto-verify"}, Streams{
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

func TestRunHookClaudeAllowWithoutRewriteOmitsRewriteSystemMessage(t *testing.T) {
	payload := runClaudeHookMapTest(t, hookEnvSpec{
		UserConfig: `permission:
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
		Command: "git status",
	})
	if _, ok := payload["systemMessage"]; ok {
		t.Fatalf("expected no rewrite systemMessage, payload=%+v", payload)
	}
}

func TestRunHookClaudeAskWithoutRewriteOmitsRewriteSystemMessage(t *testing.T) {
	payload := runClaudeHookMapTest(t, hookEnvSpec{
		UserConfig: `permission:
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
		Command: "git status",
	})
	if _, ok := payload["systemMessage"]; ok {
		t.Fatalf("expected no rewrite systemMessage, payload=%+v", payload)
	}
}

func TestRunHookClaudeRewriteIncludesRewriteSystemMessage(t *testing.T) {
	payload := runClaudeHookMapTest(t, hookEnvSpec{
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
          - "aws sts get-caller-identity"
test:
  - in: "aws --profile dev sts get-caller-identity"
    rewritten: "AWS_PROFILE=dev aws sts get-caller-identity"
    decision: allow
`,
		Command: "aws --profile dev sts get-caller-identity",
	})
	message, ok := payload["systemMessage"].(string)
	if !ok || !strings.Contains(message, "rewrote") {
		t.Fatalf("expected rewrite systemMessage, payload=%+v", payload)
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
	code := Run([]string{"hook", "--auto-verify"}, Streams{
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

func TestRunHookClaudeMigrationCompatSettingsAllowUpgradesAskToAllow(t *testing.T) {
	home := t.TempDir()
	writeClaudeSettings(t, home, `{
  "permissions": {
    "allow": ["Bash(git status -s)"]
  }
}`)
	writeUserConfig(t, home, `claude_permission_merge_mode: migration_compat
permission:
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
	code := Run([]string{"hook", "--auto-verify"}, Streams{
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

func TestRunHookClaudeStrictMergeDoesNotUpgradeAskToAllow(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `claude_permission_merge_mode: strict
permission:
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
		ClaudeSettings: `{
  "permissions": {
    "allow": ["Bash(git status)"]
  }
}`,
		Command: "git status",
	})
	if _, ok := payload.HookSpecificOutput["permissionDecision"]; ok {
		t.Fatalf("strict mode should keep ask, payload=%+v", payload)
	}
	if payload.Cmdproxy["outcome"] != "ask" {
		t.Fatalf("outcome=%v payload=%+v", payload.Cmdproxy["outcome"], payload)
	}
	if !traceHasEffect(payload.Cmdproxy["trace"], "claude_permission_merge_mode", "strict") {
		t.Fatalf("trace should include strict merge mode, payload=%+v", payload)
	}
}

func TestRunHookClaudeDefaultMergeDoesNotUpgradeAskToAllow(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `permission:
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
		ClaudeSettings: `{
  "permissions": {
    "allow": ["Bash(git status)"]
  }
}`,
		Command: "git status",
	})
	if _, ok := payload.HookSpecificOutput["permissionDecision"]; ok {
		t.Fatalf("default strict mode should keep ask, payload=%+v", payload)
	}
	if payload.Cmdproxy["outcome"] != "ask" {
		t.Fatalf("outcome=%v payload=%+v", payload.Cmdproxy["outcome"], payload)
	}
	if !traceHasEffect(payload.Cmdproxy["trace"], "claude_permission_merge_mode", "strict") {
		t.Fatalf("trace should include default strict merge mode, payload=%+v", payload)
	}
}

func TestRunHookClaudeMigrationCompatExplicitlyUpgradesAskToAllow(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `claude_permission_merge_mode: migration_compat
permission:
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
		ClaudeSettings: `{
  "permissions": {
    "allow": ["Bash(git status)"]
  }
}`,
		Command: "git status",
	})
	if payload.HookSpecificOutput["permissionDecision"] != "allow" {
		t.Fatalf("migration_compat should upgrade ask to allow, payload=%+v", payload)
	}
	if payload.Cmdproxy["outcome"] != "allow" {
		t.Fatalf("outcome=%v payload=%+v", payload.Cmdproxy["outcome"], payload)
	}
	if !traceHasEffect(payload.Cmdproxy["trace"], "claude_permission_merge_mode", "migration_compat") {
		t.Fatalf("trace should include migration_compat merge mode, payload=%+v", payload)
	}
}

func TestRunHookClaudeAuthoritativeMergeIgnoresClaudeAsk(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `claude_permission_merge_mode: cc_bash_proxy_authoritative
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
  - in: "git status"
    decision: allow
`,
		ClaudeSettings: `{
  "permissions": {
    "ask": ["Bash(git status)"]
  }
}`,
		Command: "git status",
	})
	if payload.HookSpecificOutput["permissionDecision"] != "allow" {
		t.Fatalf("authoritative mode should keep cc-bash-proxy allow, payload=%+v", payload)
	}
	if payload.Cmdproxy["outcome"] != "allow" {
		t.Fatalf("outcome=%v payload=%+v", payload.Cmdproxy["outcome"], payload)
	}
}

func TestRunHookClaudeAuthoritativeMergeStillHonorsClaudeDeny(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `claude_permission_merge_mode: cc_bash_proxy_authoritative
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
  - in: "git status"
    decision: allow
`,
		ClaudeSettings: `{
  "permissions": {
    "deny": ["Bash(git status)"]
  }
}`,
		Command: "git status",
	})
	if payload.HookSpecificOutput["permissionDecision"] != "deny" {
		t.Fatalf("authoritative mode should still honor Claude deny, payload=%+v", payload)
	}
	if payload.Cmdproxy["outcome"] != "deny" {
		t.Fatalf("outcome=%v payload=%+v", payload.Cmdproxy["outcome"], payload)
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
		wantExplicit        bool
		wantReason          string
		wantTrace           []struct {
			name   string
			effect string
		}
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
			wantExplicit:        true,
			wantReason:          "rule_match",
		},
		{
			name: "settings allow does not upgrade ask by default",
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
			wantDecision:        "ask",
			wantPermissionField: false,
			wantExplicit:        true,
			wantReason:          "rule_match",
			wantTrace: []struct {
				name   string
				effect string
			}{{name: "claude_settings", effect: "allow"}},
		},
		{
			name: "settings allow fills cc-bash-proxy no match in strict mode",
			cmdproxyPermission: `permission:
  allow:
    - match:
        command: aws
        subcommand: sts
      test:
        allow:
          - "aws sts get-caller-identity"
        pass:
          - "git status"
test:
  - in: "aws sts get-caller-identity"
    decision: allow
`,
			claudeSettings: `{
  "permissions": {
    "allow": ["Bash(git status)"]
  }
}`,
			command:             "git status",
			wantDecision:        "allow",
			wantPermissionField: true,
			wantExplicit:        true,
			wantReason:          "claude_settings",
			wantTrace: []struct {
				name   string
				effect string
			}{{name: "no_match", effect: "abstain"}, {name: "claude_settings", effect: "allow"}},
		},
		{
			name: "settings deny beats cc-bash-proxy allow",
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
			wantExplicit:        true,
			wantReason:          "claude_settings",
		},
		{
			name: "explicit ask beats allow",
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
    "ask": ["Bash(git status)"]
  }
}`,
			command:             "git status",
			wantDecision:        "ask",
			wantPermissionField: false,
			wantExplicit:        true,
			wantReason:          "claude_settings",
		},
		{
			name: "settings ask fills cc-bash-proxy no match",
			cmdproxyPermission: `permission:
  allow:
    - match:
        command: aws
        subcommand: sts
      test:
        allow:
          - "aws sts get-caller-identity"
        pass:
          - "git status"
test:
  - in: "aws sts get-caller-identity"
    decision: allow
`,
			claudeSettings: `{
  "permissions": {
    "ask": ["Bash(git status)"]
  }
}`,
			command:             "git status",
			wantDecision:        "ask",
			wantPermissionField: false,
			wantExplicit:        true,
			wantReason:          "claude_settings",
			wantTrace: []struct {
				name   string
				effect string
			}{{name: "no_match", effect: "abstain"}, {name: "claude_settings", effect: "ask"}},
		},
		{
			name: "cc-bash-proxy allow plus settings abstain stays allow",
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
			claudeSettings:      `{ "permissions": {} }`,
			command:             "git status",
			wantDecision:        "allow",
			wantPermissionField: true,
			wantExplicit:        true,
			wantReason:          "rule_match",
		},
		{
			name: "both abstain become ask",
			cmdproxyPermission: `permission:
  allow:
    - match:
        command: aws
        subcommand: sts
      test:
        allow:
          - "aws sts get-caller-identity"
        pass:
          - "git status"
test:
  - in: "aws sts get-caller-identity"
    decision: allow
`,
			claudeSettings:      `{ "permissions": {} }`,
			command:             "git status",
			wantDecision:        "ask",
			wantPermissionField: false,
			wantExplicit:        false,
			wantReason:          "default_fallback",
			wantTrace: []struct {
				name   string
				effect string
			}{{name: "no_match", effect: "abstain"}, {name: "claude_settings", effect: "abstain"}, {name: "default", effect: "ask"}},
		},
		{
			name: "cc-bash-proxy ask plus settings abstain stays ask",
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
			wantExplicit:        true,
			wantReason:          "rule_match",
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
			} else if has {
				t.Fatalf("unexpected permissionDecision=%v payload=%+v", got, payload)
			}
			if payload.Cmdproxy["outcome"] != tt.wantDecision {
				t.Fatalf("outcome=%v payload=%+v", payload.Cmdproxy["outcome"], payload)
			}
			if payload.Cmdproxy["explicit"] != tt.wantExplicit {
				t.Fatalf("explicit=%v want=%v payload=%+v", payload.Cmdproxy["explicit"], tt.wantExplicit, payload)
			}
			if tt.wantReason != "" && payload.Cmdproxy["reason"] != tt.wantReason {
				t.Fatalf("reason=%v want=%v payload=%+v", payload.Cmdproxy["reason"], tt.wantReason, payload)
			}
			for _, want := range tt.wantTrace {
				if !traceHasEffect(payload.Cmdproxy["trace"], want.name, want.effect) {
					t.Fatalf("trace missing %s/%s payload=%+v", want.name, want.effect, payload)
				}
			}
		})
	}
}

func TestRunHookClaudeMergesGlobalAndLocalPolicyAndSettings(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `claude_permission_merge_mode: migration_compat
rewrite:
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
	code := Run([]string{"hook", "--rtk", "--auto-verify"}, Streams{
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
	message, ok := payload["systemMessage"].(string)
	if !ok || !strings.Contains(message, "rtk") {
		t.Fatalf("expected rtk rewrite systemMessage, payload=%+v", payload)
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
	code := Run([]string{"hook", "--auto-verify"}, Streams{
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

func TestRunHookClaudeDeniesWhenArtifactMissingByDefault(t *testing.T) {
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
	code := Run([]string{"hook"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"bash -c 'git status'"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
	reason, _ := hookOut["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "verified artifact missing or stale; run cc-bash-proxy verify") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRunHookClaudeDeniesWhenArtifactStaleByDefault(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
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
	if _, err := configrepo.VerifyEffectiveToAllCaches(cwd, home, "", "", "claude", "test"); err != nil {
		t.Fatalf("verify effective: %v", err)
	}
	writeUserConfig(t, home, `permission:
  allow:
    - match:
        command: git
        subcommand: diff
      test:
        allow:
          - "git diff"
        pass:
          - "git status"
test:
  - in: "git diff"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git diff"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: cwd, Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
	reason, _ := hookOut["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "verified artifact missing or stale; run cc-bash-proxy verify") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRunHookClaudeDeniesWhenArtifactEvaluationSemanticsIncompatible(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
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
	if _, err := configrepo.VerifyEffectiveToAllCaches(cwd, home, "", cacheHome, "claude", "test"); err != nil {
		t.Fatalf("verify effective: %v", err)
	}
	removeCLIJSONField(t, singleCLICachePath(t, filepath.Join(cacheHome, "cc-bash-proxy")), "evaluation_semantics_version")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git status"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: cwd, Home: home, XDGCacheHome: cacheHome})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
	reason, _ := hookOut["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "evaluation semantics version 0") || !strings.Contains(reason, "run cc-bash-proxy verify") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRunHookClaudeAutoVerifyVerifiesWhenArtifactMissing(t *testing.T) {
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
	code := Run([]string{"hook", "--auto-verify"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"bash -c 'git status'"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	entries, err := os.ReadDir(configrepo.HookCacheDir(home, ""))
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected auto-verify artifact, err=%v entries=%v", err, entries)
	}
}

func TestRunHookClaudeStructuredAllowFailsClosedOnCompoundCommand(t *testing.T) {
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
  - in: "git status && rm -rf /tmp/x"
    decision: ask
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "--auto-verify"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git status && rm -rf /tmp/x"}}`),
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
	ccPayload := payload["cc-bash-proxy"].(map[string]any)
	if ccPayload["outcome"] != "ask" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeBashPrefixAllowDoesNotAuthorizeCompoundRightSide(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `permission:
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
  - in: "git status && rm -rf /tmp/x"
    decision: ask
`,
		ClaudeSettings: `{
  "permissions": {
    "allow": ["Bash(git status *)"]
  }
}`,
		Command: "git status && rm -rf /tmp/x",
	})
	if _, ok := payload.HookSpecificOutput["permissionDecision"]; ok {
		t.Fatalf("payload = %+v", payload)
	}
	if payload.Cmdproxy["outcome"] != "ask" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookAllowsCompoundWhenEveryCommandIsIndividuallyAllowed(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `permission:
  allow:
    - match:
        command: git
        subcommand: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
    - match:
        command: git
        subcommand: diff
      test:
        allow:
          - "git diff"
        pass:
          - "git status"
    - match:
        command: git
        subcommand: log
      test:
        allow:
          - "git log"
        pass:
          - "git status"
test:
  - in: "git status && git diff && git log"
    decision: allow
  - in: "git status; git diff; git log"
    decision: allow
  - in: "git status || git diff || git log"
    decision: allow
`,
		Command: "git status && git diff && git log",
	})
	if payload.HookSpecificOutput["permissionDecision"] != "allow" {
		t.Fatalf("payload = %+v", payload)
	}
	if payload.Cmdproxy["outcome"] != "allow" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookDeniesCompoundWhenAnyCommandIsDenied(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `permission:
  deny:
    - match:
        command: rm
      test:
        deny:
          - "rm -rf /tmp/x"
        pass:
          - "git status"
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
  - in: "git status && rm -rf /tmp/x"
    decision: deny
`,
		Command: "git status && rm -rf /tmp/x",
	})
	if payload.HookSpecificOutput["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
	if payload.Cmdproxy["outcome"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestVerifyStatus(t *testing.T) {
	report := doctoring.Report{
		Checks: []doctoring.Check{
			{ID: "config.parse", Status: doctoring.StatusPass},
			{ID: "tests.pass", Status: doctoring.StatusPass},
		},
	}
	ok, reasons := app.VerifyStatus(report, buildinfo.Info{Version: "dev", Module: "github.com/tasuku43/cc-bash-proxy", VCSRevision: "abc123"}, "claude")
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
	data, err := os.ReadFile(filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "permission:") {
		t.Fatalf("config=%q", string(data))
	}
}

func writeUserConfig(t *testing.T, home string, body string) {
	t.Helper()
	path := filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml")
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
	path := filepath.Join(cwd, ".cc-bash-proxy", "cc-bash-proxy.yaml")
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

func singleCLICachePath(t *testing.T, dir string) string {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	return filepath.Join(dir, files[0].Name())
}

func removeCLIJSONField(t *testing.T, path string, key string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	delete(payload, key)
	data, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
