package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cc-bash-guard/internal/app"
	"github.com/tasuku43/cc-bash-guard/internal/app/doctoring"
	"github.com/tasuku43/cc-bash-guard/internal/infra/buildinfo"
	configrepo "github.com/tasuku43/cc-bash-guard/internal/infra/config"
)

type hookPayload struct {
	HookSpecificOutput map[string]any `json:"hookSpecificOutput"`
	SystemMessage      string         `json:"systemMessage"`
	Cmdproxy           map[string]any `json:"cc-bash-guard"`
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

func traceHasReason(trace any, name string, reason string) bool {
	steps, ok := trace.([]any)
	if !ok {
		return false
	}
	for _, step := range steps {
		entry, ok := step.(map[string]any)
		if !ok {
			continue
		}
		if entry["name"] == name && entry["reason"] == reason {
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

func TestRunHookClaudeAllowReturnsAllowWithoutUpdatedInput(t *testing.T) {
	home := t.TempDir()
	writeClaudeSettings(t, home, `{
  "permissions": {
    "allow": ["Bash(aws --profile dev sts:*)"]
  }
}`)
	writeUserConfig(t, home, `permission:
  allow:
    - command:

        name: aws

        semantic:

          service: sts
          profile: dev
      test:
        allow:
          - "aws --profile dev sts get-caller-identity"
        pass:
          - "aws --profile dev s3 ls"
test:
  - in: "aws --profile dev sts get-caller-identity"
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
	if _, ok := hookOut["updatedInput"]; ok {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeSupportedPolicyDoesNotInvokeRTKWithoutFlag(t *testing.T) {
	toolDir := t.TempDir()
	markerPath := filepath.Join(toolDir, "called")
	rtkPath := filepath.Join(toolDir, "rtk")
	script := fmt.Sprintf("#!/bin/sh\nprintf called > %q\nprintf 'rtk %%s\\n' \"$2\"\n", markerPath)
	if err := os.WriteFile(rtkPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fmt.Sprintf("%s:%s", toolDir, os.Getenv("PATH")))

	payload := runClaudeHookMapTest(t, hookEnvSpec{
		UserConfig: `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: diff
      test:
        allow:
          - "git diff goal.md"
        pass:
          - "git status"
test:
  - in: "git diff goal.md"
    decision: allow
`,
		Command: "git diff goal.md",
	})

	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["permissionDecision"] != "allow" {
		t.Fatalf("payload = %+v", payload)
	}
	if _, ok := hookOut["updatedInput"]; ok {
		t.Fatalf("payload = %+v", payload)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("rtk should not run without --rtk, stat err=%v", err)
	}
}

func TestRunHookClaudeAskReturnsAsk(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  ask:
    - command:

        name: aws

        semantic:

          service: s3
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
	if hookOut["permissionDecision"] != "ask" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeAllowWithoutRewriteOmitsRewriteSystemMessage(t *testing.T) {
	payload := runClaudeHookMapTest(t, hookEnvSpec{
		UserConfig: `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
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
    - command:

        name: git

        semantic:

          verb: status
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

func TestRunHookClaudeRTKEvaluatesPermissionsBeforeRTKRewrite(t *testing.T) {
	toolDir := t.TempDir()
	rtkPath := filepath.Join(toolDir, "rtk")
	script := "#!/bin/sh\nif [ \"$1\" = \"rewrite\" ]; then\n  printf 'rtk %s\\n' \"$2\"\n  exit 0\nfi\nexit 1\n"
	if err := os.WriteFile(rtkPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fmt.Sprintf("%s:%s", toolDir, os.Getenv("PATH")))

	payload := runClaudeHookMapTest(t, hookEnvSpec{
		UserConfig: `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: diff
      test:
        allow:
          - "git diff goal.md"
        pass:
          - "git status"
test:
  - in: "git diff goal.md"
    decision: allow
`,
		ClaudeSettings: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"cc-bash-guard hook --rtk"}]}]}}`,
		Command:        "git diff goal.md",
		UseRTK:         true,
	})

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

func TestRunHookClaudeRTKOmittedUpdatedInputWhenCommandUnchanged(t *testing.T) {
	toolDir := t.TempDir()
	markerPath := filepath.Join(toolDir, "called")
	rtkPath := filepath.Join(toolDir, "rtk")
	script := fmt.Sprintf("#!/bin/sh\nprintf called > %q\nprintf '%%s\\n' \"$2\"\n", markerPath)
	if err := os.WriteFile(rtkPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fmt.Sprintf("%s:%s", toolDir, os.Getenv("PATH")))

	payload := runClaudeHookMapTest(t, hookEnvSpec{
		UserConfig: `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
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
		UseRTK:  true,
	})

	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["permissionDecision"] != "allow" {
		t.Fatalf("payload = %+v", payload)
	}
	if _, ok := hookOut["updatedInput"]; ok {
		t.Fatalf("expected unchanged RTK result to omit updatedInput, payload=%+v", payload)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("rtk should run for non-deny --rtk decision, stat err=%v", err)
	}
}

func TestRunHookClaudeRTKDoesNotRunAfterDeny(t *testing.T) {
	toolDir := t.TempDir()
	markerPath := filepath.Join(toolDir, "called")
	rtkPath := filepath.Join(toolDir, "rtk")
	script := fmt.Sprintf("#!/bin/sh\nprintf called > %q\nprintf 'rtk %%s\\n' \"$2\"\n", markerPath)
	if err := os.WriteFile(rtkPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fmt.Sprintf("%s:%s", toolDir, os.Getenv("PATH")))

	payload := runClaudeHookMapTest(t, hookEnvSpec{
		UserConfig: `permission:
  deny:
    - command:
        name: rm
      test:
        deny:
          - "rm -rf /tmp/x"
test:
  - in: "rm -rf /tmp/x"
    decision: deny
`,
		ClaudeSettings: `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"cc-bash-guard hook --rtk"}]}]}}`,
		Command:        "rm -rf /tmp/x",
		UseRTK:         true,
	})

	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("rtk should not run after deny, stat err=%v", err)
	}
}

func TestEvaluateForCommandPreservesDecisionCommandWithoutRTK(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	command := "bash -c 'git status'"
	writeUserConfig(t, home, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "bash -c 'git status'"
        pass:
          - "git diff"
test:
  - in: "bash -c 'git status'"
    decision: allow
`)

	_, decision, err := app.EvaluateForCommand(command, app.Env{Cwd: cwd, Home: home}, true)
	if err != nil {
		t.Fatalf("EvaluateForCommand error: %v", err)
	}
	if decision.Outcome != "allow" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Command != command {
		t.Fatalf("decision command changed: got %q want %q", decision.Command, command)
	}
	if decision.OriginalCommand != command {
		t.Fatalf("original command changed: got %q want %q", decision.OriginalCommand, command)
	}
}

func TestRunVerifyRejectsRewriteConfig(t *testing.T) {
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
    - command:

        name: aws

        semantic:

          service: sts

      env:

        requires: ["AWS_PROFILE"]
      test:
        allow:
          - "AWS_PROFILE=dev aws sts get-caller-identity"
        pass:
          - "aws sts get-caller-identity"
test:
  - in: "aws --profile dev sts get-caller-identity"
    rewritten: "AWS_PROFILE=dev aws sts get-caller-identity"
    decision: allow
`)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify", "--format", "json"}, Streams{
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: home})
	if code == 0 {
		t.Fatalf("code = 0, want failure stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "top-level rewrite is no longer supported") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Use permission.command / env / patterns") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestRunHookClaudeAllowRemainsAllowWithoutClaudeSettingsMatch(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: diff
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
		wantTraceReason []struct {
			name   string
			reason string
		}
	}{
		{
			name: "deny beats allow",
			cmdproxyPermission: `permission:
  deny:
    - command:

        name: git

        semantic:

          verb: status
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
    - command:

        name: git

        semantic:

          verb: status
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
			wantPermissionField: true,
			wantExplicit:        true,
			wantReason:          "rule_match",
			wantTrace: []struct {
				name   string
				effect string
			}{{name: "claude_settings", effect: "allow"}},
		},
		{
			name: "settings allow fills cc-bash-guard no match",
			cmdproxyPermission: `permission:
  allow:
    - command:

        name: aws

        semantic:

          service: sts
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
			name: "settings deny beats cc-bash-guard allow",
			cmdproxyPermission: `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
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
    - command:

        name: git

        semantic:

          verb: status
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
			wantPermissionField: true,
			wantExplicit:        true,
			wantReason:          "claude_settings",
		},
		{
			name: "settings ask fills cc-bash-guard no match",
			cmdproxyPermission: `permission:
  allow:
    - command:

        name: aws

        semantic:

          service: sts
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
			wantPermissionField: true,
			wantExplicit:        true,
			wantReason:          "claude_settings",
			wantTrace: []struct {
				name   string
				effect string
			}{{name: "no_match", effect: "abstain"}, {name: "claude_settings", effect: "ask"}},
		},
		{
			name: "cc-bash-guard allow plus settings abstain stays allow",
			cmdproxyPermission: `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
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
    - command:

        name: aws

        semantic:

          service: sts
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
			wantPermissionField: true,
			wantExplicit:        false,
			wantReason:          "default_fallback",
			wantTrace: []struct {
				name   string
				effect string
			}{{name: "no_match", effect: "abstain"}, {name: "claude_settings", effect: "abstain"}, {name: "permission_sources_merge", effect: "ask"}},
			wantTraceReason: []struct {
				name   string
				reason string
			}{{name: "permission_sources_merge", reason: "all sources abstained; fallback ask"}},
		},
		{
			name: "cc-bash-guard ask plus settings abstain stays ask",
			cmdproxyPermission: `permission:
  ask:
    - command:

        name: git

        semantic:

          verb: status
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
			wantPermissionField: true,
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
			for _, want := range tt.wantTraceReason {
				if !traceHasReason(payload.Cmdproxy["trace"], want.name, want.reason) {
					t.Fatalf("trace missing %s reason %q payload=%+v", want.name, want.reason, payload)
				}
			}
		})
	}
}

func TestRunHookClaudeMergesGlobalAndLocalPolicyAndSettings(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `permission:
  ask:
    - command:

        name: git

        semantic:

          verb: status
      test:
        ask:
          - "git status"
        pass:
          - "aws --profile dev sts get-caller-identity"
test:
  - in: "git status"
    decision: ask
`,
		LocalConfig: `permission:
  deny:
    - patterns:

        - '^\s*git\s+push'
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
    "allow": ["Bash(aws --profile dev sts:*)"]
  }
}`,
		Command: "aws --profile dev sts get-caller-identity",
	})

	if payload.HookSpecificOutput["permissionDecision"] != "allow" {
		t.Fatalf("payload=%+v", payload)
	}
	if _, ok := payload.HookSpecificOutput["updatedInput"]; ok {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestRunHookClaudeAllowUsesRuleMessageAsPermissionDecisionReason(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      message: "git status auto-approved"
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
	code := Run([]string{"hook", "--auto-verify"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git status"}}`),
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
	if got := hookOut["permissionDecisionReason"]; got != "git status auto-approved" {
		t.Fatalf("permissionDecisionReason = %q, want rule message; payload=%+v", got, payload)
	}
}

func TestRunHookClaudeAskUsesRuleMessageAsPermissionDecisionReason(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  ask:
    - name: git diff review
      command:
        name: git
        semantic:
          verb: diff
      message: "git diff requires confirmation"
      test:
        ask:
          - "git diff"
        pass:
          - "git status"
test:
  - in: "git diff"
    decision: ask
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook", "--auto-verify"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git diff"}}`),
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
	if hookOut["permissionDecision"] != "ask" {
		t.Fatalf("permissionDecision = %v, want ask; payload=%+v", hookOut["permissionDecision"], payload)
	}
	if got := hookOut["permissionDecisionReason"]; got != "git diff requires confirmation" {
		t.Fatalf("permissionDecisionReason = %q, want rule message; payload=%+v", got, payload)
	}
}

func TestRunHookClaudeInvalidInputReturnsDenyJSONWithSuccessExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"hook"}, Streams{
		Stdin:  strings.NewReader(`{"tool_name":"Write","tool_input":{"file_path":"/tmp/x"}}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: t.TempDir(), Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	hookOut := payload["hookSpecificOutput"].(map[string]any)
	if hookOut["hookEventName"] != "PreToolUse" {
		t.Fatalf("payload = %+v", payload)
	}
	if hookOut["permissionDecision"] != "deny" {
		t.Fatalf("payload = %+v", payload)
	}
	reason, _ := hookOut["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "invalid_input") || !strings.Contains(reason, "unsupported tool_name") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRunHookClaudeDenyReturnsDeny(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  deny:
    - command:

        name: rm
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
	writeUserConfig(t, home, `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
      test:
        allow:
          - "bash -c 'git status'"
        pass:
          - "git diff"
test:
  - in: "bash -c 'git status'"
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
	if !strings.Contains(reason, "verified artifact missing or stale; run cc-bash-guard verify") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRunHookClaudeDeniesWhenArtifactStaleByDefault(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
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
    - command:

        name: git

        semantic:

          verb: diff
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
	if !strings.Contains(reason, "verified artifact missing or stale; run cc-bash-guard verify") {
		t.Fatalf("reason = %q", reason)
	}
}

func runExplainCLI(t *testing.T, home string, cwd string, cacheHome string, command string, args ...string) (int, string, string) {
	t.Helper()
	allArgs := append([]string{"explain"}, args...)
	allArgs = append(allArgs, command)
	var stdout, stderr bytes.Buffer
	code := Run(allArgs, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: cwd, Home: home, XDGCacheHome: cacheHome})
	return code, stdout.String(), stderr.String()
}

func verifyExplainConfig(t *testing.T, home string, cwd string, cacheHome string) {
	t.Helper()
	if _, err := configrepo.VerifyEffectiveToAllCaches(cwd, home, "", cacheHome, "claude", "test"); err != nil {
		t.Fatalf("verify effective: %v", err)
	}
}

func TestRunExplainSimpleAllow(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: allow
`)
	verifyExplainConfig(t, home, cwd, cacheHome)

	code, stdout, stderr := runExplainCLI(t, home, cwd, cacheHome, "git status")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	for _, want := range []string{
		"outcome: allow",
		"name: git status",
		"parser: git",
		"verb: status",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("explain output missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunExplainDenyWithIncludedSource(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	configDir := filepath.Join(home, ".config", "cc-bash-guard")
	if err := os.MkdirAll(filepath.Join(configDir, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "policies", "git.yml"), []byte(`permission:
  deny:
    - name: git force push
      command:
        name: git
        semantic:
          verb: push
          force: true
      test:
        deny:
          - "git push --force origin main"
        pass:
          - "git status"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeUserConfig(t, home, `include:
  - ./policies/git.yml
test:
  - in: "git push --force origin main"
    decision: deny
`)
	verifyExplainConfig(t, home, cwd, cacheHome)

	code, stdout, stderr := runExplainCLI(t, home, cwd, cacheHome, "git push --force origin main")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	for _, want := range []string{
		"outcome: deny",
		"name: git force push",
		"policies/git.yml",
		"bucket: permission.deny",
		"force: true",
		"reason: cc-bash-guard policy denied",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("explain output missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunExplainFallbackAsk(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: allow
`)
	verifyExplainConfig(t, home, cwd, cacheHome)

	code, stdout, stderr := runExplainCLI(t, home, cwd, cacheHome, "unknown-tool foo")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	for _, want := range []string{
		"cc-bash-guard policy:",
		"outcome: abstain",
		"Claude settings:",
		"outcome: abstain",
		"Final decision:",
		"outcome: ask",
		"all permission sources abstained; fallback ask",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("explain output missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunExplainJSON(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: allow
`)
	verifyExplainConfig(t, home, cwd, cacheHome)

	code, stdout, stderr := runExplainCLI(t, home, cwd, cacheHome, "git status", "--format", "json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout)
	}
	if payload["command"] != "git status" {
		t.Fatalf("payload=%+v", payload)
	}
	parsed := payload["parsed"].(map[string]any)
	if len(parsed["segments"].([]any)) == 0 {
		t.Fatalf("payload=%+v", payload)
	}
	final := payload["final"].(map[string]any)
	if final["outcome"] != "allow" {
		t.Fatalf("payload=%+v", payload)
	}
	policy := payload["policy"].(map[string]any)
	if policy["matched_rule"] == nil {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestRunExplainShellC(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "bash -c 'git status'"
        pass:
          - "git diff"
test:
  - in: "bash -c 'git status'"
    decision: allow
`)
	verifyExplainConfig(t, home, cwd, cacheHome)

	code, stdout, stderr := runExplainCLI(t, home, cwd, cacheHome, "bash -c 'git status'")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	for _, want := range []string{
		"bash -c 'git status'",
		"shape: shell_c",
		"evaluated inner command:",
		"command.name: git",
		"verb: status",
		"not rewritten or executed",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("explain output missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunExplainAbsolutePath(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "/usr/bin/git status"
        pass:
          - "git diff"
test:
  - in: "/usr/bin/git status"
    decision: allow
`)
	verifyExplainConfig(t, home, cwd, cacheHome)

	code, stdout, stderr := runExplainCLI(t, home, cwd, cacheHome, "/usr/bin/git status")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
	}
	for _, want := range []string{
		"program_token: /usr/bin/git",
		"command.name: git",
		"parser: git",
		"verb: status",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("explain output missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunExplainParseErrorReturnsNonZero(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: allow
`)
	verifyExplainConfig(t, home, cwd, cacheHome)

	code, stdout, _ := runExplainCLI(t, home, cwd, cacheHome, "bash -c 'echo $('")
	if code == 0 {
		t.Fatalf("expected non-zero stdout=%s", stdout)
	}
	if !strings.Contains(stdout, "diagnostics:") || strings.Contains(stdout, "outcome: allow") {
		t.Fatalf("stdout=%s", stdout)
	}
}

func TestRunExplainStaleArtifact(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
test:
  - in: "git status"
    decision: allow
`)
	verifyExplainConfig(t, home, cwd, cacheHome)
	writeUserConfig(t, home, `permission:
  allow:
    - name: git diff
      command:
        name: git
        semantic:
          verb: diff
      test:
        allow:
          - "git diff"
        pass:
          - "git status"
test:
  - in: "git diff"
    decision: allow
`)

	code, stdout, _ := runExplainCLI(t, home, cwd, cacheHome, "git diff")
	if code == 0 {
		t.Fatalf("expected non-zero stdout=%s", stdout)
	}
	if !strings.Contains(stdout, "verified artifact missing or stale") || !strings.Contains(stdout, "run cc-bash-guard verify") {
		t.Fatalf("stdout=%s", stdout)
	}
}

func TestRunHookClaudeDeniesWhenArtifactEvaluationSemanticsIncompatible(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
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
	removeCLIJSONField(t, singleCLICachePath(t, filepath.Join(cacheHome, "cc-bash-guard")), "evaluation_semantics_version")

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
	if !strings.Contains(reason, "evaluation semantics version 0") || !strings.Contains(reason, "run cc-bash-guard verify") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRunHookClaudeAutoVerifyVerifiesWhenArtifactMissing(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
      test:
        allow:
          - "bash -c 'git status'"
        pass:
          - "git diff"
test:
  - in: "bash -c 'git status'"
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
    - command:

        name: git

        semantic:

          verb: status
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
	if hookOut["permissionDecision"] != "ask" {
		t.Fatalf("payload = %+v", payload)
	}
	ccPayload := payload["cc-bash-guard"].(map[string]any)
	if ccPayload["outcome"] != "ask" {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestRunHookClaudeBashPrefixAllowDoesNotAuthorizeCompoundRightSide(t *testing.T) {
	payload := runClaudeHookTest(t, hookEnvSpec{
		UserConfig: `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
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
	if payload.HookSpecificOutput["permissionDecision"] != "ask" {
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
    - command:

        name: git

        semantic:

          verb: status
      test:
        allow:
          - "git status"
        pass:
          - "git diff"
    - command:

        name: git

        semantic:

          verb: diff
      test:
        allow:
          - "git diff"
        pass:
          - "git status"
    - command:

        name: git

        semantic:

          verb: log
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
    - command:

        name: rm
      test:
        deny:
          - "rm -rf /tmp/x"
        pass:
          - "git status"
  allow:
    - command:

        name: git

        semantic:

          verb: status
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
	ok, reasons := app.VerifyStatus(report, buildinfo.Info{Version: "dev", Module: "github.com/tasuku43/cc-bash-guard", VCSRevision: "abc123"}, "claude")
	if !ok || len(reasons) != 0 {
		t.Fatalf("ok=%v reasons=%v", ok, reasons)
	}
}

func TestRunVerifyHumanSuccessSummaryNoColorForBuffer(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        pass: ["git diff"]
test:
  - in: "git status"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"PASS verify", "config files:", "permission rules: 1", "tests: 1", "artifact:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
	if hasANSI(out) {
		t.Fatalf("stdout contains ANSI escapes: %q", out)
	}
}

func TestRunVerifyColorBehavior(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        pass: ["git diff"]
test:
  - in: "git status"
    decision: allow
`)
	t.Setenv("TERM", "xterm")
	t.Setenv("NO_COLOR", "")
	var colored bytes.Buffer
	code := Run([]string{"verify", "--color", "always"}, Streams{Stdout: &colored, Stderr: &bytes.Buffer{}}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s", code, colored.String())
	}
	if !hasANSI(colored.String()) {
		t.Fatalf("stdout missing ANSI escapes: %q", colored.String())
	}

	t.Setenv("NO_COLOR", "1")
	var noColor bytes.Buffer
	code = Run([]string{"verify", "--color", "always"}, Streams{Stdout: &noColor, Stderr: &bytes.Buffer{}}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s", code, noColor.String())
	}
	if hasANSI(noColor.String()) {
		t.Fatalf("NO_COLOR output contains ANSI escapes: %q", noColor.String())
	}

	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	var dumb bytes.Buffer
	code = Run([]string{"verify", "--color", "always"}, Streams{Stdout: &dumb, Stderr: &bytes.Buffer{}}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s", code, dumb.String())
	}
	if hasANSI(dumb.String()) {
		t.Fatalf("TERM=dumb output contains ANSI escapes: %q", dumb.String())
	}
}

func TestRunVerifyE2EFailureDiagnosticsIncludeSourceAndMatchedRule(t *testing.T) {
	cwd := t.TempDir()
	writeProjectConfig(t, cwd, `permission:
  deny:
    - name: git force push
      command:
        name: git
        semantic:
          verb: push
          force: true
      message: force push is blocked
      test:
        deny: ["git push --force origin main"]
        pass: ["git status"]
test:
  - in: "git push --force origin main"
    decision: ask
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: cwd, Home: t.TempDir()})
	if code == 0 {
		t.Fatalf("code = 0 stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"FAIL verify",
		"E2E test failed",
		".cc-bash-guard/cc-bash-guard.yaml test[0]",
		"input: git push --force origin main",
		"expected: ask",
		"actual: deny",
		"cc-bash-guard: deny",
		"Claude settings: abstain",
		"matched rule:",
		"permission.deny[0] \"git force push\"",
		"message: force push is blocked",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestRunVerifySemanticDiagnostics(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "unsupported field",
			body: `permission:
  deny:
    - name: bad git field
      command:
        name: git
        semantic:
          namespace: prod
      test:
        deny: ["git push"]
        pass: ["git status"]
`,
			want: []string{"Unsupported semantic field", "command: git", "field: command.semantic.namespace", "Supported fields for git:", "cc-bash-guard help semantic git"},
		},
		{
			name: "unsupported type",
			body: `permission:
  deny:
    - name: bad git type
      command:
        name: git
        semantic:
          force: "yes"
      test:
        deny: ["git push --force"]
        pass: ["git status"]
`,
			want: []string{"Invalid semantic field type", "command: git", "field: permission.deny[0].command.semantic.force", "expected: bool", "actual: string", "cc-bash-guard help semantic git"},
		},
		{
			name: "schema unavailable",
			body: `permission:
  ask:
    - name: helm semantic
      command:
        name: helm
        semantic:
          namespace: prod
      test:
        ask: ["helm list"]
        pass: ["git status"]
`,
			want: []string{"Semantic schema unavailable", "command: helm", "field: command.semantic", "Use patterns for commands without semantic support"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			writeUserConfig(t, home, tt.body)
			var stdout, stderr bytes.Buffer
			code := Run([]string{"verify"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: t.TempDir(), Home: home})
			if code == 0 {
				t.Fatalf("code = 0 stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
			out := stdout.String()
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Fatalf("stdout missing %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestRunVerifyJSONFailureOutput(t *testing.T) {
	cwd := t.TempDir()
	writeProjectConfig(t, cwd, `permission:
  deny:
    - name: git force push
      command:
        name: git
        semantic:
          verb: push
          force: true
      message: force push is blocked
      test:
        deny: ["git push --force origin main"]
        pass: ["git status"]
test:
  - in: "git push --force origin main"
    decision: ask
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify", "--format", "json", "--color", "always"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: cwd, Home: t.TempDir()})
	if code == 0 {
		t.Fatalf("code = 0 stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if hasANSI(stdout.String()) {
		t.Fatalf("JSON contains ANSI escapes: %q", stdout.String())
	}
	var payload struct {
		OK      bool `json:"ok"`
		Summary struct {
			ConfigFiles     int `json:"config_files"`
			PermissionRules int `json:"permission_rules"`
			Tests           int `json:"tests"`
			Failures        int `json:"failures"`
			Warnings        int `json:"warnings"`
		} `json:"summary"`
		Failures []struct {
			Kind     string `json:"kind"`
			Input    string `json:"input"`
			Expected string `json:"expected"`
			Actual   string `json:"actual"`
			Source   struct {
				File    string `json:"file"`
				Section string `json:"section"`
				Index   int    `json:"index"`
			} `json:"source"`
			MatchedRule struct {
				File   string `json:"file"`
				Bucket string `json:"bucket"`
				Index  int    `json:"index"`
				Name   string `json:"name"`
			} `json:"matched_rule"`
		} `json:"failures"`
		Warnings []any `json:"warnings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	if payload.OK || payload.Summary.PermissionRules != 1 || payload.Summary.Tests != 1 || len(payload.Failures) == 0 {
		t.Fatalf("payload=%+v", payload)
	}
	f := payload.Failures[0]
	if f.Kind != "e2e_test_failed" || f.Expected != "ask" || f.Actual != "deny" || f.MatchedRule.Name != "git force push" || f.MatchedRule.Bucket != "deny" {
		t.Fatalf("failure=%+v", f)
	}
}

func TestRunVerifyDuplicateRuleNameWarningJSON(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: git read-only
      command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        pass: ["git diff"]
    - name: git read-only
      command:
        name: git
        semantic:
          verb: diff
      test:
        allow: ["git diff"]
        pass: ["git status"]
test:
  - in: "git status"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify", "--format", "json"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload struct {
		OK       bool `json:"ok"`
		Warnings []struct {
			Kind   string           `json:"kind"`
			First  app.VerifySource `json:"first"`
			Second app.VerifySource `json:"second"`
		} `json:"warnings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	if !payload.OK || len(payload.Warnings) == 0 || payload.Warnings[0].Kind != "duplicate_rule_name" {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestRunVerifyBroadAllowPatternWarningHuman(t *testing.T) {
	cwd := t.TempDir()
	writeProjectConfig(t, cwd, `permission:
  allow:
    - name: broad aws fallback
      patterns:
        - "^aws"
      test:
        allow: ["aws sts get-caller-identity"]
        pass: ["git status"]
test:
  - in: "aws sts get-caller-identity"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: cwd, Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"PASS verify",
		"WARN warnings: 1",
		"Broad allow pattern",
		`pattern: ^aws`,
		`.cc-bash-guard/cc-bash-guard.yaml permission.allow[0] "broad aws fallback"`,
		"allows the aws command namespace without a meaningful subcommand boundary",
		"Prefer permission.allow.command with command.name: aws",
		"Safer alternative:",
		"command.semantic for aws",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestRunVerifySafeAnchoredReadOnlyPatternDoesNotWarn(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  allow:
    - name: terraform read-only fallback
      patterns:
        - '^[[:space:]]*terraform\s+(plan|show)(\s|$)[^;&|<>]*$'
      test:
        allow: ["terraform plan"]
        pass: ["terraform apply -auto-approve"]
test:
  - in: "terraform plan"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify", "--format", "json"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload struct {
		Summary struct {
			Warnings int `json:"warnings"`
		} `json:"summary"`
		Warnings []app.VerifyDiagnostic `json:"warnings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	if payload.Summary.Warnings != 0 || len(payload.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", payload)
	}
}

func TestRunVerifyBroadDenyAndAskPatternsDoNotWarn(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  deny:
    - name: deny any aws fallback
      patterns:
        - "^aws"
      test:
        deny: ["aws s3 rm s3://bucket/key"]
        pass: ["git status"]
  ask:
    - name: ask any kubectl fallback
      patterns:
        - "^kubectl"
      test:
        ask: ["kubectl delete pod x"]
        pass: ["git status"]
test:
  - in: "aws s3 rm s3://bucket/key"
    decision: deny
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify", "--format", "json"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: t.TempDir(), Home: home})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload struct {
		Summary struct {
			Warnings int `json:"warnings"`
		} `json:"summary"`
		Warnings []app.VerifyDiagnostic `json:"warnings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	if payload.Summary.Warnings != 0 || len(payload.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", payload)
	}
}

func TestRunVerifyBroadAllowPatternWarningJSONShape(t *testing.T) {
	cwd := t.TempDir()
	writeProjectConfig(t, cwd, `permission:
  allow:
    - name: broad terraform fallback
      patterns:
        - "^terraform\\s+.*"
      test:
        allow: ["terraform plan"]
        pass: ["git status"]
test:
  - in: "terraform plan"
    decision: allow
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify", "--format", "json"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: cwd, Home: t.TempDir()})
	if code != 0 {
		t.Fatalf("code = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload struct {
		OK      bool `json:"ok"`
		Summary struct {
			Warnings int `json:"warnings"`
		} `json:"summary"`
		Warnings []struct {
			Kind             string           `json:"kind"`
			Title            string           `json:"title"`
			Source           app.VerifySource `json:"source"`
			Pattern          string           `json:"pattern"`
			Message          string           `json:"message"`
			Reason           string           `json:"reason"`
			Hint             string           `json:"hint"`
			SaferAlternative string           `json:"safer_alternative"`
		} `json:"warnings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	if !payload.OK || payload.Summary.Warnings != 1 || len(payload.Warnings) != 1 {
		t.Fatalf("payload=%+v", payload)
	}
	warning := payload.Warnings[0]
	if warning.Kind != "broad_allow_pattern" ||
		warning.Title != "Broad allow pattern" ||
		warning.Pattern != `^terraform\s+.*` ||
		warning.Source.Section != "permission" ||
		warning.Source.Bucket != "allow" ||
		warning.Source.Index != 0 ||
		warning.Source.Name != "broad terraform fallback" ||
		!strings.Contains(warning.Source.File, ".cc-bash-guard/cc-bash-guard.yaml") ||
		!strings.Contains(warning.Message, "allow.patterns rule is broad") ||
		!strings.Contains(warning.Reason, "terraform command namespace") ||
		!strings.Contains(warning.Reason, "shell metacharacters") ||
		!strings.Contains(warning.Hint, "narrower regex") ||
		warning.SaferAlternative == "" {
		t.Fatalf("warning=%+v", warning)
	}
}

func TestRunVerifyAllFailuresJSON(t *testing.T) {
	home := t.TempDir()
	writeUserConfig(t, home, `permission:
  deny:
    - name: deny rm
      command:
        name: rm
      test:
        deny: ["rm -rf /tmp/x"]
        pass: ["git status"]
test:
  - in: "rm -rf /tmp/x"
    decision: ask
  - in: "rm -rf /tmp/y"
    decision: ask
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify", "--format", "json", "--all-failures"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: t.TempDir(), Home: home})
	if code == 0 {
		t.Fatalf("code = 0 stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	var payload struct {
		Failures []struct {
			Kind string `json:"kind"`
		} `json:"failures"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("json error: %v stdout=%s", err, stdout.String())
	}
	count := 0
	for _, failure := range payload.Failures {
		if failure.Kind == "e2e_test_failed" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("e2e failure count = %d payload=%+v", count, payload)
	}
}

func TestRunVerifyIncludedSourceMetadata(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(cwd, ".cc-bash-guard")
	policyPath := filepath.Join(configDir, "policies", "git.yml")
	testPath := filepath.Join(configDir, "tests", "git.yml")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(testPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`permission:
  deny:
    - name: git force push
      command:
        name: git
        semantic:
          verb: push
          force: true
      test:
        deny: ["git push --force origin main"]
        pass: ["git status"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(testPath, []byte(`test:
  - in: "git push --force origin main"
    decision: ask
`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProjectConfig(t, cwd, `include:
  - ./policies/git.yml
  - ./tests/git.yml
`)

	var stdout, stderr bytes.Buffer
	code := Run([]string{"verify"}, Streams{Stdout: &stdout, Stderr: &stderr}, Env{Cwd: cwd, Home: t.TempDir()})
	if code == 0 {
		t.Fatalf("code = 0 stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		".cc-bash-guard/tests/git.yml test[0]",
		".cc-bash-guard/policies/git.yml permission.deny[0] \"git force push\"",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
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
	data, err := os.ReadFile(filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "permission:") {
		t.Fatalf("config=%q", string(data))
	}
}

func hasANSI(s string) bool {
	return strings.Contains(s, "\x1b[")
}

func writeUserConfig(t *testing.T, home string, body string) {
	t.Helper()
	path := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
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
	path := filepath.Join(cwd, ".cc-bash-guard", "cc-bash-guard.yaml")
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
