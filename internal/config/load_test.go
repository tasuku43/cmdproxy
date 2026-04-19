package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEffectiveUsesUserConfig(t *testing.T) {
	home := t.TempDir()
	userPath := filepath.Join(home, ".config", "cmdproxy", "cmdproxy.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `rules:
  - id: user-rule
    pattern: "^echo"
    reject:
      message: "user"
      test:
        expect: ["echo hi"]
        pass: ["git status"]
`
	if err := os.WriteFile(userPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffective(home, "")
	if len(loaded.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", loaded.Errors)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].ID != "user-rule" {
		t.Fatalf("rules = %#v", loaded.Rules)
	}
}

func TestLoadFileForEvalIfPresentSupportsRewriteDirective(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdproxy.yml")
	cachePath := filepath.Join(t.TempDir(), "hook-cache-v1.json")
	body := `rules:
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
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadFileForEvalIfPresent(Source{Layer: LayerUser, Path: path}, cachePath)
	if err != nil {
		t.Fatalf("LoadFileForEvalIfPresent() error = %v", err)
	}
	rewritten, ok := rules[0].RewriteCommand("bash -c 'git status'")
	if !ok || rewritten != "git status" {
		t.Fatalf("RewriteCommand() = %q ok=%v", rewritten, ok)
	}
}

func TestLoadFileForEvalIfPresentSupportsMoveFlagToEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdproxy.yml")
	cachePath := filepath.Join(t.TempDir(), "hook-cache-v1.json")
	body := `rules:
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
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadFileForEvalIfPresent(Source{Layer: LayerUser, Path: path}, cachePath)
	if err != nil {
		t.Fatalf("LoadFileForEvalIfPresent() error = %v", err)
	}
	rewritten, ok := rules[0].RewriteCommand("aws --profile read-only-profile s3 ls")
	if !ok || rewritten != "AWS_PROFILE=read-only-profile aws s3 ls" {
		t.Fatalf("RewriteCommand() = %q ok=%v", rewritten, ok)
	}
}

func TestLoadFileForEvalIfPresentSupportsMoveEnvToFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdproxy.yml")
	cachePath := filepath.Join(t.TempDir(), "hook-cache-v1.json")
	body := `rules:
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
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadFileForEvalIfPresent(Source{Layer: LayerUser, Path: path}, cachePath)
	if err != nil {
		t.Fatalf("LoadFileForEvalIfPresent() error = %v", err)
	}
	rewritten, ok := rules[0].RewriteCommand("AWS_PROFILE=read-only-profile aws s3 ls")
	if !ok || rewritten != "aws --profile read-only-profile s3 ls" {
		t.Fatalf("RewriteCommand() = %q ok=%v", rewritten, ok)
	}
}

func TestLoadFileForEvalIfPresentSupportsUnwrapWrapper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdproxy.yml")
	cachePath := filepath.Join(t.TempDir(), "hook-cache-v1.json")
	body := `rules:
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
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadFileForEvalIfPresent(Source{Layer: LayerUser, Path: path}, cachePath)
	if err != nil {
		t.Fatalf("LoadFileForEvalIfPresent() error = %v", err)
	}
	rewritten, ok := rules[0].RewriteCommand("env AWS_PROFILE=dev command exec aws s3 ls")
	if !ok || rewritten != "AWS_PROFILE=dev aws s3 ls" {
		t.Fatalf("RewriteCommand() = %q ok=%v", rewritten, ok)
	}
}

func TestLoadFileIfPresentRejectsPatternAndMatchTogether(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cmdproxy.yml")
	body := `rules:
  - id: bad-rule
    pattern: "^git"
    match:
      command: git
    reject:
      message: "bad"
      test:
        expect: ["git status"]
        pass: ["echo ok"]
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: path})
	if err == nil || !strings.Contains(err.Error(), "must not set both pattern and match") {
		t.Fatalf("unexpected error: %v", err)
	}
}
