package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
)

func TestLoadEffectiveUsesUserConfig(t *testing.T) {
	home := t.TempDir()
	userPath := filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `rewrite:
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
`
	if err := os.WriteFile(userPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffective(home, "")
	if len(loaded.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", loaded.Errors)
	}
	if len(loaded.Pipeline.Rewrite) != 1 || len(loaded.Pipeline.Permission.Allow) != 1 {
		t.Fatalf("pipeline = %#v", loaded.Pipeline)
	}
}

func TestLoadEffectiveForToolMergesUserAndProjectConfig(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	userPath := filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(`rewrite:
  - match:
      command: aws
    move_flag_to_env:
      flag: "--profile"
      env: "AWS_PROFILE"
    test:
      - in: "aws --profile dev sts get-caller-identity"
        out: "AWS_PROFILE=dev aws sts get-caller-identity"
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
`), 0o644); err != nil {
		t.Fatal(err)
	}

	localPath := filepath.Join(project, ".cc-bash-proxy", "cc-bash-proxy.yaml")
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, []byte(`permission:
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
`), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffectiveForTool(project, home, "", "claude")
	if len(loaded.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", loaded.Errors)
	}
	if len(loaded.Pipeline.Rewrite) != 1 {
		t.Fatalf("rewrite = %#v", loaded.Pipeline.Rewrite)
	}
	if len(loaded.Pipeline.Permission.Allow) != 1 || len(loaded.Pipeline.Permission.Deny) != 1 {
		t.Fatalf("permission = %#v", loaded.Pipeline.Permission)
	}
	if len(loaded.Pipeline.Test) != 2 {
		t.Fatalf("tests = %#v", loaded.Pipeline.Test)
	}
	if got := loaded.Pipeline.Permission.Allow[0].Source; got.Layer != LayerUser || got.Path != userPath {
		t.Fatalf("allow source = %+v", got)
	}
	if got := loaded.Pipeline.Permission.Deny[0].Source; got.Layer != LayerProject || got.Path != localPath {
		t.Fatalf("deny source = %+v", got)
	}
}

func TestLoadEffectiveForToolProjectOverridesClaudeMergeMode(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(`claude_permission_merge_mode: strict
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
`), 0o644); err != nil {
		t.Fatal(err)
	}
	localPath := filepath.Join(project, ".cc-bash-proxy", "cc-bash-proxy.yml")
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, []byte(`claude_permission_merge_mode: cc_bash_proxy_authoritative
permission:
  ask:
    - match:
        command: git
        subcommand: push
      test:
        ask:
          - "git push"
        pass:
          - "git status"
test:
  - in: "git push"
    decision: ask
`), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffectiveForTool(project, home, "", "claude")
	if len(loaded.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", loaded.Errors)
	}
	if loaded.Pipeline.ClaudePermissionMergeMode != "cc_bash_proxy_authoritative" {
		t.Fatalf("mode=%q", loaded.Pipeline.ClaudePermissionMergeMode)
	}
}

func TestLoadEffectiveRejectsPermissionCompositionConfig(t *testing.T) {
	home := t.TempDir()
	userPath := filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(`permission:
  composition:
    allow:
      - pipeline
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
`), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffective(home, "")
	if len(loaded.Errors) == 0 {
		t.Fatal("expected permission.composition to be rejected")
	}
	if !strings.Contains(loaded.Errors[0].Error(), "field composition not found") {
		t.Fatalf("error = %v", loaded.Errors[0])
	}
}

func TestLoadFileForEvalIfPresentSupportsStripCommandPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-proxy.yml")
	cacheDir := t.TempDir()
	body := `rewrite:
  - match:
      command_is_absolute_path: true
    strip_command_path: true
    test:
      - in: "/bin/ls -R foo"
        out: "ls -R foo"
      - pass: "ls -R foo"
permission:
  allow:
    - match:
        command: ls
      test:
        allow:
          - "ls -R foo"
        pass:
          - "pwd"
test:
  - in: "/bin/ls -R foo"
    rewritten: "ls -R foo"
    decision: allow
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, err := LoadFileForEvalIfPresent(Source{Layer: LayerUser, Path: path}, cacheDir)
	if err != nil {
		t.Fatalf("LoadFileForEvalIfPresent() error = %v", err)
	}
	decision, err := policy.Evaluate(pipeline, "/bin/ls -R foo")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Outcome != "allow" || decision.Command != "ls -R foo" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestVerifyFileWritesVerifiedArtifactAndHookLoadsIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-proxy.yml")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	body := `permission:
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
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, err := VerifyFile(Source{Layer: LayerUser, Path: path}, cacheDir, "vtest")
	if err != nil {
		t.Fatalf("VerifyFile() error = %v", err)
	}
	if len(pipeline.Permission.Allow) != 1 {
		t.Fatalf("pipeline = %#v", pipeline)
	}

	files, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	if fi, err := os.Stat(cacheDir); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir mode = %o, want 0700", fi.Mode().Perm())
	}
	cachePath := filepath.Join(cacheDir, files[0].Name())
	if fi, err := os.Stat(cachePath); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode = %o, want 0600", fi.Mode().Perm())
	}
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	var cache struct {
		CmdproxyVersion            string `json:"cmdproxy_version"`
		EvaluationSemanticsVersion int    `json:"evaluation_semantics_version"`
		VerifiedAt                 string `json:"verified_at"`
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		t.Fatal(err)
	}
	if cache.CmdproxyVersion != "vtest" || cache.VerifiedAt == "" {
		t.Fatalf("cache = %+v", cache)
	}
	if cache.EvaluationSemanticsVersion != EvaluationSemanticsVersion {
		t.Fatalf("evaluation semantics version = %d, want %d", cache.EvaluationSemanticsVersion, EvaluationSemanticsVersion)
	}

	hookPipeline, err := LoadVerifiedFileForHook(Source{Layer: LayerUser, Path: path}, []string{cacheDir})
	if err != nil {
		t.Fatalf("LoadVerifiedFileForHook() error = %v", err)
	}
	if len(hookPipeline.Permission.Allow) != 1 {
		t.Fatalf("hookPipeline = %#v", hookPipeline)
	}
}

func TestHookCacheDirsUseUserCacheOnly(t *testing.T) {
	home := t.TempDir()
	xdg := filepath.Join(t.TempDir(), "xdg-cache")

	got := HookCacheDirs(home, xdg)
	want := []string{
		filepath.Join(xdg, "cc-bash-proxy"),
		filepath.Join(home, ".cache", "cc-bash-proxy"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HookCacheDirs() = %#v, want %#v", got, want)
	}

	got = HookCacheDirs(home, "")
	want = []string{
		filepath.Join(home, ".cache", "cc-bash-proxy"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HookCacheDirs() without xdg = %#v, want %#v", got, want)
	}
}

func TestLoadVerifiedFileForHookRejectsMismatchedEvaluationSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-proxy.yml")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	body := `permission:
  allow:
    - match:
        command: git
      test:
        allow: ["git status"]
        pass: ["pwd"]
test:
  - in: "git status"
    decision: allow
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(Source{Layer: LayerUser, Path: path}, cacheDir, "vtest"); err != nil {
		t.Fatalf("VerifyFile() error = %v", err)
	}
	cachePath := singleCachePath(t, cacheDir)
	removeJSONField(t, cachePath, "evaluation_semantics_version")

	_, err := LoadVerifiedFileForHook(Source{Layer: LayerUser, Path: path}, []string{cacheDir})
	if err == nil || !strings.Contains(err.Error(), "evaluation semantics version 0") || !strings.Contains(err.Error(), "run cc-bash-proxy verify") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadVerifiedFileForHookRejectsUnsafeCachePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-proxy.yml")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	body := `permission:
  allow:
    - match:
        command: git
      test:
        allow: ["git status"]
        pass: ["pwd"]
test:
  - in: "git status"
    decision: allow
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(Source{Layer: LayerUser, Path: path}, cacheDir, "vtest"); err != nil {
		t.Fatalf("VerifyFile() error = %v", err)
	}

	files, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	cachePath := filepath.Join(cacheDir, files[0].Name())
	if err := os.Chmod(cachePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifiedFileForHook(Source{Layer: LayerUser, Path: path}, []string{cacheDir}); err == nil {
		t.Fatal("expected unsafe cache file permissions to be rejected")
	}

	if err := os.Chmod(cachePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cacheDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifiedFileForHook(Source{Layer: LayerUser, Path: path}, []string{cacheDir}); err == nil {
		t.Fatal("expected unsafe cache dir permissions to be rejected")
	}
}

func TestVerifyFileSupportsCompoundCommandAsExplicitAskE2E(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-proxy.yml")
	cacheDir := t.TempDir()
	body := `permission:
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
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, err := VerifyFile(Source{Layer: LayerUser, Path: path}, cacheDir, "vtest")
	if err != nil {
		t.Fatalf("VerifyFile() error = %v", err)
	}
	decision, err := policy.Evaluate(pipeline, "git status && rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Outcome != "ask" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestLoadVerifiedFileForHookFailsWhenArtifactMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-proxy.yml")
	body := `permission:
  allow:
    - match:
        command: git
      test:
        allow: ["git status"]
        pass: ["pwd"]
test:
  - in: "git status"
    decision: allow
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadVerifiedFileForHook(Source{Layer: LayerUser, Path: path}, []string{t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "run cc-bash-proxy verify") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyEffectiveToAllCachesIncludesToolSettingsFingerprint(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	cacheHome := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`permission:
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
    decision: allow
`), 0o644); err != nil {
		t.Fatal(err)
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"permissions":{"allow":["Bash(git status)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	pipeline, err := VerifyEffectiveToAllCaches(project, home, "", cacheHome, "claude", "vtest")
	if err != nil {
		t.Fatalf("VerifyEffectiveToAllCaches() error = %v", err)
	}
	if len(pipeline.Permission.Ask) != 1 {
		t.Fatalf("pipeline = %#v", pipeline)
	}
	data, err := os.ReadFile(singleCachePath(t, filepath.Join(cacheHome, "cc-bash-proxy")))
	if err != nil {
		t.Fatal(err)
	}
	var cache struct {
		EvaluationSemanticsVersion int `json:"evaluation_semantics_version"`
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		t.Fatal(err)
	}
	if cache.EvaluationSemanticsVersion != EvaluationSemanticsVersion {
		t.Fatalf("evaluation semantics version = %d, want %d", cache.EvaluationSemanticsVersion, EvaluationSemanticsVersion)
	}

	hookLoaded := LoadEffectiveForHookTool(project, home, "", cacheHome, "claude")
	if len(hookLoaded.Errors) != 0 {
		t.Fatalf("hook errors = %v", hookLoaded.Errors)
	}

	if err := os.WriteFile(settingsPath, []byte(`{"permissions":{"deny":["Bash(git status)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	hookLoaded = LoadEffectiveForHookTool(project, home, "", cacheHome, "claude")
	if len(hookLoaded.Errors) == 0 {
		t.Fatalf("expected settings fingerprint mismatch to invalidate artifact")
	}
}

func TestLoadEffectiveForHookToolRejectsMismatchedEvaluationSemantics(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	configPath := filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`permission:
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
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEffectiveToAllCaches(cwd, home, "", cacheHome, "claude", "vtest"); err != nil {
		t.Fatalf("VerifyEffectiveToAllCaches() error = %v", err)
	}
	cachePath := singleCachePath(t, filepath.Join(cacheHome, "cc-bash-proxy"))
	setJSONField(t, cachePath, "evaluation_semantics_version", float64(EvaluationSemanticsVersion+1))

	loaded := LoadEffectiveForHookTool(cwd, home, "", cacheHome, "claude")
	if len(loaded.Errors) == 0 {
		t.Fatal("expected incompatible artifact error")
	}
	msg := loaded.Errors[0].Error()
	if !strings.Contains(msg, "evaluation semantics version") || !strings.Contains(msg, "run cc-bash-proxy verify") {
		t.Fatalf("unexpected error: %v", loaded.Errors[0])
	}
}

func TestLoadFileIfPresentRejectsUnsupportedBuiltInRewriteContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-proxy.yml")
	body := `rewrite:
  - match:
      command: aws
    move_flag_to_env:
      flag: "--profile"
      env: "HOGE"
    test:
      - in: "aws --profile dev sts get-caller-identity"
        out: "HOGE=dev aws sts get-caller-identity"
      - pass: "aws sts get-caller-identity"
test:
  - in: "aws --profile dev sts get-caller-identity"
    decision: ask
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: path})
	if err == nil || !strings.Contains(err.Error(), "AWS_PROFILE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func singleCachePath(t *testing.T, dir string) string {
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

func removeJSONField(t *testing.T, path string, key string) {
	t.Helper()
	updateJSONFile(t, path, func(v map[string]any) {
		delete(v, key)
	})
}

func setJSONField(t *testing.T, path string, key string, value any) {
	t.Helper()
	updateJSONFile(t, path, func(v map[string]any) {
		v[key] = value
	})
}

func updateJSONFile(t *testing.T, path string, update func(map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	update(payload)
	data, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
