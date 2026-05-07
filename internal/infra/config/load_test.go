package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
)

func TestLoadEffectiveUsesUserConfig(t *testing.T) {
	home := t.TempDir()
	userPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `permission:
  allow:
    - command:

        name: aws

        semantic:

          service: sts
          profile: dev
      test:
        allow:
          - "aws --profile dev sts get-caller-identity"
        abstain:
          - "aws --profile dev s3 ls"
test:
  - in: "aws --profile dev sts get-caller-identity"
    decision: allow
`
	if err := os.WriteFile(userPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffective(home, "")
	if len(loaded.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", loaded.Errors)
	}
	if len(loaded.Pipeline.Rewrite) != 0 || len(loaded.Pipeline.Permission.Allow) != 1 {
		t.Fatalf("pipeline = %#v", loaded.Pipeline)
	}
}

func TestLoadEffectiveForToolMergesUserAndProjectConfig(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	userPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(`permission:
  allow:
    - command:

        name: aws

        semantic:

          service: sts
          profile: dev
      test:
        allow:
          - "aws --profile dev sts get-caller-identity"
        abstain:
          - "aws --profile dev s3 ls"
test:
  - in: "aws --profile dev sts get-caller-identity"
    decision: allow
`), 0o644); err != nil {
		t.Fatal(err)
	}

	localPath := filepath.Join(project, ".cc-bash-guard", "cc-bash-guard.yaml")
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, []byte(`permission:
  deny:
    - patterns:

        - '^\s*git\s+push'
      message: "push blocked"
      test:
        deny:
          - "git push origin main"
        abstain:
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
	if len(loaded.Pipeline.Rewrite) != 0 {
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

func TestLoadEffectiveRejectsClaudePermissionMergeMode(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(`claude_permission_merge_mode: strict
permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
      test:
        allow:
          - "git status"
        abstain:
          - "git diff"
test:
  - in: "git status"
    decision: allow
`), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffectiveForTool(project, home, "", "claude")
	if len(loaded.Errors) == 0 {
		t.Fatal("expected error")
	}
	if !strings.Contains(loaded.Errors[0].Error(), "claude_permission_merge_mode is no longer supported; permission sources are merged using deny > ask > allow > abstain.") {
		t.Fatalf("error=%v", loaded.Errors[0])
	}
}

func TestLoadEffectiveRejectsPermissionCompositionConfig(t *testing.T) {
	home := t.TempDir()
	userPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(`permission:
  composition:
    allow:
      - pipeline
  allow:
    - command:

        name: git

        semantic:

          verb: status
      test:
        allow:
          - "git status"
        abstain:
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

func TestLoadEffectiveRejectsMalformedYAMLWithoutPanic(t *testing.T) {
	home := t.TempDir()
	userPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte("permission:\n  allow:\n    - command: ["), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffective(home, "")
	if len(loaded.Errors) == 0 {
		t.Fatal("expected invalid YAML error")
	}
	if !strings.Contains(loaded.Errors[0].Error(), "invalid") {
		t.Fatalf("error=%v, want actionable invalid config error", loaded.Errors[0])
	}
}

func TestLoadEffectiveRejectsUnknownFieldsWithKnownFields(t *testing.T) {
	home := t.TempDir()
	userPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, []byte(`permission:
  allow:
    - command:
        name: git
        pattern: status
test:
  - in: "git status"
    decision: allow
`), 0o644); err != nil {
		t.Fatal(err)
	}

	loaded := LoadEffective(home, "")
	if len(loaded.Errors) == 0 {
		t.Fatal("expected unknown field error")
	}
	if !strings.Contains(loaded.Errors[0].Error(), "field pattern not found") {
		t.Fatalf("error=%v, want KnownFields diagnostic", loaded.Errors[0])
	}
}

func TestLoadEffectiveRejectsInvalidGhSemanticYAML(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unsupported semantic field for gh",
			body: `permission:
  deny:
    - command:

        name: gh

        semantic:
          service: sts
      test:
        deny:
          - "gh api repos/OWNER/REPO"
        abstain:
          - "git status"
test:
  - in: "gh api repos/OWNER/REPO"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.service is not supported for command gh. Supported semantic fields for gh:",
		},
		{
			name: "unsupported bool type",
			body: `permission:
  deny:
    - command:

        name: gh

        semantic:
          paginate: "true"
test:
  - in: "gh api --paginate repos/OWNER/REPO"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.paginate must be bool, got string.",
		},
		{
			name: "nested semantic gh form",
			body: `permission:
  deny:
    - command:

        name: gh

        semantic:
          gh:
            area: api
test:
  - in: "gh api repos/OWNER/REPO"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.gh is not supported for command gh. Supported semantic fields for gh:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			userPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
			if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(userPath, []byte(tt.body), 0o644); err != nil {
				t.Fatal(err)
			}
			loaded := LoadEffective(home, "")
			if len(loaded.Errors) == 0 {
				t.Fatal("expected error")
			}
			if !strings.Contains(loaded.Errors[0].Error(), tt.want) {
				t.Fatalf("error=%v, want substring %q", loaded.Errors[0], tt.want)
			}
		})
	}
}

func TestLoadFileForEvalIfPresentSupportsAbsolutePathNormalization(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-guard.yml")
	cacheDir := t.TempDir()
	body := `permission:
  allow:
    - command:
        name: ls
      test:
        allow:
          - "/bin/ls -R foo"
        abstain:
          - "pwd"
test:
  - in: "/bin/ls -R foo"
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
	if decision.Outcome != "allow" || decision.Command != "/bin/ls -R foo" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestVerifyFileWritesVerifiedArtifactAndHookLoadsIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-guard.yml")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	body := `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
      test:
        allow:
          - "git status"
        abstain:
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

func TestVerifyFileRejectsInvalidSemanticSchema(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown semantic field",
			body: `permission:
  deny:
    - command:

        name: git
        semantic:
          namespace: prod
      test:
        deny: ["git push"]
        abstain: ["git status"]
test:
  - in: "git push"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.namespace is not supported for command git. Supported semantic fields for git:",
		},
		{
			name: "unknown command with semantic",
			body: `permission:
  ask:
    - command:
        name: unknown-tool
        semantic:
          verb: delete
      test:
        ask: ["unknown-tool delete prod"]
        abstain: ["unknown-tool list"]
test:
  - in: "unknown-tool delete prod"
    decision: ask
`,
			want: "permission.ask[0].command.semantic is not available for command unknown-tool. Use patterns, or add a semantic schema/parser for unknown-tool.",
		},
		{
			name: "unsupported semantic type",
			body: `permission:
  deny:
    - command:

        name: git
        semantic:
          force: "true"
      test:
        deny: ["git push --force origin main"]
        abstain: ["git status"]
test:
  - in: "git push --force origin main"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.force must be bool, got string.",
		},
		{
			name: "unsupported semantic list type",
			body: `permission:
  deny:
    - command:
        name: git
        semantic:
          verb_in: push
      test:
        deny: ["git push origin main"]
        abstain: ["git status"]
test:
  - in: "git push origin main"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.verb_in must be []string, got string.",
		},
		{
			name: "unsupported semantic string type",
			body: `permission:
  deny:
    - command:
        name: git
        semantic:
          verb: [push]
      test:
        deny: ["git push origin main"]
        abstain: ["git status"]
test:
  - in: "git push origin main"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.verb must be string, got [].",
		},
		{
			name: "unknown aws semantic field",
			body: `permission:
  deny:
    - command:

        name: aws

        semantic:
          namespace: prod
      test:
        deny: ["aws sts get-caller-identity"]
        abstain: ["aws s3 ls"]
test:
  - in: "aws sts get-caller-identity"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.namespace is not supported for command aws. Supported semantic fields for aws:",
		},
		{
			name: "unsupported aws semantic type",
			body: `permission:
  deny:
    - command:

        name: aws

        semantic:
          dry_run: "false"
      test:
        deny: ["aws ec2 terminate-instances --no-dry-run"]
        abstain: ["aws ec2 describe-instances"]
test:
  - in: "aws ec2 terminate-instances --no-dry-run"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.dry_run must be bool, got string.",
		},
		{
			name: "unknown gws semantic field",
			body: `permission:
  deny:
    - command:
        name: gws
        semantic:
          namespace: prod
      test:
        deny: ["gws drive files delete"]
        abstain: ["gws drive files list"]
test:
  - in: "gws drive files delete"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.namespace is not supported for command gws. Supported semantic fields for gws:",
		},
		{
			name: "unsupported gws semantic type",
			body: `permission:
  deny:
    - command:
        name: gws
        semantic:
          unmasked: "true"
      test:
        deny: ["gws auth export --unmasked"]
        abstain: ["gws auth login"]
test:
  - in: "gws auth export --unmasked"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.unmasked must be bool, got string.",
		},
		{
			name: "nested aws semantic key",
			body: `permission:
  deny:
    - command:

        name: aws

        semantic:
          aws:
            service: sts
      test:
        deny: ["aws sts get-caller-identity"]
        abstain: ["aws s3 ls"]
test:
  - in: "aws sts get-caller-identity"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.aws is not supported for command aws. Supported semantic fields for aws:",
		},
		{
			name: "unknown kubectl semantic field",
			body: `permission:
  deny:
    - command:

        name: kubectl

        semantic:
          service: s3
      test:
        deny: ["kubectl get pods"]
        abstain: ["kubectl describe pods"]
test:
  - in: "kubectl get pods"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.service is not supported for command kubectl. Supported semantic fields for kubectl:",
		},
		{
			name: "unsupported kubectl semantic type",
			body: `permission:
  deny:
    - command:

        name: kubectl

        semantic:
          all_namespaces: "true"
      test:
        deny: ["kubectl get pods -A"]
        abstain: ["kubectl get pods"]
test:
  - in: "kubectl get pods -A"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.all_namespaces must be bool, got string.",
		},
		{
			name: "nested kubectl semantic key",
			body: `permission:
  deny:
    - command:

        name: kubectl

        semantic:
          kubectl:
            verb: get
      test:
        deny: ["kubectl get pods"]
        abstain: ["kubectl describe pods"]
test:
  - in: "kubectl get pods"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.kubectl is not supported for command kubectl. Supported semantic fields for kubectl:",
		},
		{
			name: "unknown helmfile semantic field",
			body: `permission:
  deny:
    - command:

        name: helmfile

        semantic:
          service: sts
      test:
        deny: ["helmfile sync"]
        abstain: ["helmfile diff"]
test:
  - in: "helmfile sync"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.service is not supported for command helmfile. Supported semantic fields for helmfile:",
		},
		{
			name: "unsupported helmfile semantic type",
			body: `permission:
  deny:
    - command:

        name: helmfile

        semantic:
          interactive: "true"
      test:
        deny: ["helmfile destroy"]
        abstain: ["helmfile diff"]
test:
  - in: "helmfile destroy"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.interactive must be bool, got string.",
		},
		{
			name: "nested helmfile semantic key",
			body: `permission:
  deny:
    - command:

        name: helmfile

        semantic:
          helmfile:
            verb: sync
      test:
        deny: ["helmfile sync"]
        abstain: ["helmfile diff"]
test:
  - in: "helmfile sync"
    decision: deny
`,
			want: "permission.deny[0].command.semantic.helmfile is not supported for command helmfile. Supported semantic fields for helmfile:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "cc-bash-guard.yml")
			cacheDir := filepath.Join(t.TempDir(), "cache")
			if err := os.WriteFile(path, []byte(tt.body), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := VerifyFile(Source{Layer: LayerUser, Path: path}, cacheDir, "vtest")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("VerifyFile() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestVerifyFileAcceptsGwsSemanticSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-guard.yml")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	body := `permission:
  allow:
    - command:
        name: gws
        semantic:
          service: drive
          resource_path: [files]
          method: list
          params: true
      test:
        allow:
          - "gws drive files list --params '{\"pageSize\": 5}'"
        abstain:
          - "gws drive files delete --params '{\"fileId\":\"abc\"}'"
test:
  - in: "gws drive files list --params '{\"pageSize\": 5}'"
    decision: allow
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(Source{Layer: LayerUser, Path: path}, cacheDir, "vtest"); err != nil {
		t.Fatalf("VerifyFile() error = %v", err)
	}
}

func TestHookCacheDirsUseUserCacheOnly(t *testing.T) {
	home := t.TempDir()
	xdg := filepath.Join(t.TempDir(), "xdg-cache")

	got := HookCacheDirs(home, xdg)
	want := []string{
		filepath.Join(xdg, "cc-bash-guard"),
		filepath.Join(home, ".cache", "cc-bash-guard"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HookCacheDirs() = %#v, want %#v", got, want)
	}

	got = HookCacheDirs(home, "")
	want = []string{
		filepath.Join(home, ".cache", "cc-bash-guard"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HookCacheDirs() without xdg = %#v, want %#v", got, want)
	}
}

func TestLoadVerifiedFileForHookRejectsMismatchedEvaluationSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-guard.yml")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	body := `permission:
  allow:
    - command:

        name: git
      test:
        allow: ["git status"]
        abstain: ["pwd"]
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
	if err == nil || !strings.Contains(err.Error(), "evaluation semantics version 0") || !strings.Contains(err.Error(), "run cc-bash-guard verify") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadVerifiedFileForHookRejectsUnsafeCachePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-guard.yml")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	body := `permission:
  allow:
    - command:

        name: git
      test:
        allow: ["git status"]
        abstain: ["pwd"]
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
	path := filepath.Join(dir, "cc-bash-guard.yml")
	cacheDir := t.TempDir()
	body := `permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
      test:
        allow:
          - "git status"
        abstain:
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
	path := filepath.Join(dir, "cc-bash-guard.yml")
	body := `permission:
  allow:
    - command:

        name: git
      test:
        allow: ["git status"]
        abstain: ["pwd"]
test:
  - in: "git status"
    decision: allow
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadVerifiedFileForHook(Source{Layer: LayerUser, Path: path}, []string{t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "run cc-bash-guard verify") {
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

	configPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`permission:
  ask:
    - command:

        name: git

        semantic:

          verb: status
      test:
        ask:
          - "git status"
        abstain:
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
	data, err := os.ReadFile(singleCachePath(t, filepath.Join(cacheHome, "cc-bash-guard")))
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

	if err := os.WriteFile(settingsPath, []byte(`{"permissions":{"allow":["Bash(git status)"]},"theme":"dark"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	hookLoaded = LoadEffectiveForHookTool(project, home, "", cacheHome, "claude")
	if len(hookLoaded.Errors) != 0 {
		t.Fatalf("unrelated settings changes should not invalidate artifact: %v", hookLoaded.Errors)
	}

	if err := os.WriteFile(settingsPath, []byte(`{"permissions":{"allow":["Bash(git status)"],"extra":["Bash(git diff)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	hookLoaded = LoadEffectiveForHookTool(project, home, "", cacheHome, "claude")
	if len(hookLoaded.Errors) != 0 {
		t.Fatalf("irrelevant permission keys should not invalidate artifact: %v", hookLoaded.Errors)
	}

	if err := os.WriteFile(settingsPath, []byte(`{"permissions":{"deny":["Bash(git status)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	hookLoaded = LoadEffectiveForHookTool(project, home, "", cacheHome, "claude")
	if len(hookLoaded.Errors) == 0 {
		t.Fatalf("expected settings fingerprint mismatch to invalidate artifact")
	}
}

func TestLoadEffectiveForHookToolRejectsChangedIncludedFile(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	configPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	includePath := filepath.Join(home, ".config", "cc-bash-guard", "policies", "git.yml")
	writeFile(t, includePath, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	writeFile(t, configPath, `include:
  - ./policies/git.yml
`)
	if _, err := VerifyEffectiveToAllCaches(cwd, home, "", cacheHome, "claude", "vtest"); err != nil {
		t.Fatalf("VerifyEffectiveToAllCaches() error = %v", err)
	}
	loaded := LoadEffectiveForHookTool(cwd, home, "", cacheHome, "claude")
	if len(loaded.Errors) != 0 {
		t.Fatalf("hook errors before include change = %v", loaded.Errors)
	}

	writeFile(t, includePath, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: diff
      test:
        allow: ["git diff"]
        abstain: ["git status"]
`)
	loaded = LoadEffectiveForHookTool(cwd, home, "", cacheHome, "claude")
	if len(loaded.Errors) == 0 {
		t.Fatal("expected changed included file to invalidate effective artifact")
	}
	if !strings.Contains(loaded.Errors[0].Error(), "changed since last verify") {
		t.Fatalf("unexpected error: %v", loaded.Errors[0])
	}
	if !strings.Contains(loaded.Errors[0].Error(), "config changed: user:"+includePath) {
		t.Fatalf("expected changed config fingerprint input, got: %v", loaded.Errors[0])
	}
	if !strings.Contains(loaded.Errors[0].Error(), "binary build info") {
		t.Fatalf("expected binary build info hint, got: %v", loaded.Errors[0])
	}
}

func TestVerifyEffectiveStoresFingerprintInputs(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	configPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	writeFile(t, configPath, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	if _, err := VerifyEffectiveToAllCaches(cwd, home, "", cacheHome, "claude", "vtest"); err != nil {
		t.Fatalf("VerifyEffectiveToAllCaches() error = %v", err)
	}
	data, err := os.ReadFile(singleCachePath(t, filepath.Join(cacheHome, "cc-bash-guard")))
	if err != nil {
		t.Fatal(err)
	}
	var cache struct {
		FingerprintInputs []FingerprintInput `json:"fingerprint_inputs"`
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		t.Fatal(err)
	}
	for _, want := range []FingerprintInput{
		{Kind: "tool", Name: "tool", Value: "claude"},
		{Kind: "config", Name: "user:" + configPath},
		{Kind: "binary", Name: "vcs.modified"},
	} {
		if !hasFingerprintInput(cache.FingerprintInputs, want) {
			t.Fatalf("missing fingerprint input %+v in %+v", want, cache.FingerprintInputs)
		}
	}
}

func TestResolveEffectiveInputsSkipsMissingProjectConfigInFingerprint(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	writeFile(t, configPath, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	missingProjectConfig := filepath.Join(cwd, ".cc-bash-guard", "cc-bash-guard.yml")

	inputs := ResolveEffectiveInputs(cwd, home, "", "claude")
	for _, src := range inputs.ConfigFiles {
		if src.Path == missingProjectConfig {
			t.Fatalf("missing project config included in config files: %+v", inputs.ConfigFiles)
		}
	}
	for _, input := range inputs.Inputs {
		if strings.Contains(input.Name, missingProjectConfig) {
			t.Fatalf("missing project config included in fingerprint inputs: %+v", inputs.Inputs)
		}
	}
	if !hasFingerprintInput(inputs.Inputs, FingerprintInput{Kind: "config", Name: "user:" + configPath}) {
		t.Fatalf("user config missing from fingerprint inputs: %+v", inputs.Inputs)
	}
}

func TestVerifiedEffectiveArtifactIgnoresMissingProjectConfigAfterVerify(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	writeFile(t, configPath, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)

	if _, err := VerifyEffectiveToAllCaches(cwd, home, "", cacheHome, "claude", "vtest"); err != nil {
		t.Fatalf("VerifyEffectiveToAllCaches() error = %v", err)
	}
	loaded := LoadEffectiveForHookTool(cwd, home, "", cacheHome, "claude")
	if len(loaded.Errors) != 0 {
		t.Fatalf("hook errors after verify = %v", loaded.Errors)
	}
}

func TestLoadEffectiveForHookToolRejectsMismatchedEvaluationSemantics(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	configPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`permission:
  allow:
    - command:

        name: git

        semantic:

          verb: status
      test:
        allow:
          - "git status"
        abstain:
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
	cachePath := singleCachePath(t, filepath.Join(cacheHome, "cc-bash-guard"))
	setJSONField(t, cachePath, "evaluation_semantics_version", float64(EvaluationSemanticsVersion+1))

	loaded := LoadEffectiveForHookTool(cwd, home, "", cacheHome, "claude")
	if len(loaded.Errors) == 0 {
		t.Fatal("expected incompatible artifact error")
	}
	msg := loaded.Errors[0].Error()
	if !strings.Contains(msg, "evaluation semantics version") || !strings.Contains(msg, "run cc-bash-guard verify") {
		t.Fatalf("unexpected error: %v", loaded.Errors[0])
	}
}

func TestLoadFileIfPresentRejectsUnsupportedBuiltInRewriteContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cc-bash-guard.yml")
	body := `rewrite:
  - match:
      command: aws
    move_flag_to_env:
      flag: "--profile"
      env: "HOGE"
    test:
      - in: "aws --profile dev sts get-caller-identity"
        out: "HOGE=dev aws sts get-caller-identity"
      - abstain: "aws sts get-caller-identity"
test:
  - in: "aws --profile dev sts get-caller-identity"
    decision: ask
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: path})
	if err == nil || !strings.Contains(err.Error(), "top-level rewrite is no longer supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadFileIfPresentSupportsBasicInclude(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "cc-bash-guard.yml")
	writeFile(t, filepath.Join(dir, "git.yml"), `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	writeFile(t, root, `include:
  - ./git.yml
`)

	pipeline, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: root})
	if err != nil {
		t.Fatalf("LoadFileIfPresent() error = %v", err)
	}
	decision, err := policy.Evaluate(pipeline, "git status")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Outcome != "allow" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestLoadFileIfPresentMergesIncludeThenCurrentFile(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "cc-bash-guard.yml")
	writeFile(t, filepath.Join(dir, "git.yml"), `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	writeFile(t, root, `include:
  - ./git.yml
permission:
  deny:
    - name: git force push
      command:
        name: git
        semantic:
          verb: push
          force: true
      test:
        deny: ["git push --force origin main"]
        abstain: ["git status"]
`)

	pipeline, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: root})
	if err != nil {
		t.Fatalf("LoadFileIfPresent() error = %v", err)
	}
	if len(pipeline.Permission.Allow) != 1 || len(pipeline.Permission.Deny) != 1 {
		t.Fatalf("permission = %#v", pipeline.Permission)
	}
	if got := pipeline.Permission.Allow[0].Source.Path; got != filepath.Join(dir, "git.yml") {
		t.Fatalf("included source = %q", got)
	}
	assertDecision(t, pipeline, "git status", "allow")
	assertDecision(t, pipeline, "git push --force origin main", "deny")
}

func TestLoadFileIfPresentAppliesRootToleratedRedirectsToIncludedAllowRules(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "cc-bash-guard.yml")
	writeFile(t, filepath.Join(dir, "coreutils.yml"), `permission:
  allow:
    - name: ls
      command:
        name: ls
      test:
        allow: ["ls"]
        abstain: ["pwd"]
`)
	writeFile(t, root, `include:
  - ./coreutils.yml
permission:
  tolerated_redirects:
    only:
      - stderr_to_devnull
    scope:
      - sequence
test:
  - in: "ls argocd-helmfile/ 2>/dev/null"
    decision: allow
`)

	pipeline, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: root})
	if err != nil {
		t.Fatalf("LoadFileIfPresent() error = %v", err)
	}
	if got := pipeline.Permission.ToleratedRedirects.Only; !reflect.DeepEqual(got, []string{"stderr_to_devnull"}) {
		t.Fatalf("tolerated redirects = %#v", got)
	}
	if got := pipeline.Permission.ToleratedRedirects.Scope; !reflect.DeepEqual(got, []string{"sequence"}) {
		t.Fatalf("tolerated redirect scope = %#v", got)
	}
	assertDecision(t, pipeline, "ls argocd-helmfile/ 2>/dev/null", "allow")
}

func TestLoadEffectiveWithSourcesAppliesGlobalToleratedRedirectsAcrossSources(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.yml")
	second := filepath.Join(dir, "second.yml")
	writeFile(t, first, `permission:
  allow:
    - name: ls
      command:
        name: ls
      test:
        allow: ["ls"]
        abstain: ["pwd"]
`)
	writeFile(t, second, `permission:
  tolerated_redirects:
    only:
      - stderr_to_devnull
    scope:
      - sequence
`)

	loaded := loadEffectiveWithSources([]Source{
		{Layer: LayerUser, Path: first},
		{Layer: LayerProject, Path: second},
	}, LoadFileIfPresent)
	if len(loaded.Errors) > 0 {
		t.Fatalf("loadEffectiveWithSources() errors = %v", loaded.Errors)
	}
	if got := loaded.Pipeline.Permission.ToleratedRedirects.Scope; !reflect.DeepEqual(got, []string{"sequence"}) {
		t.Fatalf("tolerated redirect scope = %#v", got)
	}
	assertDecision(t, loaded.Pipeline, "ls argocd-helmfile/ 2>/dev/null", "allow")
}

func TestLoadFileIfPresentPreservesIncludeOrder(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "cc-bash-guard.yml")
	writeFile(t, filepath.Join(dir, "first.yml"), `permission:
  ask:
    - name: first
      patterns: ["^one$"]
      test:
        ask: ["one"]
        abstain: ["two"]
`)
	writeFile(t, filepath.Join(dir, "second.yml"), `permission:
  ask:
    - name: second
      patterns: ["^two$"]
      test:
        ask: ["two"]
        abstain: ["one"]
`)
	writeFile(t, root, `include:
  - ./first.yml
  - ./second.yml
permission:
  ask:
    - name: current
      patterns: ["^three$"]
      test:
        ask: ["three"]
        abstain: ["one"]
`)

	pipeline, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: root})
	if err != nil {
		t.Fatalf("LoadFileIfPresent() error = %v", err)
	}
	got := []string{pipeline.Permission.Ask[0].Name, pipeline.Permission.Ask[1].Name, pipeline.Permission.Ask[2].Name}
	want := []string{"first", "second", "current"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %#v, want %#v", got, want)
	}
}

func TestLoadFileIfPresentSupportsNestedIncludeRelativeToIncludingFile(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "cc-bash-guard.yml")
	policyDir := filepath.Join(dir, "policies")
	writeFile(t, filepath.Join(policyDir, "git.yml"), `permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	writeFile(t, filepath.Join(policyDir, "base.yml"), `include:
  - ./git.yml
`)
	writeFile(t, root, `include:
  - ./policies/base.yml
`)

	pipeline, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: root})
	if err != nil {
		t.Fatalf("LoadFileIfPresent() error = %v", err)
	}
	assertDecision(t, pipeline, "git status", "allow")
}

func TestLoadFileIfPresentRejectsIncludeCycle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yml")
	b := filepath.Join(dir, "b.yml")
	writeFile(t, a, "include:\n  - ./b.yml\n")
	writeFile(t, b, "include:\n  - ./a.yml\n")

	_, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: a})
	if err == nil || !strings.Contains(err.Error(), "include cycle detected") || !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadFileIfPresentRejectsInvalidIncludeEntries(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "missing", body: "include:\n  - ./missing.yml\n", want: "include file missing"},
		{name: "url", body: "include:\n  - https://example.com/policy.yml\n", want: "must be a local file path"},
		{name: "empty", body: "include:\n  - \"\"\n", want: "include[0] must be non-empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "cc-bash-guard.yml")
			writeFile(t, root, tt.body)
			_, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: root})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadFileIfPresentRunsIncludedTestsAndReportsSource(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "cc-bash-guard.yml")
	testsPath := filepath.Join(dir, "tests", "git.yml")
	writeFile(t, filepath.Join(dir, "policy.yml"), `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	writeFile(t, testsPath, `test:
  - in: "git status"
    decision: deny
`)
	writeFile(t, root, `include:
  - ./policy.yml
  - ./tests/git.yml
`)

	pipeline, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: root})
	if err != nil {
		t.Fatalf("LoadFileIfPresent() error = %v", err)
	}
	if len(pipeline.Test) != 1 || pipeline.Test[0].Source.Path != testsPath {
		t.Fatalf("test source = %#v", pipeline.Test)
	}
	decision, err := policy.Evaluate(pipeline, pipeline.Test[0].In)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Outcome == pipeline.Test[0].Decision {
		t.Fatalf("test unexpectedly passed")
	}
}

func TestLoadFileIfPresentReportsIncludedRuleSourceInValidationError(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "cc-bash-guard.yml")
	invalid := filepath.Join(dir, "policies", "git.yml")
	writeFile(t, invalid, `permission:
  deny:
    - name: bad
      command:
        name: git
        semantic:
          namespace: prod
      test:
        deny: ["git push"]
        abstain: ["git status"]
`)
	writeFile(t, root, `include:
  - ./policies/git.yml
`)

	_, err := LoadFileIfPresent(Source{Layer: LayerUser, Path: root})
	if err == nil || !strings.Contains(err.Error(), invalid) || !strings.Contains(err.Error(), "permission.deny[0].command.semantic.namespace") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIncludedFileChangeInvalidatesVerifiedArtifact(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "cache")
	root := filepath.Join(dir, "cc-bash-guard.yml")
	include := filepath.Join(dir, "git.yml")
	writeFile(t, include, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	writeFile(t, root, `include:
  - ./git.yml
`)
	if _, err := VerifyFile(Source{Layer: LayerUser, Path: root}, cacheDir, "vtest"); err != nil {
		t.Fatalf("VerifyFile() error = %v", err)
	}
	writeFile(t, include, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: diff
      test:
        allow: ["git diff"]
        abstain: ["git status"]
`)
	_, err := LoadVerifiedFileForHook(Source{Layer: LayerUser, Path: root}, []string{cacheDir})
	if err == nil || !strings.Contains(err.Error(), "included policy files changed since last verify") || !strings.Contains(err.Error(), "Included policy files are part of the verified artifact") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyEffectiveArtifactContainsBundledConfigAndIncludedSources(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	cacheHome := t.TempDir()
	configPath := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	includePath := filepath.Join(home, ".config", "cc-bash-guard", "policies", "git.yml")
	writeFile(t, includePath, `permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
      test:
        allow: ["git status"]
        abstain: ["git diff"]
`)
	writeFile(t, configPath, `include:
  - ./policies/git.yml
`)
	if _, err := VerifyEffectiveToAllCaches(cwd, home, "", cacheHome, "claude", "vtest"); err != nil {
		t.Fatalf("VerifyEffectiveToAllCaches() error = %v", err)
	}
	data, err := os.ReadFile(singleCachePath(t, filepath.Join(cacheHome, "cc-bash-guard")))
	if err != nil {
		t.Fatal(err)
	}
	var cache struct {
		SourcePaths []string            `json:"source_paths"`
		Pipeline    policy.PipelineSpec `json:"pipeline"`
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cache.SourcePaths, []string{includePath, configPath}) {
		t.Fatalf("source paths = %#v", cache.SourcePaths)
	}
	if len(cache.Pipeline.Include) != 0 || len(cache.Pipeline.Permission.Allow) != 1 {
		t.Fatalf("pipeline = %#v", cache.Pipeline)
	}
	src := cache.Pipeline.Permission.Allow[0].Source
	if src.Path != includePath || src.Section != "permission.allow" || src.Index != 0 {
		t.Fatalf("rule source = %+v", src)
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

func hasFingerprintInput(inputs []FingerprintInput, want FingerprintInput) bool {
	for _, input := range inputs {
		if input.Kind != want.Kind || input.Name != want.Name {
			continue
		}
		if want.Value == "" || input.Value == want.Value {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertDecision(t *testing.T, pipeline policy.Pipeline, command string, want string) {
	t.Helper()
	decision, err := policy.Evaluate(pipeline, command)
	if err != nil {
		t.Fatalf("Evaluate(%q) error = %v", command, err)
	}
	if decision.Outcome != want {
		t.Fatalf("Evaluate(%q) = %s, want %s", command, decision.Outcome, want)
	}
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
