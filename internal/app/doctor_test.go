package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cc-bash-guard/internal/app/doctoring"
	configrepo "github.com/tasuku43/cc-bash-guard/internal/infra/config"
)

func TestRunDoctorUsesEffectiveProjectConfig(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	writeAppUserConfig(t, home, minimalValidConfig())
	projectConfig := writeAppProjectConfig(t, cwd, "unknown_field: true\n")

	result := RunDoctor(Env{Cwd: cwd, Home: home})
	if !doctoring.HasFailures(result.Report) {
		t.Fatalf("expected project config error, report=%+v", result.Report)
	}
	if !reportHasSource(result.Report.ConfigSources, projectConfig) {
		t.Fatalf("expected project config source %q, sources=%+v", projectConfig, result.Report.ConfigSources)
	}
	if result.Report.Tool != "claude" {
		t.Fatalf("tool=%q", result.Report.Tool)
	}
	if strings.TrimSpace(result.Report.EffectiveFingerprint) == "" {
		t.Fatal("expected effective fingerprint")
	}
}

func TestRunDoctorReportsVerifiedEffectiveArtifact(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	xdgCacheHome := t.TempDir()
	writeAppUserConfig(t, home, minimalValidConfig())

	before := RunDoctor(Env{Cwd: cwd, Home: home, XDGCacheHome: xdgCacheHome})
	if before.Report.VerifiedArtifactExists {
		t.Fatalf("expected no verified artifact before verify, report=%+v", before.Report)
	}

	if _, err := configrepo.VerifyEffectiveToAllCaches(cwd, home, "", xdgCacheHome, "claude", "test"); err != nil {
		t.Fatalf("verify effective: %v", err)
	}

	after := RunDoctor(Env{Cwd: cwd, Home: home, XDGCacheHome: xdgCacheHome})
	if !after.Report.VerifiedArtifactExists {
		t.Fatalf("expected verified artifact after verify, report=%+v", after.Report)
	}
	if !after.Report.VerifiedArtifactCompatible {
		t.Fatalf("expected compatible verified artifact after verify, report=%+v", after.Report)
	}
}

func TestRunDoctorReportsIncompatibleVerifiedArtifact(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	xdgCacheHome := t.TempDir()
	writeAppUserConfig(t, home, minimalValidConfig())

	if _, err := configrepo.VerifyEffectiveToAllCaches(cwd, home, "", xdgCacheHome, "claude", "test"); err != nil {
		t.Fatalf("verify effective: %v", err)
	}
	appRemoveJSONField(t, singleAppCachePath(t, filepath.Join(xdgCacheHome, "cc-bash-guard")), "evaluation_semantics_version")

	result := RunDoctor(Env{Cwd: cwd, Home: home, XDGCacheHome: xdgCacheHome})
	if !result.Report.VerifiedArtifactExists {
		t.Fatalf("expected artifact to exist, report=%+v", result.Report)
	}
	if result.Report.VerifiedArtifactCompatible {
		t.Fatalf("expected incompatible artifact, report=%+v", result.Report)
	}
	if !doctoring.HasFailures(result.Report) {
		t.Fatalf("expected doctor failure for incompatible artifact, report=%+v", result.Report)
	}
	if !reportHasCheck(result.Report, "artifact.evaluation-semantics", doctoring.StatusFail, "evaluation semantics version 0") {
		t.Fatalf("expected incompatible artifact check, report=%+v", result.Report)
	}
}

func minimalValidConfig() string {
	return `permission:
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
}

func writeAppUserConfig(t *testing.T, home string, body string) string {
	t.Helper()
	path := filepath.Join(home, ".config", "cc-bash-guard", "cc-bash-guard.yml")
	writeAppFile(t, path, body)
	return path
}

func writeAppProjectConfig(t *testing.T, cwd string, body string) string {
	t.Helper()
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o755); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	path := filepath.Join(cwd, ".cc-bash-guard", "cc-bash-guard.yaml")
	writeAppFile(t, path, body)
	return path
}

func writeAppFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func reportHasSource(sources []configrepo.Source, path string) bool {
	for _, src := range sources {
		if src.Path == path {
			return true
		}
	}
	return false
}

func reportHasCheck(report doctoring.Report, id string, status doctoring.Status, messagePart string) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status && strings.Contains(check.Message, messagePart) {
			return true
		}
	}
	return false
}

func singleAppCachePath(t *testing.T, dir string) string {
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

func appRemoveJSONField(t *testing.T, path string, key string) {
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
