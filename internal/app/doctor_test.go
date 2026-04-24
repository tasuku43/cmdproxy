package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tasuku43/cc-bash-proxy/internal/app/doctoring"
	configrepo "github.com/tasuku43/cc-bash-proxy/internal/infra/config"
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
}

func minimalValidConfig() string {
	return `permission:
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
}

func writeAppUserConfig(t *testing.T, home string, body string) string {
	t.Helper()
	path := filepath.Join(home, ".config", "cc-bash-proxy", "cc-bash-proxy.yml")
	writeAppFile(t, path, body)
	return path
}

func writeAppProjectConfig(t *testing.T, cwd string, body string) string {
	t.Helper()
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o755); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	path := filepath.Join(cwd, ".cc-bash-proxy", "cc-bash-proxy.yaml")
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
