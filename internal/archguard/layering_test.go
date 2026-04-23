package archguard

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLayerDirectoriesExist(t *testing.T) {
	for _, dir := range []string{"../config", "../domain", "../cli", "../app", "../infra", "../domain/directive"} {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			t.Fatalf("layer dir missing: %s", dir)
		}
	}
}

func TestDomainDoesNotImportCLI(t *testing.T) {
	assertNoForbiddenImport(t, "../domain", []string{"/internal/cli"})
}

func TestConfigDoesNotImportCLI(t *testing.T) {
	assertNoForbiddenImport(t, "../config", []string{"/internal/cli"})
}

func TestDomainDoesNotImportApp(t *testing.T) {
	assertNoForbiddenImport(t, "../domain", []string{"/internal/app"})
}

func TestAppDoesNotImportCLI(t *testing.T) {
	assertNoForbiddenImport(t, "../app", []string{"/internal/cli"})
}

func TestInfraDoesNotImportCLIOrApp(t *testing.T) {
	assertNoForbiddenImport(t, "../infra", []string{"/internal/cli", "/internal/app"})
}

func assertNoForbiddenImport(t *testing.T, dir string, forbidden []string) {
	t.Helper()
	fset := token.NewFileSet()
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", path, parseErr)
		}
		for _, imp := range file.Imports {
			v := strings.Trim(imp.Path.Value, "\"")
			for _, f := range forbidden {
				if strings.Contains(v, f) {
					t.Fatalf("forbidden import in %s: %s", path, v)
				}
			}
		}
		return nil
	})
}
