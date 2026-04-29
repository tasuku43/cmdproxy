package semantic

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSemanticSchemaSnapshot(t *testing.T) {
	got := mustMarshalSemanticSchemaSnapshot(t)
	path := filepath.Join("testdata", "semantic_schema.json")

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create snapshot dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update schema snapshot: %v", err)
		}
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema snapshot: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatalf("semantic schema snapshot drifted; run UPDATE_GOLDEN=1 go test ./internal/domain/semantic and update docs if the change is intentional")
	}
}

func TestSemanticSchemaRegistryIsConsistent(t *testing.T) {
	commands := SupportedCommands()
	want := []string{"git", "aws", "kubectl", "gh", "argocd", "gws", "helmfile", "helm", "terraform", "docker"}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("supported commands = %#v, want %#v", commands, want)
	}

	seen := map[string]bool{}
	for _, schema := range AllSchemas() {
		if schema.Command == "" || schema.Parser == "" {
			t.Fatalf("schema has empty command or parser: %+v", schema)
		}
		if schema.Command != schema.Parser {
			t.Fatalf("schema command %q uses parser %q; document generic fallback explicitly if this is intentional", schema.Command, schema.Parser)
		}
		if seen[schema.Command] {
			t.Fatalf("duplicate semantic schema command %q", schema.Command)
		}
		seen[schema.Command] = true
		if schema.SemanticPath != "command.semantic" {
			t.Fatalf("%s semantic path = %q", schema.Command, schema.SemanticPath)
		}
		if len(schema.Fields) == 0 {
			t.Fatalf("%s schema has no fields", schema.Command)
		}
		fieldSeen := map[string]bool{}
		for _, field := range schema.Fields {
			if field.Name == "" || field.Type == "" || field.Description == "" {
				t.Fatalf("%s has incomplete field metadata: %+v", schema.Command, field)
			}
			if fieldSeen[field.Name] {
				t.Fatalf("%s has duplicate field %q", schema.Command, field.Name)
			}
			fieldSeen[field.Name] = true
		}
	}
}

func TestSemanticDocsMentionAllSchemaCommandsAndCoverageFields(t *testing.T) {
	docs := map[string]string{
		"coverage": filepath.Join("..", "..", "..", "docs", "user", "SEMANTIC_COVERAGE.md"),
		"schemas":  filepath.Join("..", "..", "..", "docs", "user", "SEMANTIC_SCHEMAS.md"),
	}
	for name, path := range docs {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s doc: %v", name, err)
		}
		doc := string(content)
		for _, schema := range AllSchemas() {
			if !strings.Contains(doc, "`"+schema.Command+"`") && !strings.Contains(doc, "### "+schema.Command) && !strings.Contains(doc, "## "+schema.Command) {
				t.Errorf("%s doc missing command %q", name, schema.Command)
			}
			if name != "coverage" {
				continue
			}
			for _, field := range schema.Fields {
				if !strings.Contains(doc, "`"+field.Name+"`") {
					t.Errorf("%s doc missing field %q for command %q", name, field.Name, schema.Command)
				}
			}
		}
	}
}

func mustMarshalSemanticSchemaSnapshot(t *testing.T) []byte {
	t.Helper()
	payload := map[string]any{
		"schemas":            AllSchemas(),
		"schemas_by_command": SchemasByCommand(),
	}
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal schema snapshot: %v", err)
	}
	return append(out, '\n')
}
