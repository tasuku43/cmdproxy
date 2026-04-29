package semantic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSemanticCoverageDocMentionsSchemaCommandsAndFields(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "user", "SEMANTIC_COVERAGE.md")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read semantic coverage doc: %v", err)
	}
	doc := string(content)

	for _, schema := range AllSchemas() {
		if !strings.Contains(doc, "### "+schema.Command) {
			t.Errorf("coverage doc missing section for command %q", schema.Command)
		}
		if !strings.Contains(doc, "`"+schema.Command+"`") {
			t.Errorf("coverage doc missing command mention %q", schema.Command)
		}
		for _, field := range schema.Fields {
			if !strings.Contains(doc, "`"+field.Name+"`") {
				t.Errorf("coverage doc missing field %q for command %q", field.Name, schema.Command)
			}
		}
	}
}
