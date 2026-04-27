package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
)

func runCLIHelpTest(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(args, Streams{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}, Env{Cwd: ".", Home: "."})
	return code, stdout.String(), stderr.String()
}

func TestRootHelpOrientsNewUsers(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"permission guard",
		"evaluates Bash commands against policy",
		"Start here:",
		"cc-bash-guard init",
		"cc-bash-guard verify",
		"cc-bash-guard doctor",
		"cc-bash-guard explain",
		"PreToolUse Bash snippet",
		"permission.deny",
		"top-level include",
		"deny > ask > allow",
		"unmatched commands fall back to ask",
		"never rewrites commands itself",
		"cc-bash-guard help init",
		"cc-bash-guard help config",
		"cc-bash-guard help permission",
		"cc-bash-guard help semantic",
		"cc-bash-guard help examples",
		"cc-bash-guard help troubleshoot",
		"docs/user/QUICKSTART.md",
		"docs/user/THREAT_MODEL.md",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("root help missing %q:\n%s", want, stdout)
		}
	}
}

func TestHookHelpDocumentsNoPolicyRewriteAndRTKIntegration(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "hook")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"returns Claude Code hook JSON for allow, ask, deny",
		"cc-bash-guard hook [--rtk] [--auto-verify]",
		"Hook protocol:",
		"permissionDecision: allow, ask, or deny",
		"Deny is also returned as JSON with exit 0",
		"missing or stale verified artifacts therefore fail closed",
		"--rtk",
		"delegate rewriting to external RTK",
		"RTK integration:",
		"single Bash hook",
		"evaluates permissions first",
		"external rtk rewrite",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help hook missing %q:\n%s", want, stdout)
		}
	}
	for _, bad := range []string{
		"compatibility path",
		"hidden",
	} {
		if strings.Contains(stdout, bad) {
			t.Fatalf("help hook contains %q:\n%s", bad, stdout)
		}
	}
}

func TestHelpExplainDescribesDiagnosticBehavior(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "explain")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"Diagnose why a command would be allowed, asked, or denied.",
		"does not execute",
		"verified policy artifact",
		"run verify after",
		"cc-bash-guard explain [--format text|json]",
		"cc-bash-guard explain --format json",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help explain missing %q:\n%s", want, stdout)
		}
	}
}

func TestHelpInitGivesNextSteps(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "init")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"creates a starter deny rule and test case",
		"prints the user config path",
		"prints the Claude Code PreToolUse Bash hook snippet",
		"After init:",
		"edit ~/.config/cc-bash-guard/cc-bash-guard.yml",
		"cc-bash-guard verify",
		"~/.claude/settings.json",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help init missing %q:\n%s", want, stdout)
		}
	}
}

func TestHelpPermissionExplainsCurrentSchema(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "permission")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"Permission rules are grouped into deny, ask, and allow buckets.",
		"Start with deny rules",
		"command",
		"env",
		"patterns",
		"semantic",
		"cc-bash-guard help semantic",
		"command.name",
		"Use command.semantic for commands listed",
		"Use patterns for commands without semantic support",
		"Put rules under permission.deny",
		"Do not combine command and patterns",
		"^ls(\\\\s+-[A-Za-z0-9]+)?\\\\s+[^;&|$()]+$",
		"permission:",
		"docs/user/PERMISSION_SCHEMA.md",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help permission missing %q:\n%s", want, stdout)
		}
	}
}

func TestHelpConfigSeparatesRuleAndTopLevelTests(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "config")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"First-time setup:",
		"permission: deny / ask / allow buckets",
		"test: end-to-end expect cases",
		"rule-local test checks whether one rule matches or passes examples",
		"top-level test checks final allow / ask / deny decisions",
		"Permission source merge rule:",
		"Decision order:",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help config missing %q:\n%s", want, stdout)
		}
	}
}

func TestHelpVerifyReferencesPatternExamplesAndTests(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "verify")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"Use top-level test entries",
		"patterns fallback rules",
		"docs/user/EXAMPLES.md",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help verify missing %q:\n%s", want, stdout)
		}
	}
}

func TestHelpExamplesShowsSafePatternFallback(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "examples")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"Safe patterns fallback:",
		"terraform read-only fallback",
		"^terraform\\\\s+(plan|show)(\\\\s|$)[^;&|$()]*$",
		"terraform apply -auto-approve",
		"decision: ask",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help examples missing %q:\n%s", want, stdout)
		}
	}
}

func TestHelpSemanticListsSupportedCommands(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "semantic")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, command := range semanticpkg.SupportedCommands() {
		if !strings.Contains(stdout, command) {
			t.Fatalf("help semantic missing registered command %q:\n%s", command, stdout)
		}
	}
	for _, want := range []string{
		"The schema is selected by command.name",
		"semantic-schema",
		"docs/user/SEMANTIC_SCHEMAS.md",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help semantic missing %q:\n%s", want, stdout)
		}
	}
}

func TestHelpSemanticGitShowsSchema(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "semantic", "git")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	gitSchema, ok := semanticpkg.Lookup("git")
	if !ok {
		t.Fatalf("git schema missing")
	}
	for _, field := range gitSchema.Fields {
		if !strings.Contains(stdout, field.Name) {
			t.Fatalf("help semantic git missing registered field %q:\n%s", field.Name, stdout)
		}
	}
	for _, want := range []string{
		"Semantic schema: git",
		"verb",
		"force",
		"--force or -f",
		"force_with_lease",
		"force_if_includes",
		"--force-with-lease",
		"parser-recognized option tokens, not raw argv words",
		"Examples:",
		"Validation rules:",
		"permission command.semantic requires exact command.name",
		"fields are interpreted in the namespace selected by command.name",
		"docs/user/SEMANTIC_SCHEMAS.md",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help semantic git missing %q:\n%s", want, stdout)
		}
	}
}

func TestHelpSemanticUnknownFails(t *testing.T) {
	code, _, stderr := runCLIHelpTest("help", "semantic", "unknown")
	if code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(stderr, "unknown semantic command") || !strings.Contains(stderr, "git") {
		t.Fatalf("stderr=%s", stderr)
	}
}

func TestSemanticSchemaJSON(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("semantic-schema", "--format", "json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var payload struct {
		Schemas []struct {
			Command      string `json:"command"`
			SemanticPath string `json:"semantic_path"`
			Fields       []struct {
				Name string `json:"name"`
			} `json:"fields"`
		} `json:"schemas"`
		SchemasByCommand map[string]struct {
			Command      string `json:"command"`
			SemanticPath string `json:"semantic_path"`
			Fields       []struct {
				Name string `json:"name"`
			} `json:"fields"`
		} `json:"schemas_by_command"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, stdout)
	}
	if len(payload.Schemas) == 0 {
		t.Fatalf("missing schemas")
	}
	foundGit := false
	for _, schema := range payload.Schemas {
		if schema.Command == "git" {
			foundGit = true
			if schema.SemanticPath != "command.semantic" {
				t.Fatalf("git schema paths not populated: %+v", schema)
			}
			if len(schema.Fields) == 0 {
				t.Fatalf("git fields empty")
			}
		}
	}
	if !foundGit {
		t.Fatalf("git schema missing: %+v", payload.Schemas)
	}
	if payload.SchemasByCommand["git"].Command != "git" || payload.SchemasByCommand["git"].SemanticPath != "command.semantic" || len(payload.SchemasByCommand["git"].Fields) == 0 {
		t.Fatalf("schema by command missing git: %+v", payload.SchemasByCommand["git"])
	}
}

func TestHelpSemanticAndSchemaJSONListSameCommands(t *testing.T) {
	code, helpOut, stderr := runCLIHelpTest("help", "semantic")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	code, jsonOut, stderr := runCLIHelpTest("semantic-schema", "--format", "json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var payload struct {
		Schemas []struct {
			Command string `json:"command"`
		} `json:"schemas"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &payload); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, jsonOut)
	}
	var jsonCommands []string
	for _, schema := range payload.Schemas {
		jsonCommands = append(jsonCommands, schema.Command)
		if !strings.Contains(helpOut, schema.Command) {
			t.Fatalf("help semantic missing json command %q:\n%s", schema.Command, helpOut)
		}
	}
	registryCommands := semanticpkg.SupportedCommands()
	sort.Strings(jsonCommands)
	sort.Strings(registryCommands)
	if !reflect.DeepEqual(jsonCommands, registryCommands) {
		t.Fatalf("json commands=%#v registry=%#v", jsonCommands, registryCommands)
	}
}

func TestSemanticSchemaJSONAndGitHelpUseSameRegistry(t *testing.T) {
	code, jsonOut, stderr := runCLIHelpTest("semantic-schema", "git", "--format", "json")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var schema struct {
		Command string `json:"command"`
		Fields  []struct {
			Name string `json:"name"`
		} `json:"fields"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &schema); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, jsonOut)
	}
	code, helpOut, stderr := runCLIHelpTest("help", "semantic", "git")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, field := range schema.Fields {
		if !strings.Contains(helpOut, field.Name) {
			t.Fatalf("git help missing schema field %q:\n%s", field.Name, helpOut)
		}
	}
}

func TestHelpExamplesUseCurrentSyntax(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "examples")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"permission:",
		"command:",
		"env:",
		"patterns:",
		"include:",
		"./policies/git.yml",
		"git destructive force push",
		"AWS identity",
		"kubectl read-only",
		"Unknown command fallback",
		"docs/user/EXAMPLES.md",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help examples missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "explain") {
		t.Fatalf("help examples mentions explain:\n%s", stdout)
	}
}

func TestHelpTroubleshootCoversCommonFailures(t *testing.T) {
	code, stdout, stderr := runCLIHelpTest("help", "troubleshoot")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"Verified artifact missing or stale",
		"Include error",
		"Unsupported semantic field",
		"Command has no semantic schema",
		"All permission sources abstained",
		"Regex pattern not matching",
		"AWS profile style",
		"Command not being rewritten",
		"docs/user/TROUBLESHOOTING.md",
		"docs/user/THREAT_MODEL.md",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help troubleshoot missing %q:\n%s", want, stdout)
		}
	}
}

func TestUserDocsExamplesUseCurrentPermissionShape(t *testing.T) {
	docsRoot := filepath.Join("..", "..", "docs", "user")
	entries, err := os.ReadDir(docsRoot)
	if err != nil {
		t.Fatalf("read docs/user: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		path := filepath.Join(docsRoot, entry.Name())
		bodyBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(bodyBytes)
		for _, bad := range []string{
			"match:",
			"pattern:",
			"command_in:",
			"semantic.git",
			"semantic.gh",
			"Skills",
			"rewriting proxy",
		} {
			if strings.Contains(body, bad) {
				t.Fatalf("%s contains unsupported or out-of-scope text %q", path, bad)
			}
		}
	}
}

func TestReadmeDocumentsNoPolicyRewriteAndRTKIntegration(t *testing.T) {
	bodyBytes, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	body := string(bodyBytes)
	for _, want := range []string{
		"`cc-bash-guard` never rewrites commands",
		"returns `allow`, `ask`, or `deny`",
		"If you use RTK rewriting",
		"docs/user/THREAT_MODEL.md",
		"`cc-bash-guard hook --rtk` as the single Bash",
		"evaluates permissions first",
		"external `rtk rewrite`",
		"register RTK as a second Bash hook",
		"top-level `rewrite`, `verify` fails with migration guidance",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("README missing %q", want)
		}
	}
	for _, bad := range []string{
		"compatibility path",
		"hidden",
	} {
		if strings.Contains(body, bad) {
			t.Fatalf("README contains %q", bad)
		}
	}
}
