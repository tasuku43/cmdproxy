package command

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

func TestSemanticParserGoldenOutputs(t *testing.T) {
	cases := []string{
		"git push --force-with-lease origin main",
		"aws --profile prod --region us-east-1 ec2 describe-instances --no-cli-pager",
		"kubectl -n prod get pods -l app=web",
		"gh api -X POST repos/OWNER/REPO/actions/workflows/deploy.yml/dispatches -f ref=main",
		"gws users list --customer my_customer --page-all",
		"helm upgrade --install web ./chart -n prod --dry-run --set image.tag=abc",
		"helmfile -e prod -f helmfile.yaml diff --selector app=web",
		"argocd app rollback my-app 42 --project prod",
		"terraform -chdir=infra plan -target=module.web -out=tfplan",
		"docker run --rm --network host -v /var/run/docker.sock:/var/run/docker.sock alpine sh",
	}

	got := mustMarshalSemanticParseGolden(t, cases)
	path := filepath.Join("testdata", "semantic_parse_golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update semantic parse golden: %v", err)
		}
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read semantic parse golden: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatalf("semantic parse golden drifted; run UPDATE_GOLDEN=1 go test ./internal/domain/command and review docs/schema if intentional")
	}
}

func TestSemanticParserCoverageMatchesSchemaRegistry(t *testing.T) {
	parserPrograms := map[string]bool{}
	for _, parser := range defaultParsers {
		parserPrograms[parser.Program()] = true
	}

	for _, command := range semanticpkg.SupportedCommands() {
		if !parserPrograms[command] {
			t.Fatalf("semantic command %q has schema but no default parser", command)
		}
	}
	for program := range parserPrograms {
		if program == "generic" {
			continue
		}
		if _, ok := semanticpkg.Lookup(program); !ok {
			t.Fatalf("default parser %q has no semantic schema; document generic fallback or add schema", program)
		}
	}
}

func TestSemanticParserNearMissesRemainConservative(t *testing.T) {
	tests := []struct {
		raw      string
		program  string
		parser   string
		semantic string
	}{
		{raw: "git -C repo -- status", program: "git", parser: "git", semantic: "git"},
		{raw: "terraform -chdir=infra frobnicate", program: "terraform", parser: "terraform", semantic: "terraform"},
		{raw: "unknownctl get pods", program: "unknownctl", parser: "generic", semantic: ""},
	}
	registry := DefaultParserRegistry()
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			cmd, ok := registry.Parse(NewInvocation(tt.raw))
			if !ok {
				t.Fatalf("parse failed")
			}
			if cmd.Program != tt.program || cmd.Parser != tt.parser || cmd.SemanticParser != tt.semantic {
				t.Fatalf("parse state = program %q parser %q semantic %q", cmd.Program, cmd.Parser, cmd.SemanticParser)
			}
		})
	}
}

func mustMarshalSemanticParseGolden(t *testing.T, cases []string) []byte {
	t.Helper()
	registry := DefaultParserRegistry()
	var payload []map[string]any
	for _, raw := range cases {
		cmd, ok := registry.Parse(NewInvocation(raw))
		if !ok {
			t.Fatalf("parse %q failed", raw)
		}
		entry := map[string]any{
			"raw":             raw,
			"program":         cmd.Program,
			"parser":          cmd.Parser,
			"semantic_parser": cmd.SemanticParser,
			"action_path":     cmd.ActionPath,
			"semantic":        semanticPayload(cmd),
		}
		payload = append(payload, entry)
	}
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal semantic parse golden: %v", err)
	}
	return append(out, '\n')
}

func semanticPayload(cmd Command) any {
	switch cmd.SemanticParser {
	case "git":
		return cmd.Git
	case "aws":
		return cmd.AWS
	case "kubectl":
		return cmd.Kubectl
	case "gh":
		return cmd.Gh
	case "gws":
		return cmd.Gws
	case "helm":
		return cmd.Helm
	case "helmfile":
		return cmd.Helmfile
	case "argocd":
		return cmd.ArgoCD
	case "terraform":
		return cmd.Terraform
	case "docker":
		return cmd.Docker
	default:
		return nil
	}
}

func TestSemanticStructFieldsAreRepresentedInSchemas(t *testing.T) {
	semanticTypes := map[string]reflect.Type{
		"git":       reflect.TypeOf(GitSemantic{}),
		"aws":       reflect.TypeOf(AWSSemantic{}),
		"kubectl":   reflect.TypeOf(KubectlSemantic{}),
		"gh":        reflect.TypeOf(GhSemantic{}),
		"gws":       reflect.TypeOf(GwsSemantic{}),
		"helm":      reflect.TypeOf(HelmSemantic{}),
		"helmfile":  reflect.TypeOf(HelmfileSemantic{}),
		"argocd":    reflect.TypeOf(ArgoCDSemantic{}),
		"terraform": reflect.TypeOf(TerraformSemantic{}),
		"docker":    reflect.TypeOf(DockerSemantic{}),
	}
	for commandName, typ := range semanticTypes {
		schema, ok := semanticpkg.Lookup(commandName)
		if !ok {
			t.Fatalf("%s schema missing", commandName)
		}
		schemaFields := map[string]bool{}
		for _, field := range schema.Fields {
			schemaFields[field.Name] = true
		}
		var missing []string
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i).Name
			if internalSemanticField(commandName, field) {
				continue
			}
			name := camelToSnake(field)
			if !schemaFieldRepresents(schemaFields, name) {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Fatalf("%s semantic struct fields missing from schema: %s", commandName, strings.Join(missing, ", "))
		}
	}
}

func internalSemanticField(commandName, field string) bool {
	switch commandName + "." + field {
	case "aws.ProfileConflict", "aws.RegionSource",
		"terraform.ProvidersSubcommand", "terraform.MetadataSubcommand",
		"docker.Target":
		return true
	default:
		return false
	}
}

func schemaFieldRepresents(fields map[string]bool, name string) bool {
	if fields[name] {
		return true
	}
	for field := range fields {
		if strings.HasPrefix(field, name+"_") {
			return true
		}
	}
	return false
}

func camelToSnake(s string) string {
	switch s {
	case "EndpointURL":
		return "endpoint_url"
	case "NoCLIPager":
		return "no_cli_pager"
	case "RepoURL":
		return "repo_url"
	case "PRNumber":
		return "pr_number"
	case "RunID":
		return "run_id"
	case "WorkflowID":
		return "workflow_id"
	case "PID":
		return "pid"
	case "PIDHost":
		return "pid_host"
	case "IPC":
		return "ipc"
	case "IPCHost":
		return "ipc_host"
	case "UTS":
		return "uts"
	case "UTSHost":
		return "uts_host"
	case "RM":
		return "rm"
	case "JSON":
		return "json"
	case "JSONBody":
		return "json_body"
	case "Files":
		return "file"
	case "Filenames":
		return "filename"
	case "Selectors":
		return "selector"
	case "Profiles":
		return "profile"
	case "Labels":
		return "label"
	case "Assignees":
		return "assignee"
	case "EnvName":
		return "env"
	case "StateValuesFiles":
		return "state_values_file"
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}
