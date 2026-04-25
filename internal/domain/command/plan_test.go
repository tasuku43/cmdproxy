package command

import (
	"reflect"
	"testing"
)

func TestParseCommandPlanSimpleGitStatus(t *testing.T) {
	plan := Parse("git status")

	if plan.Shape.Kind != ShellShapeSimple {
		t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeSimple)
	}
	if !plan.SafeForStructuredAllow {
		t.Fatal("SafeForStructuredAllow = false, want true")
	}
	if len(plan.Commands) != 1 {
		t.Fatalf("len(Commands) = %d, want 1", len(plan.Commands))
	}
	cmd := plan.Commands[0]
	if cmd.Program != "git" || cmd.ProgramToken != "git" {
		t.Fatalf("command program = (%q, %q), want git/git", cmd.Program, cmd.ProgramToken)
	}
	if len(cmd.ActionPath) != 1 || cmd.ActionPath[0] != "status" {
		t.Fatalf("ActionPath = %#v, want [status]", cmd.ActionPath)
	}
	if cmd.Parser != "git" {
		t.Fatalf("Parser = %q, want git", cmd.Parser)
	}
}

func TestParseCommandPlanAndListExtractsCommandsButFailsClosed(t *testing.T) {
	plan := Parse("git status && git diff")

	if plan.Shape.Kind != ShellShapeAndList {
		t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeAndList)
	}
	if !plan.Shape.HasConditional {
		t.Fatal("HasConditional = false, want true")
	}
	if plan.SafeForStructuredAllow {
		t.Fatal("SafeForStructuredAllow = true, want false")
	}
	if len(plan.Commands) != 2 {
		t.Fatalf("len(Commands) = %d, want 2", len(plan.Commands))
	}
	if plan.Commands[0].Raw != "git status" || plan.Commands[1].Raw != "git diff" {
		t.Fatalf("command raws = %#v", []string{plan.Commands[0].Raw, plan.Commands[1].Raw})
	}
	assertNoShellConnectorMetadata(t, plan.Commands)
}

func TestParseCommandPlanMultiCommandListsExtractAllCommands(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		kind ShellShapeKind
		want []string
	}{
		{name: "three and list", raw: "git status && git diff && git log", kind: ShellShapeAndList, want: []string{"git status", "git diff", "git log"}},
		{name: "four sequence semicolon", raw: "git status; git diff; git log; git branch", kind: ShellShapeSequence, want: []string{"git status", "git diff", "git log", "git branch"}},
		{name: "newline sequence", raw: "git status\ngit diff\ngit log", kind: ShellShapeSequence, want: []string{"git status", "git diff", "git log"}},
		{name: "three or list", raw: "git status || git diff || git log", kind: ShellShapeOrList, want: []string{"git status", "git diff", "git log"}},
		{name: "pipe all", raw: "git status |& sh", kind: ShellShapePipeline, want: []string{"git status", "sh"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Parse(tt.raw)
			if plan.Shape.Kind != tt.kind {
				t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, tt.kind)
			}
			if len(plan.Commands) != len(tt.want) {
				t.Fatalf("len(Commands) = %d, want %d", len(plan.Commands), len(tt.want))
			}
			for i, want := range tt.want {
				if plan.Commands[i].Raw != want {
					t.Fatalf("Commands[%d].Raw = %q, want %q; commands=%+v", i, plan.Commands[i].Raw, want, plan.Commands)
				}
			}
			assertNoShellConnectorMetadata(t, plan.Commands)
		})
	}
}

func TestParseCommandPlanPipelineExtractsCommandsButFailsClosed(t *testing.T) {
	plan := Parse("git status | sh")

	if plan.Shape.Kind != ShellShapePipeline {
		t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapePipeline)
	}
	if !plan.Shape.HasPipeline {
		t.Fatal("HasPipeline = false, want true")
	}
	if plan.SafeForStructuredAllow {
		t.Fatal("SafeForStructuredAllow = true, want false")
	}
	if len(plan.Commands) != 2 {
		t.Fatalf("len(Commands) = %d, want 2", len(plan.Commands))
	}
	if plan.Commands[0].Program != "git" || plan.Commands[1].Program != "sh" {
		t.Fatalf("command programs = %#v", []string{plan.Commands[0].Program, plan.Commands[1].Program})
	}
	assertNoShellConnectorMetadata(t, plan.Commands)
}

func TestParseCommandPlanProcessSubstitutionExtractsCommandsButFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "input process substitution", raw: "cat <(rm -rf /tmp/x)", want: []string{"rm -rf /tmp/x", "cat <(rm -rf /tmp/x)"}},
		{name: "output process substitution", raw: "echo >(sh)", want: []string{"sh", "echo >(sh)"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Parse(tt.raw)
			if plan.Shape.Kind != ShellShapeUnknown {
				t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeUnknown)
			}
			if !plan.Shape.HasProcessSubstitution {
				t.Fatal("HasProcessSubstitution = false, want true")
			}
			if plan.SafeForStructuredAllow {
				t.Fatal("SafeForStructuredAllow = true, want false")
			}
			if len(plan.Commands) != len(tt.want) {
				t.Fatalf("len(Commands) = %d, want %d; commands=%+v diagnostics=%+v", len(plan.Commands), len(tt.want), plan.Commands, plan.Diagnostics)
			}
			for i, want := range tt.want {
				if plan.Commands[i].Raw != want {
					t.Fatalf("Commands[%d].Raw = %q, want %q; commands=%+v", i, plan.Commands[i].Raw, want, plan.Commands)
				}
			}
			assertNoShellConnectorMetadata(t, plan.Commands)
		})
	}
}

func TestParseCommandPlanUnsafeShellShapesFailClosed(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		kind ShellShapeKind
	}{
		{name: "sequence", raw: "git status; git diff", kind: ShellShapeSequence},
		{name: "background", raw: "git status &", kind: ShellShapeBackground},
		{name: "redirect", raw: "git status > /tmp/out", kind: ShellShapeRedirect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Parse(tt.raw)
			if plan.Shape.Kind != tt.kind {
				t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, tt.kind)
			}
			if plan.SafeForStructuredAllow {
				t.Fatal("SafeForStructuredAllow = true, want false")
			}
		})
	}
}

func assertNoShellConnectorMetadata(t *testing.T, commands []Command) {
	t.Helper()
	for _, cmd := range commands {
		if cmd.Raw == "&&" || cmd.Raw == "||" || cmd.Raw == ";" || cmd.Raw == "|" || cmd.Raw == "&" {
			t.Fatalf("command contains connector as raw command: %+v", cmd)
		}
		for _, token := range append(append([]string{}, cmd.ActionPath...), cmd.Args...) {
			switch token {
			case "&&", "||", ";", "|", "&":
				t.Fatalf("command contains connector token %q: %+v", token, cmd)
			}
		}
	}
}

func TestParserRegistryDispatchesKnownParser(t *testing.T) {
	registry := NewCommandParserRegistry(testParser{program: "known"})

	plan := ParseWithRegistry("known run --flag", registry)

	if len(plan.Commands) != 1 {
		t.Fatalf("len(Commands) = %d, want 1", len(plan.Commands))
	}
	cmd := plan.Commands[0]
	if cmd.Parser != "test-known" {
		t.Fatalf("Parser = %q, want test-known", cmd.Parser)
	}
	if len(cmd.ActionPath) != 1 || cmd.ActionPath[0] != "dispatched" {
		t.Fatalf("ActionPath = %#v, want [dispatched]", cmd.ActionPath)
	}
}

func TestParserRegistryFallsBackToGenericParser(t *testing.T) {
	registry := NewCommandParserRegistry(testParser{program: "known"})

	plan := ParseWithRegistry("unknown status", registry)

	if len(plan.Commands) != 1 {
		t.Fatalf("len(Commands) = %d, want 1", len(plan.Commands))
	}
	cmd := plan.Commands[0]
	if cmd.Program != "unknown" {
		t.Fatalf("Program = %q, want unknown", cmd.Program)
	}
	if cmd.Parser != "generic" {
		t.Fatalf("Parser = %q, want generic", cmd.Parser)
	}
	if len(cmd.ActionPath) != 0 {
		t.Fatalf("ActionPath = %#v, want empty for generic parser", cmd.ActionPath)
	}
}

func TestGenericParserBuildsOnlyStructuralLayer(t *testing.T) {
	cmd, ok := GenericParser{}.Parse(Invocation{
		Raw:          "tool --profile dev status --verbose",
		ProgramToken: "tool",
		Program:      "tool",
		Words:        []string{"--profile", "dev", "status", "--verbose"},
	})
	if !ok {
		t.Fatal("GenericParser.Parse() ok = false, want true")
	}
	if len(cmd.GlobalOptions) != 0 {
		t.Fatalf("GlobalOptions = %#v, want empty for generic parser", cmd.GlobalOptions)
	}
	if len(cmd.ActionPath) != 0 {
		t.Fatalf("ActionPath = %#v, want empty for generic parser", cmd.ActionPath)
	}
	if len(cmd.Args) != 0 {
		t.Fatalf("Args = %#v, want empty for generic parser", cmd.Args)
	}
	wantRawOptions := []Option{{Name: "--profile", Position: 0}, {Name: "--verbose", Position: 3}}
	if !reflect.DeepEqual(cmd.RawOptions, wantRawOptions) {
		t.Fatalf("RawOptions = %#v, want %#v", cmd.RawOptions, wantRawOptions)
	}
}

type testParser struct {
	program string
}

func (p testParser) Program() string {
	return p.program
}

func (p testParser) Parse(base Command) (Command, bool) {
	base.Args = append([]string(nil), base.RawWords...)
	base.ActionPath = []string{"dispatched"}
	base.Parser = "test-" + p.program
	base.SemanticParser = "test-" + p.program
	return base, true
}
