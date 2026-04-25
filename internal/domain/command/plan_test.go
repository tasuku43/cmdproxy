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
	if cmd.Git == nil || cmd.Git.Verb != "status" {
		t.Fatalf("Git semantic = %+v, want verb status", cmd.Git)
	}
}

func TestGitParserBuildsSemanticFields(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want GitSemantic
	}{
		{name: "push force", raw: "git push --force origin main", want: GitSemantic{Verb: "push", Force: true, Remote: "origin", Branch: "main", Ref: "main"}},
		{name: "push short force", raw: "git push -f origin main", want: GitSemantic{Verb: "push", Force: true, Remote: "origin", Branch: "main", Ref: "main"}},
		{name: "diff cached", raw: "git diff --cached", want: GitSemantic{Verb: "diff", Cached: true, Staged: true}},
		{name: "reset hard", raw: "git reset --hard HEAD", want: GitSemantic{Verb: "reset", Hard: true, Ref: "HEAD"}},
		{name: "clean combined flags", raw: "git clean -fdx", want: GitSemantic{Verb: "clean", Force: true, Recursive: true, IncludeIgnored: true}},
		{name: "switch branch", raw: "git switch main", want: GitSemantic{Verb: "switch", Branch: "main", Ref: "main"}},
		{name: "switch create branch", raw: "git switch -c feature/foo", want: GitSemantic{Verb: "switch", Branch: "feature/foo", Ref: "feature/foo"}},
		{name: "checkout best effort branch", raw: "git checkout main", want: GitSemantic{Verb: "checkout", Branch: "main", Ref: "main"}},
		{name: "log", raw: "git log", want: GitSemantic{Verb: "log"}},
		{name: "show", raw: "git show", want: GitSemantic{Verb: "show"}},
		{name: "branch", raw: "git branch", want: GitSemantic{Verb: "branch"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Parse(tt.raw)
			if len(plan.Commands) != 1 {
				t.Fatalf("len(Commands)=%d", len(plan.Commands))
			}
			got := plan.Commands[0].Git
			if got == nil {
				t.Fatalf("Git semantic = nil")
			}
			if got.Verb != tt.want.Verb || got.Remote != tt.want.Remote || got.Branch != tt.want.Branch || got.Ref != tt.want.Ref ||
				got.Force != tt.want.Force || got.Hard != tt.want.Hard || got.Recursive != tt.want.Recursive ||
				got.IncludeIgnored != tt.want.IncludeIgnored || got.Cached != tt.want.Cached || got.Staged != tt.want.Staged {
				t.Fatalf("Git semantic = %+v, want %+v", *got, tt.want)
			}
			if tt.raw == "git clean -fdx" && !containsString(got.Flags, "-x") {
				t.Fatalf("Git clean flags = %#v, want split -x", got.Flags)
			}
		})
	}
}

func TestParseCommandPlanAndListExtractsCommandsButFailsClosed(t *testing.T) {
	plan := Parse("git status && git diff")

	if plan.Shape.Kind != ShellShapeCompound {
		t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeCompound)
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
		flag string
		want []string
	}{
		{name: "three and list", raw: "git status && git diff && git log", flag: "conditional", want: []string{"git status", "git diff", "git log"}},
		{name: "four sequence semicolon", raw: "git status; git diff; git log; git branch", flag: "sequence", want: []string{"git status", "git diff", "git log", "git branch"}},
		{name: "newline sequence", raw: "git status\ngit diff\ngit log", flag: "sequence", want: []string{"git status", "git diff", "git log"}},
		{name: "three or list", raw: "git status || git diff || git log", flag: "conditional", want: []string{"git status", "git diff", "git log"}},
		{name: "pipe all", raw: "git status |& sh", flag: "pipeline", want: []string{"git status", "sh"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Parse(tt.raw)
			if plan.Shape.Kind != ShellShapeCompound {
				t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeCompound)
			}
			if !containsString(plan.Shape.Flags(), tt.flag) {
				t.Fatalf("Shape.Flags() = %#v, want %q", plan.Shape.Flags(), tt.flag)
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

	if plan.Shape.Kind != ShellShapeCompound {
		t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeCompound)
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
			if plan.Shape.Kind != ShellShapeCompound {
				t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeCompound)
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
		flag string
	}{
		{name: "sequence", raw: "git status; git diff", flag: "sequence"},
		{name: "background", raw: "git status &", flag: "background"},
		{name: "redirect", raw: "git status > /tmp/out", flag: "redirection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Parse(tt.raw)
			if plan.Shape.Kind != ShellShapeCompound {
				t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeCompound)
			}
			if !containsString(plan.Shape.Flags(), tt.flag) {
				t.Fatalf("Shape.Flags() = %#v, want %q", plan.Shape.Flags(), tt.flag)
			}
			if plan.SafeForStructuredAllow {
				t.Fatal("SafeForStructuredAllow = true, want false")
			}
		})
	}
}

func TestCommandPlanEvaluationSafetyReasons(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantSafe   bool
		wantReason string
	}{
		{name: "simple", raw: "git status", wantSafe: true},
		{name: "pipeline", raw: "git status | sh", wantSafe: true},
		{name: "syntax error", raw: "git status &&", wantReason: "parse_error"},
		{name: "process substitution", raw: "cat <(git status)", wantReason: "process_substitution"},
		{name: "redirect", raw: "git status > /tmp/out", wantReason: "redirect"},
		{name: "unknown word part in extracted command", raw: "git status && echo $HOME", wantReason: "unknown_shape"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			safety := EvaluationSafetyForPlan(Parse(tt.raw))
			if safety.Safe != tt.wantSafe {
				t.Fatalf("Safe = %v, want %v; safety=%+v", safety.Safe, tt.wantSafe, safety)
			}
			if tt.wantReason != "" && !containsString(safety.Reasons, tt.wantReason) {
				t.Fatalf("Reasons = %#v, want %q", safety.Reasons, tt.wantReason)
			}
		})
	}
}

func TestParseCommandPlanCompoundShapePreservesAllFlags(t *testing.T) {
	plan := Parse("(git status > /tmp/out) | sh")

	if plan.Shape.Kind != ShellShapeCompound {
		t.Fatalf("Shape.Kind = %q, want %q", plan.Shape.Kind, ShellShapeCompound)
	}
	for _, flag := range []string{"pipeline", "subshell", "redirection"} {
		if !containsString(plan.Shape.Flags(), flag) {
			t.Fatalf("Shape.Flags() = %#v, want %q", plan.Shape.Flags(), flag)
		}
	}
	if !plan.Shape.HasPipeline || !plan.Shape.HasSubshell || !plan.Shape.HasRedirection {
		t.Fatalf("Shape flags not preserved: %+v", plan.Shape)
	}
	if EvaluationSafetyForPlan(plan).Safe {
		t.Fatalf("EvaluationSafetyForPlan(%q).Safe = true, want false", plan.Raw)
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
