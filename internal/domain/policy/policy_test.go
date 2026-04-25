package policy

import (
	"strconv"
	"testing"
)

func TestEvaluateRewriteThenAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Rewrite: []RewriteStepSpec{{
			Match: MatchSpec{Command: "aws", ArgsContains: []string{"--profile"}},
			MoveFlagToEnv: MoveFlagToEnvSpec{
				Flag: "--profile",
				Env:  "AWS_PROFILE",
			},
			Test: RewriteTestSpec{
				{In: "aws --profile read-only sts get-caller-identity", Out: "AWS_PROFILE=read-only aws sts get-caller-identity"},
				{Pass: "AWS_PROFILE=read-only aws sts get-caller-identity"},
			},
		}},
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", Subcommand: "sts", EnvRequires: []string{"AWS_PROFILE"}},
				Test: PermissionTestSpec{
					Allow: []string{"AWS_PROFILE=read-only aws sts get-caller-identity"},
					Pass:  []string{"AWS_PROFILE=read-only aws s3 ls"},
				},
			}},
		},
		Test: PipelineTestSpec{{
			In:        "aws --profile read-only sts get-caller-identity",
			Rewritten: "AWS_PROFILE=read-only aws sts get-caller-identity",
			Decision:  "allow",
		}},
	}, Source{})

	got, err := Evaluate(p, "aws --profile read-only sts get-caller-identity")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" || got.Command != "AWS_PROFILE=read-only aws sts get-caller-identity" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluatePermissionPriorityDenyAskAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", ArgsContains: []string{"--delete"}},
				Test:  PermissionTestSpec{Deny: []string{"aws s3 rm --delete"}, Pass: []string{"aws s3 ls"}},
			}},
			Ask: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", Subcommand: "s3"},
				Test:  PermissionTestSpec{Ask: []string{"aws s3 ls"}, Pass: []string{"aws sts get-caller-identity"}},
			}},
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", Subcommand: "sts"},
				Test:  PermissionTestSpec{Allow: []string{"aws sts get-caller-identity"}, Pass: []string{"aws s3 ls"}},
			}},
		},
		Test: PipelineTestSpec{{In: "aws sts get-caller-identity", Decision: "allow"}},
	}, Source{})

	got, err := Evaluate(p, "aws s3 rm --delete")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "deny" {
		t.Fatalf("got %+v", got)
	}
	got, err = Evaluate(p, "aws s3 ls")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("got %+v", got)
	}
	got, err = Evaluate(p, "aws sts get-caller-identity")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluateGitArgsContainsUsesRawWordsForCompatibility(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Ask: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", ArgsContains: []string{"--short"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status --short")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
}

func TestValidatePipelineRequiresE2ETest(t *testing.T) {
	issues := ValidatePipeline(PipelineSpec{
		Rewrite: []RewriteStepSpec{{
			UnwrapShellDashC: true,
			Test: RewriteTestSpec{
				{In: "bash -c 'git status'", Out: "git status"},
				{Pass: "bash script.sh"},
			},
		}},
	})
	if len(issues) == 0 {
		t.Fatal("expected validation issues")
	}
}

func TestValidatePipelineRejectsUnknownClaudePermissionMergeMode(t *testing.T) {
	issues := ValidatePipeline(PipelineSpec{
		ClaudePermissionMergeMode: "loose",
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Subcommand: "status"},
				Test:  PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
			}},
		},
		Test: PipelineTestSpec{{In: "git status", Decision: "allow"}},
	})
	if len(issues) == 0 {
		t.Fatal("expected validation issues")
	}
}

func TestRewriteStepName(t *testing.T) {
	if got := RewriteStepName(RewriteStepSpec{StripCommandPath: true}); got != "strip_command_path" {
		t.Fatalf("got %q", got)
	}
}

func TestRewriteStepMatchesPattern(t *testing.T) {
	step := RewriteStepSpec{Pattern: `^\s*git\s+diff\s+.*\.\.\.`}
	if !RewriteStepMatches(step, "git diff main...HEAD") {
		t.Fatal("expected pattern match")
	}
	if RewriteStepMatches(step, "git diff HEAD~1") {
		t.Fatal("did not expect match")
	}
}

func TestPermissionRuleMatchesPatterns(t *testing.T) {
	rule := PermissionRuleSpec{
		Patterns: []string{
			`^\s*cd\s+[^&;|]+\s*&&`,
			`^\s*cd\s+[^&;|]+\s*;`,
		},
	}
	if !PermissionRuleMatches(rule, "cd repo && git status") {
		t.Fatal("expected patterns match")
	}
	if !PermissionRuleMatches(rule, "cd repo; make test") {
		t.Fatal("expected patterns match")
	}
	if PermissionRuleMatches(rule, "cd repo") {
		t.Fatal("did not expect match")
	}
}

func TestEvaluateStructuredAllowFailsClosedOnUnsafeShellExpressions(t *testing.T) {
	tests := []struct {
		name    string
		command string
		rule    PermissionRuleSpec
	}{
		{
			name:    "and list",
			command: "git status && rm -rf /tmp/x",
			rule:    PermissionRuleSpec{Match: MatchSpec{Command: "git", Subcommand: "status"}},
		},
		{
			name:    "semicolon list",
			command: "git status; rm -rf /tmp/x",
			rule:    PermissionRuleSpec{Match: MatchSpec{Command: "git", Subcommand: "status"}},
		},
		{
			name:    "pipe",
			command: "git status | sh",
			rule:    PermissionRuleSpec{Match: MatchSpec{Command: "git", Subcommand: "status"}},
		},
		{
			name:    "redirect",
			command: "git status > /tmp/out",
			rule:    PermissionRuleSpec{Match: MatchSpec{Command: "git", Subcommand: "status"}},
		},
		{
			name:    "comment",
			command: "git status # harmless-looking comment",
			rule:    PermissionRuleSpec{Match: MatchSpec{Command: "git", Subcommand: "status"}},
		},
		{
			name:    "bash c compound",
			command: "bash -c 'git status && rm -rf /tmp/x'",
			rule:    PermissionRuleSpec{Match: MatchSpec{Command: "bash", Subcommand: "-c"}},
		},
		{
			name:    "bash c redirect",
			command: "bash -c 'git status > /tmp/out'",
			rule:    PermissionRuleSpec{Match: MatchSpec{Command: "bash", Subcommand: "-c"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPipeline(PipelineSpec{
				Permission: PermissionSpec{
					Allow: []PermissionRuleSpec{tt.rule},
				},
			}, Source{})

			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "ask" {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestMatchSpecGitSubcommandMatchesGlobalOptionVariants(t *testing.T) {
	match := MatchSpec{Command: "git", Subcommand: "status"}
	tests := []string{
		"git status",
		"git -C repo status",
		"git --no-pager status",
		"git -c core.quotePath=false status",
		"git --git-dir .git --work-tree . status",
	}

	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			if !match.MatchMatches(command) {
				t.Fatalf("MatchMatches(%q) = false, want true", command)
			}
		})
	}
}

func TestEvaluateGitStatusAllowMatchesSupportedGlobalOptions(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Subcommand: "status"},
			}},
		},
	}, Source{})

	tests := []struct {
		name    string
		command string
	}{
		{name: "plain", command: "git status"},
		{name: "working directory", command: "git -C repo status"},
		{name: "working directory with status option", command: "git -C repo status --short"},
		{name: "config", command: "git -c core.quotePath=false status"},
		{name: "git dir separate", command: "git --git-dir .git status"},
		{name: "git dir equals", command: "git --git-dir=.git status"},
		{name: "work tree separate", command: "git --work-tree . status"},
		{name: "work tree equals", command: "git --work-tree=. status"},
		{name: "namespace separate", command: "git --namespace main status"},
		{name: "namespace equals", command: "git --namespace=main status"},
		{name: "no pager", command: "git --no-pager status"},
		{name: "bare", command: "git --bare status"},
		{name: "combined globals", command: "git -C repo -c core.quotePath=false --no-pager --git-dir .git --work-tree . --namespace main status --short"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "allow" {
				t.Fatalf("Evaluate(%q).Outcome = %q, want allow; decision=%+v", tt.command, got.Outcome, got)
			}
		})
	}
}

func TestEvaluateGitStatusAllowDoesNotMatchNonStatusOrUnsafeShell(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Subcommand: "status"},
			}},
		},
	}, Source{})

	tests := []struct {
		name    string
		command string
	}{
		{name: "different subcommand", command: "git -C repo diff"},
		{name: "double dash before status", command: "git -C repo -- status"},
		{name: "compound status and diff", command: "git status && git diff"},
		{name: "pipeline status", command: "git status | sh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "ask" {
				t.Fatalf("Evaluate(%q).Outcome = %q, want ask; decision=%+v", tt.command, got.Outcome, got)
			}
		})
	}
}

func TestEvaluateCompoundGitCommandsComposeIndividualCommandDecisions(t *testing.T) {
	gitRule := func(subcommand string) PermissionRuleSpec {
		return PermissionRuleSpec{Match: MatchSpec{Command: "git", Subcommand: subcommand}}
	}

	tests := []struct {
		name    string
		command string
		allow   []PermissionRuleSpec
		want    string
	}{
		{
			name:    "left allowed right not allowed",
			command: "git status && git diff",
			allow:   []PermissionRuleSpec{gitRule("status")},
			want:    "ask",
		},
		{
			name:    "left not allowed right allowed",
			command: "git status && git diff",
			allow:   []PermissionRuleSpec{gitRule("diff")},
			want:    "ask",
		},
		{
			name:    "both allowed and list",
			command: "git status && git diff",
			allow:   []PermissionRuleSpec{gitRule("status"), gitRule("diff")},
			want:    "allow",
		},
		{
			name:    "both allowed with git global options",
			command: "git -C repo status && git --no-pager diff",
			allow:   []PermissionRuleSpec{gitRule("status"), gitRule("diff")},
			want:    "allow",
		},
		{
			name:    "both allowed or list",
			command: "git status || git diff",
			allow:   []PermissionRuleSpec{gitRule("status"), gitRule("diff")},
			want:    "allow",
		},
		{
			name:    "both allowed sequence",
			command: "git status; git diff",
			allow:   []PermissionRuleSpec{gitRule("status"), gitRule("diff")},
			want:    "allow",
		},
		{
			name:    "both allowed pipeline",
			command: "git status | git diff",
			allow:   []PermissionRuleSpec{gitRule("status"), gitRule("diff")},
			want:    "allow",
		},
		{
			name:    "three command and list allowed",
			command: "git status && git diff && git log",
			allow:   []PermissionRuleSpec{gitRule("status"), gitRule("diff"), gitRule("log")},
			want:    "allow",
		},
		{
			name:    "four command sequence allowed",
			command: "git status; git diff; git log; git branch",
			allow:   []PermissionRuleSpec{gitRule("status"), gitRule("diff"), gitRule("log"), gitRule("branch")},
			want:    "allow",
		},
		{
			name:    "four command and list asks when one command is unknown",
			command: "git status && git diff && unknown-command && git log",
			allow:   []PermissionRuleSpec{gitRule("status"), gitRule("diff"), gitRule("log")},
			want:    "ask",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPipeline(PipelineSpec{
				Permission: PermissionSpec{Allow: tt.allow},
			}, Source{})

			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != tt.want {
				t.Fatalf("Evaluate(%q).Outcome = %q, want %q; decision=%+v", tt.command, got.Outcome, tt.want, got)
			}
		})
	}
}

func TestEvaluateCompoundDenyWinsOverAllowedCommands(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "git", Subcommand: "status"}},
			},
			Deny: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "rm"}},
			},
		},
	}, Source{})

	got, err := Evaluate(p, "git status && rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "deny" {
		t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluateCompoundAskWinsUnlessACommandIsDenied(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "git", Subcommand: "status"}},
			},
			Ask: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "git", Subcommand: "diff"}},
			},
		},
	}, Source{})

	got, err := Evaluate(p, "git status && git diff")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluateCompoundTraceIncludesPerCommandComposition(t *testing.T) {
	src := Source{Layer: "project", Path: "/repo/.cc-bash-proxy/cc-bash-proxy.yml"}
	gitRule := func(subcommand string) PermissionRuleSpec {
		return PermissionRuleSpec{Match: MatchSpec{Command: "git", Subcommand: subcommand}}
	}

	tests := []struct {
		name        string
		command     string
		permission  PermissionSpec
		wantOutcome string
		wantReason  string
		wantEffects []string
		wantRaws    []string
	}{
		{
			name:    "allowed git status and diff",
			command: "git status && git diff",
			permission: PermissionSpec{Allow: []PermissionRuleSpec{
				gitRule("status"),
				gitRule("diff"),
			}},
			wantOutcome: "allow",
			wantReason:  "all commands allowed",
			wantEffects: []string{"allow", "allow"},
			wantRaws:    []string{"git status", "git diff"},
		},
		{
			name:    "rm denied",
			command: "git status && rm -rf /tmp/x",
			permission: PermissionSpec{
				Allow: []PermissionRuleSpec{gitRule("status")},
				Deny:  []PermissionRuleSpec{{Match: MatchSpec{Command: "rm"}}},
			},
			wantOutcome: "deny",
			wantReason:  "command[1] denied",
			wantEffects: []string{"allow", "deny"},
			wantRaws:    []string{"git status", "rm -rf /tmp/x"},
		},
		{
			name:    "unknown command asks by default",
			command: "git status && unknown-command",
			permission: PermissionSpec{
				Allow: []PermissionRuleSpec{gitRule("status")},
			},
			wantOutcome: "ask",
			wantReason:  "command[1] asked",
			wantEffects: []string{"allow", "ask"},
			wantRaws:    []string{"git status", "unknown-command"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPipeline(PipelineSpec{Permission: tt.permission}, src)

			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != tt.wantOutcome {
				t.Fatalf("Outcome = %q, want %q; decision=%+v", got.Outcome, tt.wantOutcome, got)
			}

			commandSteps := traceStepsByName(got.Trace, "composition.command")
			if len(commandSteps) != len(tt.wantRaws) {
				t.Fatalf("composition command steps = %d, want %d; trace=%+v", len(commandSteps), len(tt.wantRaws), got.Trace)
			}
			for i, step := range commandSteps {
				if step.CommandIndex == nil || *step.CommandIndex != i {
					t.Fatalf("command step %d index=%v; trace=%+v", i, step.CommandIndex, got.Trace)
				}
				if step.Command != tt.wantRaws[i] {
					t.Fatalf("command step %d raw=%q, want %q; trace=%+v", i, step.Command, tt.wantRaws[i], got.Trace)
				}
				if step.Effect != tt.wantEffects[i] {
					t.Fatalf("command step %d effect=%q, want %q; trace=%+v", i, step.Effect, tt.wantEffects[i], got.Trace)
				}
				if step.Parser == "" || step.Program == "" {
					t.Fatalf("command step %d missing parser/program: %+v", i, step)
				}
				if i == 0 && len(step.ActionPath) != 1 {
					t.Fatalf("command step %d action_path=%#v, want one action", i, step.ActionPath)
				}
				if step.Effect != "ask" && step.Source == nil {
					t.Fatalf("command step %d source=nil, want matched rule source; trace=%+v", i, got.Trace)
				}
			}

			final := got.Trace[len(got.Trace)-1]
			if final.Name != "composition" || final.Shape != "and_list" || final.Effect != tt.wantOutcome || final.Reason != tt.wantReason {
				t.Fatalf("final composition trace=%+v, want effect=%q shape=and_list reason=%q", final, tt.wantOutcome, tt.wantReason)
			}
		})
	}
}

func TestEvaluateCompoundDoesNotInferAllowFromLeftSideRawRule(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "git", Subcommand: "status"}},
			},
		},
	}, Source{})

	got, err := Evaluate(p, "git status && rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluatePipelineCompositionAllowsWhenEveryCommandAllowed(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "git", Subcommand: "status"}},
				{Match: MatchSpec{Command: "sh"}},
			},
		},
	}, Source{})

	got, err := Evaluate(p, "git status | sh")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluateConservativeShellShapesAskEvenWhenCommandAllowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{name: "background", command: "git status &"},
		{name: "redirect", command: "git status > /tmp/out"},
		{name: "subshell", command: "(git status)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPipeline(PipelineSpec{
				Permission: PermissionSpec{
					Allow: []PermissionRuleSpec{{Match: MatchSpec{Command: "git", Subcommand: "status"}}},
				},
			}, Source{})

			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "ask" {
				t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
			}
		})
	}
}

func TestMatchSpecGitSubcommandDoesNotTreatDoubleDashBeforeStatusAsStatus(t *testing.T) {
	match := MatchSpec{Command: "git", Subcommand: "status"}
	if match.MatchMatches("git -C repo -- status") {
		t.Fatal("MatchMatches() = true, want false")
	}
}

func traceStepsByName(trace []TraceStep, name string) []TraceStep {
	var steps []TraceStep
	for _, step := range trace {
		if step.Name == name {
			steps = append(steps, step)
		}
	}
	return steps
}

func TestEvaluatePatternAllowFailsClosedOnUnsafeShellExpressions(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Pattern: `^\s*git\s+status\s*\|\s*sh$`,
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status | sh")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluatePatternAllowCanOptInToUnsafeShellExpressions(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Pattern:          `^\s*git\s+status\s*\|\s*sh$`,
				AllowUnsafeShell: true,
				Message:          "allow trusted pipeline",
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status | sh")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluatePatternsAllowCanOptInToUnsafeShellExpressions(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Patterns: []string{
					`^\s*git\s+status\s*\|\s*sh$`,
					`^\s*git\s+diff\s*\|\s*sh$`,
				},
				AllowUnsafeShell: true,
				Message:          "allow trusted pipelines",
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status | sh")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("got %+v", got)
	}
}

func TestValidatePermissionRuleRequiresMessageForUnsafeAllow(t *testing.T) {
	issues := ValidatePermissionRule("permission.allow[0]", PermissionRuleSpec{
		Pattern:          `^\s*git\s+status\s*\|\s*sh$`,
		AllowUnsafeShell: true,
		Test:             PermissionTestSpec{Allow: []string{"git status | sh"}, Pass: []string{"git status"}},
	}, "allow")
	if len(issues) == 0 {
		t.Fatal("expected validation issues")
	}
}

func TestEvaluateTraceIncludesMatchedRuleSource(t *testing.T) {
	src := Source{Layer: "project", Path: "/repo/.cc-bash-proxy/cc-bash-proxy.yml"}
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Subcommand: "status"},
			}},
		},
	}, src)

	got, err := Evaluate(p, "git status")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(got.Trace) == 0 {
		t.Fatalf("trace=%+v", got.Trace)
	}
	last := got.Trace[len(got.Trace)-1]
	if last.Source == nil || *last.Source != src {
		t.Fatalf("source=%+v want=%+v trace=%+v", last.Source, src, got.Trace)
	}
}

func BenchmarkEvaluateManyRegexRules(b *testing.B) {
	rules := make([]PermissionRuleSpec, 0, 250)
	for i := 0; i < 249; i++ {
		rules = append(rules, PermissionRuleSpec{Pattern: `^\s*cmd-` + fmtIntForBenchmark(i) + `\s+.*$`})
	}
	rules = append(rules, PermissionRuleSpec{Pattern: `^\s*git\s+status\s*$`})
	p := NewPipeline(PipelineSpec{Permission: PermissionSpec{Allow: rules}}, Source{})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decision, err := Evaluate(p, "git status")
		if err != nil {
			b.Fatal(err)
		}
		if decision.Outcome != "allow" {
			b.Fatalf("decision=%+v", decision)
		}
	}
}

func fmtIntForBenchmark(v int) string {
	return strconv.Itoa(v)
}
