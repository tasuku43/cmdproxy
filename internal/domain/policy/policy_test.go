package policy

import (
	"slices"
	"strconv"
	"testing"

	commandpkg "github.com/tasuku43/cc-bash-proxy/internal/domain/command"
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

func TestEvaluatePermissionUsesFinalRewrittenCommandOnly(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Rewrite: []RewriteStepSpec{{
			Match: MatchSpec{Command: "aws", ArgsContains: []string{"--profile"}},
			MoveFlagToEnv: MoveFlagToEnvSpec{
				Flag: "--profile",
				Env:  "AWS_PROFILE",
			},
		}},
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Pattern: `^aws --profile read-only `,
			}},
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", Subcommand: "sts", EnvRequires: []string{"AWS_PROFILE"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "aws --profile read-only sts get-caller-identity")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
	}
	if got.Command != "AWS_PROFILE=read-only aws sts get-caller-identity" {
		t.Fatalf("Command = %q, want final rewritten command", got.Command)
	}
}

func TestEvaluateRewriteTraceIncludesBeforeAfterSafety(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Rewrite: []RewriteStepSpec{{
			Match: MatchSpec{Command: "aws", ArgsContains: []string{"--profile"}},
			MoveFlagToEnv: MoveFlagToEnvSpec{
				Flag: "--profile",
				Env:  "AWS_PROFILE",
			},
		}},
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{Match: MatchSpec{Command: "aws", Subcommand: "sts", EnvRequires: []string{"AWS_PROFILE"}}}},
		},
	}, Source{})

	got, err := Evaluate(p, "aws --profile read-only sts get-caller-identity")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	step := firstTraceStepByName(got.Trace, "move_flag_to_env")
	if step == nil {
		t.Fatalf("rewrite trace missing; trace=%+v", got.Trace)
	}
	if step.FromShape != "simple" || step.ToShape != "simple" {
		t.Fatalf("rewrite shapes = (%q, %q), want simple/simple; trace=%+v", step.FromShape, step.ToShape, got.Trace)
	}
	if step.FromSafe == nil || step.ToSafe == nil || !*step.FromSafe || !*step.ToSafe {
		t.Fatalf("rewrite safety = (%v, %v), want true/true; trace=%+v", step.FromSafe, step.ToSafe, got.Trace)
	}
}

func TestRewriteInvariantDetectsSafeToUnsafeAndSimpleToCompound(t *testing.T) {
	before := commandpkg.Parse("git status")
	after := commandpkg.Parse("git status && echo $(rm -rf /tmp/x)")
	reasons := rewriteInvariantViolationReasons(
		before,
		commandpkg.EvaluationSafetyForPlan(before),
		after,
		commandpkg.EvaluationSafetyForPlan(after),
	)

	if !slices.Contains(reasons, "rewrite_simple_to_compound") {
		t.Fatalf("reasons=%#v, want rewrite_simple_to_compound", reasons)
	}
	if !slices.Contains(reasons, "rewrite_safe_to_unsafe") {
		t.Fatalf("reasons=%#v, want rewrite_safe_to_unsafe", reasons)
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

func TestEvaluateGitArgsContainsMatchesGlobalOptionRawWords(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Ask: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", ArgsContains: []string{"-C"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git -C repo status")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
}

func TestGenericParserSemanticGuardPreventsDenyToAllowRegression(t *testing.T) {
	plan := commandpkg.ParseWithRegistry("git -C repo status", commandpkg.NewCommandParserRegistry())
	if len(plan.Commands) != 1 {
		t.Fatalf("len(Commands) = %d, want 1", len(plan.Commands))
	}
	cmd := plan.Commands[0]
	if cmd.Parser != "generic" || cmd.SemanticParser != "" {
		t.Fatalf("parser state = (%q, %q), want generic/no semantic parser", cmd.Parser, cmd.SemanticParser)
	}

	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny:  []PermissionRuleSpec{{Match: MatchSpec{Command: "git", Subcommand: "status"}}},
			Allow: []PermissionRuleSpec{{Match: MatchSpec{Command: "git"}}},
		},
	}, Source{})

	got := evaluatePreparedCommand(p.prepared.Deny, p.prepared.Ask, p.prepared.Allow, cmd)
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

func TestPermissionRuleMatchesGitSemantic(t *testing.T) {
	tests := []struct {
		name    string
		command string
		match   MatchSpec
		want    bool
	}{
		{
			name:    "force push",
			command: "git push --force origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
			want:    true,
		},
		{
			name:    "status verb in",
			command: "git status",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{VerbIn: []string{"status", "diff", "log"}}},
			want:    true,
		},
		{
			name:    "destructive clean",
			command: "git clean -fdx",
			match: MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{
				Verb:           "clean",
				Force:          boolPtr(true),
				Recursive:      boolPtr(true),
				IncludeIgnored: boolPtr(true),
			}},
			want: true,
		},
		{
			name:    "normal push is not force",
			command: "git push origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
		},
		{
			name:    "wrong verb",
			command: "git status",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push"}},
		},
		{
			name:    "generic fallback does not satisfy semantic",
			command: "unknown status",
			match:   MatchSpec{Command: "unknown", Semantic: &SemanticMatchSpec{Verb: "status"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.match.MatchMatches(tt.command); got != tt.want {
				t.Fatalf("MatchMatches(%q)=%v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestMatchSpecGitSemanticRequiresGitParserData(t *testing.T) {
	match := MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}
	cmd := commandpkg.Command{
		Raw:      "git status",
		Program:  "git",
		RawWords: []string{"status"},
		Parser:   "generic",
	}
	if match.matches(cmd) {
		t.Fatal("generic parser command satisfied git semantic match")
	}
}

func TestEvaluateGitSemanticPermissionOutcomes(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
				Message: "force push is blocked",
			}},
			Ask: []PermissionRuleSpec{{
				Match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{VerbIn: []string{"push", "reset", "rebase", "clean"}}},
				Message: "dangerous git operation requires confirmation",
			}},
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{VerbIn: []string{"status", "diff", "log", "show", "branch"}}},
			}},
		},
	}, Source{})

	tests := []struct {
		command string
		want    string
	}{
		{command: "git push --force origin main", want: "deny"},
		{command: "git push origin main", want: "ask"},
		{command: "git status", want: "allow"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != tt.want {
				t.Fatalf("Outcome=%q, want %q; decision=%+v", got.Outcome, tt.want, got)
			}
		})
	}
}

func TestEvaluateTraceIncludesSemanticMatcherInfo(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git push --force origin main")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(got.Trace) == 0 {
		t.Fatalf("trace empty")
	}
	last := got.Trace[len(got.Trace)-1]
	if last.Parser != "git" || last.SemanticParser != "git" || !last.SemanticMatch {
		t.Fatalf("trace step missing parser/semantic info: %+v", last)
	}
	if !containsString(last.SemanticFields, "verb") || !containsString(last.SemanticFields, "force") {
		t.Fatalf("SemanticFields=%#v, want verb and force", last.SemanticFields)
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

func TestEvaluateRawDenyPatternBeatsCompositionAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Pattern: `^\s*git\s+status\s*&&\s*git\s+diff\s*$`,
				Message: "raw compound denied",
			}},
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "git", Subcommand: "status"}},
				{Match: MatchSpec{Command: "git", Subcommand: "diff"}},
			},
		},
	}, Source{})

	got, err := Evaluate(p, "git status && git diff")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "deny" {
		t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
	}
	if got.Message != "raw compound denied" {
		t.Fatalf("Message = %q, want raw deny message; decision=%+v", got.Message, got)
	}
	if steps := traceStepsByName(got.Trace, "composition"); len(steps) != 0 {
		t.Fatalf("composition trace steps = %d, want 0; trace=%+v", len(steps), got.Trace)
	}
	if last := got.Trace[len(got.Trace)-1]; last.RuleType != "raw" {
		t.Fatalf("rule_type=%q, want raw; trace=%+v", last.RuleType, got.Trace)
	}
}

func TestEvaluateRawAskPatternBeatsCompositionAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Ask: []PermissionRuleSpec{{
				Pattern: `^\s*git\s+status\s*&&\s*git\s+diff\s*$`,
				Message: "raw compound asks",
			}},
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "git", Subcommand: "status"}},
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
	if got.Message != "raw compound asks" {
		t.Fatalf("Message = %q, want raw ask message; decision=%+v", got.Message, got)
	}
	if steps := traceStepsByName(got.Trace, "composition"); len(steps) != 0 {
		t.Fatalf("composition trace steps = %d, want 0; trace=%+v", len(steps), got.Trace)
	}
	if last := got.Trace[len(got.Trace)-1]; last.RuleType != "raw" {
		t.Fatalf("rule_type=%q, want raw; trace=%+v", last.RuleType, got.Trace)
	}
}

func TestEvaluateUnsafeRawAllowPatternBeatsCompositionAsk(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Pattern:          `^\s*git\s+status\s*&&\s*rm\s+-rf\s+/tmp/x\s*$`,
				AllowUnsafeShell: true,
				Message:          "trusted full compound",
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status && rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
	}
	if got.Message != "trusted full compound" {
		t.Fatalf("Message = %q, want unsafe allow message; decision=%+v", got.Message, got)
	}
	if steps := traceStepsByName(got.Trace, "composition"); len(steps) != 0 {
		t.Fatalf("composition trace steps = %d, want 0; trace=%+v", len(steps), got.Trace)
	}
	if last := got.Trace[len(got.Trace)-1]; last.RuleType != "raw" {
		t.Fatalf("rule_type=%q, want raw; trace=%+v", last.RuleType, got.Trace)
	}
}

func TestEvaluateRawAllowPatternWithoutUnsafeShellDoesNotBypassComposition(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Pattern: `^\s*git\s+status\s*&&\s*rm\s+-rf\s+/tmp/x\s*$`,
			}},
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

func TestEvaluateRawAllowPatternWithoutUnsafeShellDoesNotAllowSimpleCommand(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Pattern: `^\s*git\s+status\s*$`,
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluateStructuredDenyBeatsUnsafeRawAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Match:   MatchSpec{Command: "rm"},
				Message: "rm denied",
			}},
			Allow: []PermissionRuleSpec{{
				Pattern:          `^\s*git\s+status\s*&&\s*rm\s+-rf\s+/tmp/x\s*$`,
				AllowUnsafeShell: true,
				Message:          "trusted full compound",
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status && rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "deny" {
		t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
	}
	if got.Message != "rm denied" {
		t.Fatalf("Message = %q, want structured deny message; decision=%+v", got.Message, got)
	}
	final := got.Trace[len(got.Trace)-1]
	if final.Name != "composition" || final.RuleType != "structured" {
		t.Fatalf("final trace=%+v, want structured composition; trace=%+v", final, got.Trace)
	}
}

func TestEvaluateStructuredAskBeatsUnsafeRawAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Ask: []PermissionRuleSpec{{
				Match:   MatchSpec{Command: "rm"},
				Message: "rm asks",
			}},
			Allow: []PermissionRuleSpec{{
				Pattern:          `^\s*git\s+status\s*&&\s*rm\s+-rf\s+/tmp/x\s*$`,
				AllowUnsafeShell: true,
				Message:          "trusted full compound",
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status && rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
	if got.Message != "rm asks" {
		t.Fatalf("Message = %q, want structured ask message; decision=%+v", got.Message, got)
	}
	final := got.Trace[len(got.Trace)-1]
	if final.Name != "composition" || final.RuleType != "structured" {
		t.Fatalf("final trace=%+v, want structured composition; trace=%+v", final, got.Trace)
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
			if final.Name != "composition" || final.Shape != "compound" || final.Effect != tt.wantOutcome || final.Reason != tt.wantReason {
				t.Fatalf("final composition trace=%+v, want effect=%q shape=compound reason=%q", final, tt.wantOutcome, tt.wantReason)
			}
			if !containsString(final.ShapeFlags, "conditional") {
				t.Fatalf("final composition shape_flags=%#v, want conditional; trace=%+v", final.ShapeFlags, got.Trace)
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

func TestEvaluateProcessSubstitutionCompositionDeniesExtractedCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		deny    PermissionRuleSpec
		wantCmd string
	}{
		{
			name:    "input process substitution",
			command: "cat <(rm -rf /tmp/x)",
			deny:    PermissionRuleSpec{Match: MatchSpec{Command: "rm", ArgsContains: []string{"-rf"}}},
			wantCmd: "rm -rf /tmp/x",
		},
		{
			name:    "output process substitution",
			command: "echo >(sh)",
			deny:    PermissionRuleSpec{Match: MatchSpec{Command: "sh"}},
			wantCmd: "sh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPipeline(PipelineSpec{
				Permission: PermissionSpec{Deny: []PermissionRuleSpec{tt.deny}},
			}, Source{})

			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "deny" {
				t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
			}
			steps := traceStepsByName(got.Trace, "composition.command")
			if len(steps) == 0 {
				t.Fatalf("composition.command trace missing; trace=%+v", got.Trace)
			}
			found := false
			for _, step := range steps {
				if step.Command == tt.wantCmd && step.Effect == "deny" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("denied process substitution command %q not found in trace; trace=%+v", tt.wantCmd, got.Trace)
			}
		})
	}
}

func TestEvaluateProcessSubstitutionAsksEvenWhenExtractedCommandsAllowed(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "cat"}},
				{Match: MatchSpec{Command: "git", Subcommand: "status"}},
			},
		},
	}, Source{})

	got, err := Evaluate(p, "cat <(git status)")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
	steps := traceStepsByName(got.Trace, "composition.command")
	if len(steps) != 2 {
		t.Fatalf("composition.command trace steps = %d, want 2; trace=%+v", len(steps), got.Trace)
	}
}

func TestEvaluateCompoundTraceIncludesLosslessShapeFlags(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "git", Subcommand: "status"}},
				{Match: MatchSpec{Command: "sh"}},
			},
		},
	}, Source{})

	got, err := Evaluate(p, "(git status > /tmp/out) | sh")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
	failClosed := firstTraceStepByName(got.Trace, "fail_closed")
	if failClosed == nil {
		t.Fatalf("fail_closed trace missing; trace=%+v", got.Trace)
	}
	for _, flag := range []string{"pipeline", "subshell", "redirection"} {
		if !containsString(failClosed.ShapeFlags, flag) {
			t.Fatalf("fail_closed shape_flags=%#v, want %q; trace=%+v", failClosed.ShapeFlags, flag, got.Trace)
		}
	}
	final := got.Trace[len(got.Trace)-1]
	if final.Name != "composition" || final.Shape != "compound" {
		t.Fatalf("final trace=%+v, want compound composition; trace=%+v", final, got.Trace)
	}
	for _, flag := range []string{"pipeline", "subshell", "redirection"} {
		if !containsString(final.ShapeFlags, flag) {
			t.Fatalf("final shape_flags=%#v, want %q; trace=%+v", final.ShapeFlags, flag, got.Trace)
		}
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

func firstTraceStepByName(trace []TraceStep, name string) *TraceStep {
	for i := range trace {
		if trace[i].Name == name {
			return &trace[i]
		}
	}
	return nil
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

func TestEvaluateSyntaxErrorFailsClosedBeforeAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Pattern:          `.*`,
				AllowUnsafeShell: true,
				Message:          "unsafe raw allow",
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status &&")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
	step := firstTraceStepByName(got.Trace, "fail_closed")
	if step == nil || step.Reason != "parse_error" {
		t.Fatalf("fail_closed trace=%+v, want parse_error; trace=%+v", step, got.Trace)
	}
	if last := got.Trace[len(got.Trace)-1]; last.Effect == "allow" {
		t.Fatalf("unexpected allow trace=%+v", got.Trace)
	}
}

func TestEvaluateUnsafeCommandStillAppliesRawDeny(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Pattern: `^\s*rm\s+-rf\s+/tmp/x\s*&&`,
				Message: "raw deny wins",
			}},
			Allow: []PermissionRuleSpec{{
				Pattern:          `.*`,
				AllowUnsafeShell: true,
				Message:          "unsafe raw allow",
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "rm -rf /tmp/x &&")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "deny" {
		t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
	}
	if got.Message != "raw deny wins" {
		t.Fatalf("Message = %q, want raw deny message; decision=%+v", got.Message, got)
	}
	step := firstTraceStepByName(got.Trace, "fail_closed")
	if step == nil || step.Reason != "parse_error" {
		t.Fatalf("fail_closed trace=%+v, want parse_error; trace=%+v", step, got.Trace)
	}
}

func TestEvaluateUnknownShapeIgnoresUnsafeRawAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Pattern:          `^\s*cat\s+<\(git\s+status\)\s*$`,
				AllowUnsafeShell: true,
				Message:          "unsafe raw allow",
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "cat <(git status)")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
	step := firstTraceStepByName(got.Trace, "fail_closed")
	if step == nil || step.Reason != "process_substitution" {
		t.Fatalf("fail_closed trace=%+v, want process_substitution; trace=%+v", step, got.Trace)
	}
	if !containsString(step.ShapeFlags, "process_substitution") {
		t.Fatalf("fail_closed shape_flags=%#v, want process_substitution; trace=%+v", step.ShapeFlags, got.Trace)
	}
	final := got.Trace[len(got.Trace)-1]
	if final.Name != "composition" || final.Effect != "ask" {
		t.Fatalf("final trace=%+v, want composition ask; trace=%+v", final, got.Trace)
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

func TestValidateSemanticMatchRules(t *testing.T) {
	tests := []struct {
		name  string
		spec  PipelineSpec
		issue string
	}{
		{
			name: "semantic without command",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].match.command must be set when semantic is used",
		},
		{
			name: "command_in with semantic",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{CommandIn: []string{"git", "gh"}, Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].match.command_in cannot be used with semantic",
		},
		{
			name: "non git command",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "ls", Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].match.semantic is only supported for command: git",
		},
		{
			name: "subcommand with semantic verb",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Subcommand: "push", Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].match.subcommand cannot be used with semantic.verb",
		},
		{
			name: "rewrite semantic",
			spec: PipelineSpec{Rewrite: []RewriteStepSpec{{
				Match:            MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push"}},
				StripCommandPath: true,
			}}},
			issue: "rewrite[0].match.semantic is not supported; semantic match is currently permission-only",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := ValidatePipeline(tt.spec)
			if !containsString(issues, tt.issue) {
				t.Fatalf("issues=%#v, want %q", issues, tt.issue)
			}
		})
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
