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

func TestMatchSpecGitSubcommandDoesNotTreatDoubleDashBeforeStatusAsStatus(t *testing.T) {
	match := MatchSpec{Command: "git", Subcommand: "status"}
	if match.MatchMatches("git -C repo -- status") {
		t.Fatal("MatchMatches() = true, want false")
	}
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
