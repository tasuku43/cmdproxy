package policy

import "testing"

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
