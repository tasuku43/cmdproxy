package policy

import "testing"

func TestEvaluateFirstMatchWins(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{ID: "first", Pattern: "^git", Reject: RejectSpec{Message: "first", Test: RejectTestSpec{Expect: []string{"git status"}, Pass: []string{"echo ok"}}}}, Source{}),
		NewRule(RuleSpec{ID: "second", Pattern: "status$", Reject: RejectSpec{Message: "second", Test: RejectTestSpec{Expect: []string{"git status"}, Pass: []string{"echo ok"}}}}, Source{}),
	}

	got, err := Evaluate(rules, "git status")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "reject" || got.Rule == nil || got.Rule.ID != "first" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluatePredicateRule(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{
			ID: "no-shell-dash-c",
			Matcher: MatchSpec{
				CommandIn:    []string{"bash", "sh"},
				ArgsContains: []string{"-c"},
			},
			Reject: RejectSpec{
				Message: "blocked",
				Test: RejectTestSpec{
					Expect: []string{"bash -c 'echo hi'"},
					Pass:   []string{"bash script.sh"},
				},
			},
		}, Source{}),
	}

	got, err := Evaluate(rules, "/usr/bin/env bash -c 'echo hi'")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "reject" || got.Rule == nil || got.Rule.ID != "no-shell-dash-c" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluateRewriteRule(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{
			ID: "unwrap-shell-dash-c",
			Matcher: MatchSpec{
				CommandIn:    []string{"bash", "sh"},
				ArgsContains: []string{"-c"},
			},
			Rewrite: RewriteSpec{
				UnwrapShellDashC: true,
				Test: RewriteTestSpec{
					Expect: []RewriteExpectCase{{In: "bash -c 'git status'", Out: "git status"}},
					Pass:   []string{"bash script.sh"},
				},
			},
		}, Source{}),
	}

	got, err := Evaluate(rules, "bash -c 'git status'")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "rewrite" || got.Command != "git status" {
		t.Fatalf("got %+v", got)
	}
	if len(got.Trace) != 1 || got.Trace[0].RuleID != "unwrap-shell-dash-c" || got.Trace[0].Action != "rewrite" {
		t.Fatalf("trace = %+v", got.Trace)
	}
}

func TestEvaluateRewriteContinueReevaluatesFromTop(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{
			ID: "unwrap-shell-dash-c",
			Matcher: MatchSpec{
				CommandIn:    []string{"bash", "sh"},
				ArgsContains: []string{"-c"},
			},
			Rewrite: RewriteSpec{
				UnwrapShellDashC: true,
				Continue:         true,
				Test: RewriteTestSpec{
					Expect: []RewriteExpectCase{{In: "bash -c 'git -C repo status'", Out: "git -C repo status"}},
					Pass:   []string{"bash script.sh"},
				},
			},
		}, Source{}),
		NewRule(RuleSpec{
			ID: "no-git-dash-c",
			Matcher: MatchSpec{
				Command:      "git",
				ArgsContains: []string{"-C"},
			},
			Reject: RejectSpec{
				Message: "blocked",
				Test: RejectTestSpec{
					Expect: []string{"git -C repo status"},
					Pass:   []string{"git status"},
				},
			},
		}, Source{}),
	}

	got, err := Evaluate(rules, "bash -c 'git -C repo status'")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "reject" || got.Rule == nil || got.Rule.ID != "no-git-dash-c" {
		t.Fatalf("got %+v", got)
	}
	if len(got.Trace) != 2 || got.Trace[0].RuleID != "unwrap-shell-dash-c" || got.Trace[1].RuleID != "no-git-dash-c" {
		t.Fatalf("trace = %+v", got.Trace)
	}
}

func TestEvaluateRewriteFailureFallsThrough(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{
			ID: "unwrap-shell-dash-c",
			Matcher: MatchSpec{
				CommandIn:    []string{"bash", "sh"},
				ArgsContains: []string{"-c"},
			},
			Rewrite: RewriteSpec{
				UnwrapShellDashC: true,
				Test: RewriteTestSpec{
					Expect: []RewriteExpectCase{{In: "bash -c 'git status'", Out: "git status"}},
					Pass:   []string{"bash script.sh"},
				},
			},
		}, Source{}),
		NewRule(RuleSpec{
			ID: "no-shell-dash-c",
			Matcher: MatchSpec{
				CommandIn:    []string{"bash", "sh"},
				ArgsContains: []string{"-c"},
			},
			Reject: RejectSpec{
				Message: "blocked",
				Test: RejectTestSpec{
					Expect: []string{"bash -c 'git status && git diff'"},
					Pass:   []string{"bash script.sh"},
				},
			},
		}, Source{}),
	}

	got, err := Evaluate(rules, "bash -c 'git status && git diff'")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "reject" || got.Rule == nil || got.Rule.ID != "no-shell-dash-c" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluateMoveFlagToEnvRewriteRule(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{
			ID: "aws-profile-to-env",
			Matcher: MatchSpec{
				Command:      "aws",
				ArgsContains: []string{"--profile"},
			},
			Rewrite: RewriteSpec{
				MoveFlagToEnv: MoveFlagToEnvSpec{
					Flag: "--profile",
					Env:  "AWS_PROFILE",
				},
				Test: RewriteTestSpec{
					Expect: []RewriteExpectCase{{In: "aws --profile read-only-profile s3 ls", Out: "AWS_PROFILE=read-only-profile aws s3 ls"}},
					Pass:   []string{"AWS_PROFILE=read-only-profile aws s3 ls"},
				},
			},
		}, Source{}),
	}

	got, err := Evaluate(rules, "aws --profile read-only-profile s3 ls")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "rewrite" || got.Command != "AWS_PROFILE=read-only-profile aws s3 ls" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluateMoveEnvToFlagRewriteRule(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{
			ID: "aws-env-to-profile",
			Matcher: MatchSpec{
				Command:     "aws",
				EnvRequires: []string{"AWS_PROFILE"},
			},
			Rewrite: RewriteSpec{
				MoveEnvToFlag: MoveEnvToFlagSpec{
					Env:  "AWS_PROFILE",
					Flag: "--profile",
				},
				Test: RewriteTestSpec{
					Expect: []RewriteExpectCase{{In: "AWS_PROFILE=read-only-profile aws s3 ls", Out: "aws --profile read-only-profile s3 ls"}},
					Pass:   []string{"aws --profile read-only-profile s3 ls"},
				},
			},
		}, Source{}),
	}

	got, err := Evaluate(rules, "AWS_PROFILE=read-only-profile aws s3 ls")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "rewrite" || got.Command != "aws --profile read-only-profile s3 ls" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluateUnwrapWrapperRewriteRule(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{
			ID:      "unwrap-safe-wrappers",
			Pattern: `^\s*(env|command|exec)\b`,
			Rewrite: RewriteSpec{
				UnwrapWrapper: UnwrapWrapperSpec{
					Wrappers: []string{"env", "command", "exec"},
				},
				Test: RewriteTestSpec{
					Expect: []RewriteExpectCase{{In: "env AWS_PROFILE=dev command exec aws s3 ls", Out: "AWS_PROFILE=dev aws s3 ls"}},
					Pass:   []string{"AWS_PROFILE=dev aws s3 ls"},
				},
			},
		}, Source{}),
	}

	got, err := Evaluate(rules, "env AWS_PROFILE=dev command exec aws s3 ls")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "rewrite" || got.Command != "AWS_PROFILE=dev aws s3 ls" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluateStripCommandPathRewriteRule(t *testing.T) {
	rules := []Rule{
		NewRule(RuleSpec{
			ID: "strip-command-path",
			Matcher: MatchSpec{
				CommandIsAbsolutePath: true,
			},
			Rewrite: RewriteSpec{
				StripCommandPath: true,
				Test: RewriteTestSpec{
					Expect: []RewriteExpectCase{{In: "/bin/ls -R foo", Out: "ls -R foo"}},
					Pass:   []string{"ls -R foo"},
				},
			},
		}, Source{}),
	}

	got, err := Evaluate(rules, "/bin/ls -R foo")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "rewrite" || got.Command != "ls -R foo" {
		t.Fatalf("got %+v", got)
	}
}

func TestMatchAbsoluteCommandPath(t *testing.T) {
	rule := NewRule(RuleSpec{
		ID: "absolute-command-only",
		Matcher: MatchSpec{
			CommandIsAbsolutePath: true,
		},
		Reject: RejectSpec{
			Message: "blocked",
			Test: RejectTestSpec{
				Expect: []string{"/bin/ls -R foo"},
				Pass:   []string{"ls -R foo"},
			},
		},
	}, Source{})

	matched, err := rule.Match("/bin/ls -R foo")
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if !matched {
		t.Fatal("expected absolute-path command to match")
	}

	matched, err = rule.Match("ls -R foo")
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if matched {
		t.Fatal("expected bare command not to match")
	}
}

func TestValidateDirectiveKinds(t *testing.T) {
	issues := ValidateDirective("rules[0]", RejectSpec{Message: "new"}, RewriteSpec{UnwrapShellDashC: true})
	if len(issues) != 1 {
		t.Fatalf("issues = %#v", issues)
	}
}

func TestValidateRewriteRejectsMultiplePrimitives(t *testing.T) {
	issues := ValidateRewrite("rules[0].rewrite", RewriteSpec{
		UnwrapShellDashC: true,
		MoveFlagToEnv: MoveFlagToEnvSpec{
			Flag: "--profile",
			Env:  "AWS_PROFILE",
		},
		Test: RewriteTestSpec{
			Expect: []RewriteExpectCase{{In: "aws --profile prod s3 ls", Out: "AWS_PROFILE=prod aws s3 ls"}},
			Pass:   []string{"AWS_PROFILE=prod aws s3 ls"},
		},
	})
	if len(issues) != 1 || issues[0] != "rules[0].rewrite must set exactly one rewrite primitive" {
		t.Fatalf("issues = %#v", issues)
	}
}
