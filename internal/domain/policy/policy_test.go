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

func TestPermissionRuleMatchesAWSSemantic(t *testing.T) {
	tests := []struct {
		name    string
		command string
		match   MatchSpec
		want    bool
	}{
		{
			name:    "identity check",
			command: "aws sts get-caller-identity",
			match:   MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity"}},
			want:    true,
		},
		{
			name:    "profile and region",
			command: "aws --profile prod --region ap-northeast-1 sts get-caller-identity",
			match:   MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Profile: "prod", Region: "ap-northeast-1"}},
			want:    true,
		},
		{
			name:    "wrong service operation",
			command: "aws sts get-caller-identity",
			match:   MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Service: "s3", Operation: "rm"}},
			want:    false,
		},
		{
			name:    "dry run unknown does not match true",
			command: "aws ec2 terminate-instances --instance-ids i-123",
			match:   MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{DryRun: boolPtr(true)}},
			want:    false,
		},
		{
			name:    "generic fallback does not satisfy aws semantic",
			command: "unknown sts get-caller-identity",
			match:   MatchSpec{Command: "unknown", Semantic: &SemanticMatchSpec{Service: "sts"}},
			want:    false,
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

func TestPermissionRuleMatchesKubectlSemantic(t *testing.T) {
	tests := []struct {
		name    string
		command string
		match   MatchSpec
		want    bool
	}{
		{
			name:    "get pods",
			command: "kubectl get pods",
			match:   MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Verb: "get", ResourceType: "pods"}},
			want:    true,
		},
		{
			name:    "namespace and context",
			command: "kubectl --namespace=prod --context=prod-cluster get pods",
			match:   MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Namespace: "prod", Context: "prod-cluster"}},
			want:    true,
		},
		{
			name:    "delete deployment force",
			command: "kubectl delete deployment/foo --force",
			match:   MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Verb: "delete", ResourceType: "deployment", Force: boolPtr(true)}},
			want:    true,
		},
		{
			name:    "wrong verb",
			command: "kubectl get pods",
			match:   MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Verb: "delete"}},
			want:    false,
		},
		{
			name:    "missing namespace",
			command: "kubectl get pods",
			match:   MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Namespace: "prod"}},
			want:    false,
		},
		{
			name:    "dry run absent",
			command: "kubectl apply -f deployment.yaml",
			match:   MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{DryRun: boolPtr(true)}},
			want:    false,
		},
		{
			name:    "generic fallback does not satisfy kubectl semantic",
			command: "unknown get pods",
			match:   MatchSpec{Command: "unknown", Semantic: &SemanticMatchSpec{Verb: "get"}},
			want:    false,
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

func TestPermissionRuleMatchesGhSemantic(t *testing.T) {
	tests := []struct {
		name    string
		command string
		match   MatchSpec
		want    bool
	}{
		{
			name:    "api get repos",
			command: "gh api repos/OWNER/REPO/pulls",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "api", Method: "GET", EndpointPrefix: "/repos/"}},
			want:    true,
		},
		{
			name:    "pr squash merge",
			command: "gh pr merge 123 --squash",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "pr", Verb: "merge", MergeStrategy: "squash"}},
			want:    true,
		},
		{
			name:    "run rerun failed",
			command: "gh run rerun 123 --failed",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "run", Verb: "rerun", Failed: boolPtr(true)}},
			want:    true,
		},
		{
			name:    "wrong api method",
			command: "gh api repos/OWNER/REPO/pulls",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "api", Method: "DELETE"}},
			want:    false,
		},
		{
			name:    "api method does not match pr",
			command: "gh pr view 123",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Method: "GET"}},
			want:    false,
		},
		{
			name:    "admin absent",
			command: "gh pr merge 123 --squash",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "pr", Verb: "merge", Admin: boolPtr(true)}},
			want:    false,
		},
		{
			name:    "wrong run verb",
			command: "gh run view 123",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "run", Verb: "delete"}},
			want:    false,
		},
		{
			name:    "generic fallback does not satisfy gh semantic",
			command: "unknown api repos/OWNER/REPO/pulls",
			match:   MatchSpec{Command: "unknown", Semantic: &SemanticMatchSpec{Area: "api"}},
			want:    false,
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

func TestPermissionRuleMatchesHelmfileSemantic(t *testing.T) {
	tests := []struct {
		name    string
		command string
		match   MatchSpec
		want    bool
	}{
		{
			name:    "sync prod",
			command: "helmfile -e prod sync",
			match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Verb: "sync", Environment: "prod"}},
			want:    true,
		},
		{
			name:    "selector contains",
			command: "helmfile --selector app=foo apply",
			match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Verb: "apply", SelectorContains: []string{"app=foo"}}},
			want:    true,
		},
		{
			name:    "destroy non interactive",
			command: "helmfile destroy",
			match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Verb: "destroy", Interactive: boolPtr(false)}},
			want:    true,
		},
		{
			name:    "wrong verb",
			command: "helmfile diff",
			match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Verb: "sync"}},
			want:    false,
		},
		{
			name:    "missing environment",
			command: "helmfile sync",
			match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Environment: "prod"}},
			want:    false,
		},
		{
			name:    "selector not missing",
			command: "helmfile -l app=foo sync",
			match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{SelectorMissing: boolPtr(true)}},
			want:    false,
		},
		{
			name:    "generic fallback does not satisfy helmfile semantic",
			command: "unknown sync",
			match:   MatchSpec{Command: "unknown", Semantic: &SemanticMatchSpec{Environment: "prod"}},
			want:    false,
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

func TestMatchSpecAWSSemanticRequiresAWSParserData(t *testing.T) {
	match := MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Service: "sts"}}
	cmd := commandpkg.Command{
		Raw:      "aws sts get-caller-identity",
		Program:  "aws",
		RawWords: []string{"sts", "get-caller-identity"},
		Parser:   "generic",
	}
	if match.matches(cmd) {
		t.Fatal("generic parser command satisfied aws semantic match")
	}
}

func TestMatchSpecGhSemanticRequiresGhParserData(t *testing.T) {
	match := MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "api"}}
	cmd := commandpkg.Command{
		Raw:      "gh api repos/OWNER/REPO/pulls",
		Program:  "gh",
		RawWords: []string{"api", "repos/OWNER/REPO/pulls"},
		Parser:   "generic",
	}
	if match.matches(cmd) {
		t.Fatal("generic parser command satisfied gh semantic match")
	}
}

func TestMatchSpecHelmfileSemanticRequiresHelmfileParserData(t *testing.T) {
	match := MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Environment: "prod"}}
	cmd := commandpkg.Command{
		Raw:      "helmfile -e prod sync",
		Program:  "helmfile",
		RawWords: []string{"-e", "prod", "sync"},
		Parser:   "generic",
	}
	if match.matches(cmd) {
		t.Fatal("generic parser command satisfied helmfile semantic match")
	}
}

func TestEvaluateGhSemanticPermissionOutcomes(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{
				{
					Match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "pr", Verb: "merge", Admin: boolPtr(true)}},
					Message: "admin PR merge is blocked",
				},
				{
					Match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "run", VerbIn: []string{"delete", "cancel"}}},
					Message: "workflow run deletion/cancellation is blocked",
				},
			},
			Ask: []PermissionRuleSpec{
				{
					Match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "pr", VerbIn: []string{"create", "merge", "close", "reopen", "review", "ready", "update-branch"}}},
					Message: "PR mutation requires confirmation",
				},
				{
					Match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "run", Verb: "rerun"}},
					Message: "workflow rerun requires confirmation",
				},
				{
					Match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "api", MethodIn: []string{"POST", "PUT", "PATCH", "DELETE"}}},
					Message: "GitHub API mutation requires confirmation",
				},
			},
			Allow: []PermissionRuleSpec{
				{Match: MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "pr", VerbIn: []string{"view", "list", "diff", "status", "checks"}}}},
				{Match: MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "run", VerbIn: []string{"view", "list", "watch"}}}},
				{Match: MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "api", Method: "GET", EndpointPrefix: "/repos/"}}},
			},
		},
	}, Source{})

	tests := []struct {
		command string
		want    string
	}{
		{command: "gh pr view 123", want: "allow"},
		{command: "gh pr merge 123 --squash", want: "ask"},
		{command: "gh pr merge 123 --admin", want: "deny"},
		{command: "gh api repos/OWNER/REPO/pulls", want: "allow"},
		{command: "gh api -X PATCH repos/OWNER/REPO/pulls/123", want: "ask"},
		{command: "gh run delete 123", want: "deny"},
		{command: "gh run rerun 123 --failed", want: "ask"},
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

func TestEvaluateAWSSemanticPermissionOutcomes(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Match:   MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Service: "s3", OperationIn: []string{"rm", "rb", "delete-object", "delete-bucket"}}},
				Message: "destructive S3 operation is blocked",
			}},
			Ask: []PermissionRuleSpec{{
				Match:   MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{ServiceIn: []string{"iam"}}},
				Message: "AWS control-plane operation requires confirmation",
			}},
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity"}},
			}},
		},
	}, Source{})

	tests := []struct {
		command string
		want    string
	}{
		{command: "aws sts get-caller-identity", want: "allow"},
		{command: "aws s3 rm s3://bucket/key", want: "deny"},
		{command: "aws iam list-roles", want: "ask"},
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

func TestMatchSpecKubectlSemanticRequiresKubectlParserData(t *testing.T) {
	match := MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Verb: "get"}}
	cmd := commandpkg.Command{
		Raw:      "kubectl get pods",
		Program:  "kubectl",
		RawWords: []string{"get", "pods"},
		Parser:   "generic",
	}
	if match.matches(cmd) {
		t.Fatal("generic parser command satisfied kubectl semantic match")
	}
}

func TestEvaluateKubectlSemanticPermissionOutcomes(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Match:   MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Verb: "delete", ResourceType: "pod", Namespace: "prod"}},
				Message: "deleting production Kubernetes resources is blocked",
			}},
			Ask: []PermissionRuleSpec{{
				Match:   MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{VerbIn: []string{"apply", "patch", "scale", "rollout", "delete"}}},
				Message: "Kubernetes mutation requires confirmation",
			}},
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{VerbIn: []string{"get", "describe", "logs"}, Namespace: "default"}},
			}},
		},
	}, Source{})

	tests := []struct {
		command string
		want    string
	}{
		{command: "kubectl -n prod delete pod/foo", want: "deny"},
		{command: "kubectl apply -f deployment.yaml", want: "ask"},
		{command: "kubectl get pods -n default", want: "allow"},
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

func TestEvaluateHelmfileSemanticPermissionOutcomes(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{
				{
					Match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{VerbIn: []string{"sync", "apply", "destroy", "delete"}, EnvironmentIn: []string{"prod", "production"}, Interactive: boolPtr(false)}},
					Message: "non-interactive helmfile mutation in production is blocked",
				},
				{
					Match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Verb: "destroy", EnvironmentIn: []string{"prod", "production"}}},
					Message: "helmfile destroy in production is blocked",
				},
			},
			Ask: []PermissionRuleSpec{
				{
					Match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{VerbIn: []string{"sync", "apply", "destroy", "delete"}}},
					Message: "helmfile mutation requires confirmation",
				},
				{
					Match:   MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Verb: "sync", SelectorMissing: boolPtr(true)}},
					Message: "helmfile sync without selector requires confirmation",
				},
			},
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{VerbIn: []string{"diff", "template", "build", "list", "lint", "status"}}},
			}},
		},
	}, Source{})

	tests := []struct {
		command string
		want    string
	}{
		{command: "helmfile -e prod sync", want: "deny"},
		{command: "helmfile sync", want: "ask"},
		{command: "helmfile diff", want: "allow"},
		{command: "helmfile -e prod destroy", want: "deny"},
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

func TestEvaluateTraceIncludesHelmfileSemanticInfo(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Verb: "sync", Environment: "prod", File: "helmfile.prod.yaml", Namespace: "prod", KubeContext: "prod-cluster", SelectorContains: []string{"app=foo"}, Interactive: boolPtr(false)}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "helmfile -e prod -f helmfile.prod.yaml --kube-context prod-cluster -n prod -l app=foo sync")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(got.Trace) == 0 {
		t.Fatalf("trace empty")
	}
	last := got.Trace[len(got.Trace)-1]
	if last.Parser != "helmfile" || last.SemanticParser != "helmfile" || !last.SemanticMatch {
		t.Fatalf("trace step missing parser/semantic info: %+v", last)
	}
	if last.HelmfileVerb != "sync" || last.HelmfileEnvironment != "prod" || last.HelmfileFile != "helmfile.prod.yaml" || last.HelmfileNamespace != "prod" || last.HelmfileKubeContext != "prod-cluster" || last.HelmfileInteractive == nil || *last.HelmfileInteractive {
		t.Fatalf("trace step missing helmfile semantic info: %+v", last)
	}
	if !containsString(last.HelmfileSelectors, "app=foo") {
		t.Fatalf("HelmfileSelectors=%#v, want app=foo", last.HelmfileSelectors)
	}
	for _, field := range []string{"verb", "environment", "file", "namespace", "kube_context", "selector_contains", "interactive"} {
		if !containsString(last.SemanticFields, field) {
			t.Fatalf("SemanticFields=%#v, want %q", last.SemanticFields, field)
		}
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

func TestEvaluateTraceIncludesAWSSemanticInfo(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity", Profile: "prod", Region: "ap-northeast-1"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "aws --profile prod --region ap-northeast-1 sts get-caller-identity")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(got.Trace) == 0 {
		t.Fatalf("trace empty")
	}
	last := got.Trace[len(got.Trace)-1]
	if last.Parser != "aws" || last.SemanticParser != "aws" || !last.SemanticMatch {
		t.Fatalf("trace step missing parser/semantic info: %+v", last)
	}
	if last.AWSService != "sts" || last.AWSOperation != "get-caller-identity" || last.AWSProfile != "prod" || last.AWSRegion != "ap-northeast-1" {
		t.Fatalf("trace step missing aws semantic info: %+v", last)
	}
	for _, field := range []string{"service", "operation", "profile", "region"} {
		if !containsString(last.SemanticFields, field) {
			t.Fatalf("SemanticFields=%#v, want %q", last.SemanticFields, field)
		}
	}
}

func TestEvaluateTraceIncludesKubectlSemanticInfo(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Verb: "get", ResourceType: "pods", Namespace: "default", Context: "dev"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "kubectl --context dev get pods -n default")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(got.Trace) == 0 {
		t.Fatalf("trace empty")
	}
	last := got.Trace[len(got.Trace)-1]
	if last.Parser != "kubectl" || last.SemanticParser != "kubectl" || !last.SemanticMatch {
		t.Fatalf("trace step missing parser/semantic info: %+v", last)
	}
	if last.KubectlVerb != "get" || last.KubectlResourceType != "pods" || last.KubectlNamespace != "default" || last.KubectlContext != "dev" {
		t.Fatalf("trace step missing kubectl semantic info: %+v", last)
	}
	for _, field := range []string{"verb", "resource_type", "namespace", "context"} {
		if !containsString(last.SemanticFields, field) {
			t.Fatalf("SemanticFields=%#v, want %q", last.SemanticFields, field)
		}
	}
}

func TestEvaluateTraceIncludesGhSemanticInfo(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "api", Method: "GET", EndpointPrefix: "/repos/", Repo: "owner/repo"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "gh --repo owner/repo api repos/OWNER/REPO/pulls")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(got.Trace) == 0 {
		t.Fatalf("trace empty")
	}
	last := got.Trace[len(got.Trace)-1]
	if last.Parser != "gh" || last.SemanticParser != "gh" || !last.SemanticMatch {
		t.Fatalf("trace step missing parser/semantic info: %+v", last)
	}
	if last.GhArea != "api" || last.GhRepo != "owner/repo" || last.GhMethod != "GET" || last.GhEndpoint != "/repos/OWNER/REPO/pulls" {
		t.Fatalf("trace step missing gh semantic info: %+v", last)
	}
	for _, field := range []string{"area", "method", "endpoint_prefix", "repo"} {
		if !containsString(last.SemanticFields, field) {
			t.Fatalf("SemanticFields=%#v, want %q", last.SemanticFields, field)
		}
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
		want    string
	}{
		{name: "different subcommand", command: "git -C repo diff", want: "abstain"},
		{name: "double dash before status", command: "git -C repo -- status", want: "abstain"},
		{name: "compound status and diff", command: "git status && git diff", want: "ask"},
		{name: "pipeline status", command: "git status | sh", want: "ask"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	if got.Outcome != "abstain" {
		t.Fatalf("Outcome = %q, want abstain; decision=%+v", got.Outcome, got)
	}
	if got.Explicit {
		t.Fatalf("Explicit = true, want false; decision=%+v", got)
	}
	if got.Reason != "no_match" {
		t.Fatalf("Reason = %q, want no_match; decision=%+v", got.Reason, got)
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
			issue: "permission.deny[0].match.semantic is only supported for command: git, command: aws, command: kubectl, command: gh, or command: helmfile",
		},
		{
			name: "git command with aws semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Service: "sts"}},
			}}}},
			issue: "permission.deny[0].match.semantic contains fields not supported for command: git",
		},
		{
			name: "aws command with git semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].match.semantic contains fields not supported for command: aws",
		},
		{
			name: "aws command with kubectl semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Namespace: "prod"}},
			}}}},
			issue: "permission.deny[0].match.semantic contains fields not supported for command: aws",
		},
		{
			name: "kubectl command with aws semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "kubectl", Semantic: &SemanticMatchSpec{Service: "s3"}},
			}}}},
			issue: "permission.deny[0].match.semantic contains fields not supported for command: kubectl",
		},
		{
			name: "subcommand with semantic verb",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Subcommand: "push", Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].match.subcommand cannot be used with semantic",
		},
		{
			name: "git command with gh semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Area: "api"}},
			}}}},
			issue: "permission.deny[0].match.semantic contains fields not supported for command: git",
		},
		{
			name: "gh command with aws semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Service: "sts"}},
			}}}},
			issue: "permission.deny[0].match.semantic contains fields not supported for command: gh",
		},
		{
			name: "gh subcommand with semantic",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "gh", Subcommand: "api", Semantic: &SemanticMatchSpec{Area: "api"}},
			}}}},
			issue: "permission.deny[0].match.subcommand cannot be used with semantic",
		},
		{
			name: "git command with helmfile semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Environment: "prod"}},
			}}}},
			issue: "permission.deny[0].match.semantic contains fields not supported for command: git",
		},
		{
			name: "helmfile command with aws semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "helmfile", Semantic: &SemanticMatchSpec{Service: "sts"}},
			}}}},
			issue: "permission.deny[0].match.semantic contains fields not supported for command: helmfile",
		},
		{
			name: "helmfile subcommand with semantic",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Match: MatchSpec{Command: "helmfile", Subcommand: "sync", Semantic: &SemanticMatchSpec{Verb: "sync"}},
			}}}},
			issue: "permission.deny[0].match.subcommand cannot be used with semantic",
		},
		{
			name: "rewrite semantic",
			spec: PipelineSpec{Rewrite: []RewriteStepSpec{{
				Match:            MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "api"}},
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
