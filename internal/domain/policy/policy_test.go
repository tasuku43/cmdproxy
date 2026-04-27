package policy

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	commandpkg "github.com/tasuku43/cc-bash-guard/internal/domain/command"
	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
)

func TestEvaluateAWSProfileSemanticDoesNotRewriteCommand(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity", Profile: "read-only"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "aws --profile read-only sts get-caller-identity")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" || got.Command != "aws --profile read-only sts get-caller-identity" {
		t.Fatalf("got %+v", got)
	}
	last := got.Trace[len(got.Trace)-1]
	if last.AWSProfile != "read-only" {
		t.Fatalf("AWSProfile = %q, want read-only; trace=%+v", last.AWSProfile, got.Trace)
	}
}

func TestEvaluatePermissionUsesOriginalCommandForRawPatterns(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Patterns: []string{`^aws --profile read-only `},
			}},
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "sts"}},
				Env:     PermissionEnvSpec{Requires: []string{"AWS_PROFILE"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "aws --profile read-only sts get-caller-identity")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "deny" {
		t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluatePatternsMatchShellDashCInnerCommand(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Name:     "aws without AWS_PROFILE env",
				Patterns: []string{`^\s*aws(\s|$)`},
				Env: PermissionEnvSpec{
					Missing: []string{"AWS_PROFILE"},
				},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "bash -c 'aws s3 ls'")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "deny" {
		t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
	}
	last := got.Trace[len(got.Trace)-1]
	if last.Name != "aws without AWS_PROFILE env" || last.RuleType != permissionRuleTypeRaw || last.Command != "aws s3 ls" || last.Program != "aws" {
		t.Fatalf("last trace = %+v, want raw patterns match against inner aws command", last)
	}
}

func TestEvaluatePatternsEnvUsesShellDashCInnerCommandEnv(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Patterns: []string{`^\s*aws(\s|$)`},
				Env: PermissionEnvSpec{
					Missing: []string{"AWS_PROFILE"},
				},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "bash -c 'AWS_PROFILE=dev aws s3 ls'")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome == "deny" {
		t.Fatalf("Outcome = deny, want env-scoped patterns rule not to match; decision=%+v", got)
	}
}

func TestEvaluateShellDashCBuiltInEvaluationAllowsInnerCommand(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}},
			}},
		},
	}, Source{})

	commands := []string{
		"git status",
		"bash -c 'git status'",
		"sh -c 'git status'",
		"/bin/bash -c 'git status'",
		"env bash -c 'git status'",
		"/usr/bin/env bash -c 'git status'",
		"command bash -c 'git status'",
		"exec sh -c 'git status'",
		"sudo bash -c 'git status'",
		"sudo -u root bash -c 'git status'",
		"nohup bash -c 'git status'",
		"timeout 10 bash -c 'git status'",
		"busybox sh -c 'git status'",
	}

	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			got, err := Evaluate(p, command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "allow" {
				t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
			}
			if got.Command != command {
				t.Fatalf("Command = %q, want original %q", got.Command, command)
			}
		})
	}
}

func TestEvaluateShellDashCNonDashCPassThrough(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}},
			}},
		},
	}, Source{})

	for _, command := range []string{"bash script.sh", "sh script.sh", "env bash script.sh"} {
		t.Run(command, func(t *testing.T) {
			got, err := Evaluate(p, command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome == "allow" {
				t.Fatalf("Outcome = allow, want not allow; decision=%+v", got)
			}
		})
	}
}

func TestEvaluateShellDashCCompoundDenyWins(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Patterns: []string{`^rm\s+`},
			}},
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "bash -c 'git status && rm -rf /tmp/x'")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "deny" {
		t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluateShellDashCParseErrorFailsClosed(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Patterns: []string{`^echo\s+`},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "bash -c 'echo $('")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome == "allow" {
		t.Fatalf("Outcome = allow, want fail closed; decision=%+v", got)
	}
}

func TestEvaluateAbsolutePathCommandNameMatchesSemanticRule(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "/usr/bin/git status")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
	}
	found := false
	for _, step := range got.Trace {
		if step.ProgramToken == "/usr/bin/git" && step.NormalizedCommand == "git" {
			found = true
		}
	}
	if !found {
		t.Fatalf("trace missing normalization: %+v", got.Trace)
	}
}

func TestEvaluateAWSProfileSemanticParsingForms(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity", Profile: "myprof"}},
			}},
		},
	}, Source{})

	for _, command := range []string{
		"aws --profile myprof sts get-caller-identity",
		"aws --profile=myprof sts get-caller-identity",
		"AWS_PROFILE=myprof aws sts get-caller-identity",
	} {
		t.Run(command, func(t *testing.T) {
			got, err := Evaluate(p, command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "allow" {
				t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
			}
			if got.Command != command {
				t.Fatalf("Command = %q, want original %q", got.Command, command)
			}
		})
	}
}

func TestEvaluateReadOnlyCommandsUsePatterns(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Patterns: []string{"^ls(\\s+-[A-Za-z0-9]+)?\\s+[^;&|`$()]+$", `^pwd$`},
			}},
		},
	}, Source{})

	for _, command := range []string{"ls -la internal", "pwd"} {
		t.Run(command, func(t *testing.T) {
			got, err := Evaluate(p, command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "allow" {
				t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
			}
		})
	}
}

func TestEvaluateSafePatternFallbackExamples(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Name:     "terraform read-only fallback",
				Patterns: []string{"^terraform\\s+(plan|show)(\\s|$)[^;&|`$()]*$"},
			}},
		},
	}, Source{})

	tests := []struct {
		command string
		want    string
	}{
		{command: "terraform plan -out=tfplan", want: "allow"},
		{command: "terraform show tfplan", want: "allow"},
		{command: "terraform apply -auto-approve", want: "abstain"},
		{command: "terraform plan; terraform apply -auto-approve", want: "ask"},
		{command: "terraform plan $(echo tfplan)", want: "ask"},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != tt.want {
				t.Fatalf("Outcome = %q, want %q; decision=%+v", got.Outcome, tt.want, got)
			}
		})
	}
}

func TestEvaluateBroadPatternAllowDocumentsResidualRisk(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Name:     "too broad terraform fallback",
				Patterns: []string{`^terraform\s+`},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "terraform apply -auto-approve")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluateScriptRunnerPatternAllowDoesNotInspectScriptBody(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Name:     "npm lint script",
				Patterns: []string{`^npm\s+run\s+lint$`},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "npm run lint")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
	}
}

func TestValidatePipelineRejectsTopLevelRewrite(t *testing.T) {
	issues := ValidatePipeline(PipelineSpec{
		Rewrite: []map[string]any{{
			"match": map[string]any{
				"command_is_absolute_path": true,
			},
			"strip_command_path": true,
		}},
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{Patterns: []string{`^pwd$`}}},
		},
	})
	if len(issues) == 0 {
		t.Fatal("ValidatePipeline issues empty, want rewrite rejection")
	}
	if !strings.Contains(issues[0], "top-level rewrite is no longer supported") {
		t.Fatalf("issues = %#v, want rewrite unsupported error", issues)
	}
}

func TestEvaluateTraceIncludesCommandPlanNormalization(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}}},
		},
	}, Source{})

	got, err := Evaluate(p, "/usr/bin/git status")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	step := firstTraceStepByName(got.Trace, "normalized_command")
	if step == nil {
		t.Fatalf("normalization trace missing; trace=%+v", got.Trace)
	}
	if step.ProgramToken != "/usr/bin/git" || step.NormalizedCommand != "git" || step.NormalizedReason != "basename" {
		t.Fatalf("normalization trace = %+v, want basename git", step)
	}
}

func TestEvaluatePermissionPriorityDenyAskAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "s3", Operation: "rm"}},
				Test:    PermissionTestSpec{Deny: []string{"aws s3 rm --delete"}, Pass: []string{"aws s3 ls"}},
			}},
			Ask: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "s3"}},
				Test:    PermissionTestSpec{Ask: []string{"aws s3 ls"}, Pass: []string{"aws sts get-caller-identity"}},
			}},
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "sts"}},
				Test:    PermissionTestSpec{Allow: []string{"aws sts get-caller-identity"}, Pass: []string{"aws s3 ls"}},
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

func TestEvaluateGitFlagsContainsUsesSemanticFlags(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Ask: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status", FlagsContains: []string{"--short"}}},
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

func TestEvaluateGitSemanticVerbIgnoresGlobalOptionRawWords(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Ask: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}},
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
			Deny:  []PermissionRuleSpec{{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}}},
			Allow: []PermissionRuleSpec{{Command: PermissionCommandSpec{Name: "git"}}},
		},
	}, Source{})

	got := evaluatePreparedCommand(p.prepared.Deny, p.prepared.Ask, p.prepared.Allow, cmd)
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
}

func TestValidatePipelineRequiresE2ETest(t *testing.T) {
	issues := ValidatePipeline(PipelineSpec{
		Rewrite: []map[string]any{{
			"unwrap_shell_dash_c": true,
		}},
	})
	if len(issues) == 0 {
		t.Fatal("expected validation issues")
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

func TestPermissionRuleMatchesPatternsShellDashCInnerCommand(t *testing.T) {
	rule := PermissionRuleSpec{
		Patterns: []string{`^\s*aws(\s|$)`},
		Env: PermissionEnvSpec{
			Missing: []string{"AWS_PROFILE"},
		},
	}
	if !PermissionRuleMatches(rule, "bash -c 'aws s3 ls'") {
		t.Fatal("expected patterns match against shell -c inner command")
	}
	if PermissionRuleMatches(rule, "bash -c 'AWS_PROFILE=dev aws s3 ls'") {
		t.Fatal("did not expect env-scoped patterns rule to match")
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
			name:    "short force push",
			command: "git push -f origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
			want:    true,
		},
		{
			name:    "force with lease push uses separate field",
			command: "git push --force-with-lease origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", ForceWithLease: boolPtr(true)}},
			want:    true,
		},
		{
			name:    "force with lease is not destructive force",
			command: "git push --force-with-lease origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
			want:    false,
		},
		{
			name:    "force if includes push uses separate field",
			command: "git push --force-if-includes origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", ForceIfIncludes: boolPtr(true)}},
			want:    true,
		},
		{
			name:    "force if includes is not destructive force",
			command: "git push --force-if-includes origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
			want:    false,
		},
		{
			name:    "flags contains matches parser recognized flag",
			command: "git push --force origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", FlagsContains: []string{"--force"}}},
			want:    true,
		},
		{
			name:    "flags contains does not scan raw positional args",
			command: "git push origin main",
			match:   MatchSpec{Command: "git", Semantic: &SemanticMatchSpec{Verb: "push", FlagsContains: []string{"main"}}},
			want:    false,
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
			name:    "flags contains matches parser recognized aws flag",
			command: "aws --no-cli-pager sts get-caller-identity",
			match:   MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Service: "sts", FlagsContains: []string{"--no-cli-pager"}}},
			want:    true,
		},
		{
			name:    "flags contains does not scan raw aws operation",
			command: "aws s3 --delete-object bucket/key",
			match:   MatchSpec{Command: "aws", Semantic: &SemanticMatchSpec{Service: "s3", FlagsContains: []string{"--delete-object"}}},
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
			name:    "issue list label",
			command: "gh issue list --state open --label prod --assignee tasuku43",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "issue", Verb: "list", State: "open", LabelIn: []string{"prod"}, AssigneeIn: []string{"tasuku43"}}},
			want:    true,
		},
		{
			name:    "issue create body contains",
			command: `gh issue create --title "prod deploy" --body "needs review"`,
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "issue", Verb: "create", TitleContains: "prod", BodyContains: "review"}},
			want:    true,
		},
		{
			name:    "repo delete target",
			command: "gh repo delete owner/prod",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "repo", Verb: "delete", RepoIn: []string{"owner/prod"}}},
			want:    true,
		},
		{
			name:    "release create production",
			command: "gh release create v1.0.0",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "release", Verb: "create", Tag: "v1.0.0", Prerelease: boolPtr(false)}},
			want:    true,
		},
		{
			name:    "secret remove by env",
			command: "gh secret remove API_TOKEN --env prod",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "secret", Verb: "remove", SecretNameIn: []string{"API_TOKEN"}, EnvName: "prod"}},
			want:    true,
		},
		{
			name:    "workflow run ref",
			command: "gh workflow run deploy.yml --ref main",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "workflow", Verb: "run", WorkflowName: "deploy.yml", Ref: "main"}},
			want:    true,
		},
		{
			name:    "auth token",
			command: "gh auth token --hostname github.com",
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "auth", Verb: "token", Hostname: "github.com"}},
			want:    true,
		},
		{
			name:    "search query contains",
			command: `gh search code "TODO owner:repo"`,
			match:   MatchSpec{Command: "gh", Semantic: &SemanticMatchSpec{Area: "search", SearchType: "code", QueryContains: "owner:repo"}},
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

func TestPermissionRuleMatchesArgoCDSemantic(t *testing.T) {
	tests := []struct {
		name    string
		command string
		match   MatchSpec
		want    bool
	}{
		{
			name:    "app diff allowed",
			command: "argocd app diff payments --project prod",
			match:   MatchSpec{Command: "argocd", Semantic: &SemanticMatchSpec{Verb: "app diff", AppName: "payments", Project: "prod"}},
			want:    true,
		},
		{
			name:    "app rollback revision",
			command: "argocd app rollback payments 42",
			match:   MatchSpec{Command: "argocd", Semantic: &SemanticMatchSpec{Verb: "app rollback", Revision: "42"}},
			want:    true,
		},
		{
			name:    "wrong app",
			command: "argocd app sync payments",
			match:   MatchSpec{Command: "argocd", Semantic: &SemanticMatchSpec{Verb: "app sync", AppName: "billing"}},
			want:    false,
		},
		{
			name:    "generic fallback does not satisfy argocd semantic",
			command: "unknown app sync payments",
			match:   MatchSpec{Command: "unknown", Semantic: &SemanticMatchSpec{Verb: "app sync"}},
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
					Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "pr", Verb: "merge", Admin: boolPtr(true)}},
					Message: "admin PR merge is blocked",
				},
				{
					Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "run", VerbIn: []string{"delete", "cancel"}}},
					Message: "workflow run deletion/cancellation is blocked",
				},
			},
			Ask: []PermissionRuleSpec{
				{
					Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "pr", VerbIn: []string{"create", "merge", "close", "reopen", "review", "ready", "update-branch"}}},
					Message: "PR mutation requires confirmation",
				},
				{
					Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "run", Verb: "rerun"}},
					Message: "workflow rerun requires confirmation",
				},
				{
					Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "api", MethodIn: []string{"POST", "PUT", "PATCH", "DELETE"}}},
					Message: "GitHub API mutation requires confirmation",
				},
			},
			Allow: []PermissionRuleSpec{
				{Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "pr", VerbIn: []string{"view", "list", "diff", "status", "checks"}}}},
				{Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "run", VerbIn: []string{"view", "list", "watch"}}}},
				{Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "api", Method: "GET", EndpointPrefix: "/repos/"}}},
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
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "s3", OperationIn: []string{"rm", "rb", "delete-object", "delete-bucket"}}},
				Message: "destructive S3 operation is blocked",
			}},
			Ask: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{ServiceIn: []string{"iam"}}},
				Message: "AWS control-plane operation requires confirmation",
			}},
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity"}},
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
				Command: PermissionCommandSpec{Name: "kubectl", Semantic: &SemanticMatchSpec{Verb: "delete", ResourceType: "pod", Namespace: "prod"}},
				Message: "deleting production Kubernetes resources is blocked",
			}},
			Ask: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "kubectl", Semantic: &SemanticMatchSpec{VerbIn: []string{"apply", "patch", "scale", "rollout", "delete"}}},
				Message: "Kubernetes mutation requires confirmation",
			}},
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "kubectl", Semantic: &SemanticMatchSpec{VerbIn: []string{"get", "describe", "logs"}, Namespace: "default"}},
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
					Command: PermissionCommandSpec{Name: "helmfile", Semantic: &SemanticMatchSpec{VerbIn: []string{"sync", "apply", "destroy", "delete"}, EnvironmentIn: []string{"prod", "production"}, Interactive: boolPtr(false)}},
					Message: "non-interactive helmfile mutation in production is blocked",
				},
				{
					Command: PermissionCommandSpec{Name: "helmfile", Semantic: &SemanticMatchSpec{Verb: "destroy", EnvironmentIn: []string{"prod", "production"}}},
					Message: "helmfile destroy in production is blocked",
				},
			},
			Ask: []PermissionRuleSpec{
				{
					Command: PermissionCommandSpec{Name: "helmfile", Semantic: &SemanticMatchSpec{VerbIn: []string{"sync", "apply", "destroy", "delete"}}},
					Message: "helmfile mutation requires confirmation",
				},
				{
					Command: PermissionCommandSpec{Name: "helmfile", Semantic: &SemanticMatchSpec{Verb: "sync", SelectorMissing: boolPtr(true)}},
					Message: "helmfile sync without selector requires confirmation",
				},
			},
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "helmfile", Semantic: &SemanticMatchSpec{VerbIn: []string{"diff", "template", "build", "list", "lint", "status"}}},
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
				Command: PermissionCommandSpec{Name: "helmfile", Semantic: &SemanticMatchSpec{Verb: "sync", Environment: "prod", File: "helmfile.prod.yaml", Namespace: "prod", KubeContext: "prod-cluster", SelectorContains: []string{"app=foo"}, Interactive: boolPtr(false)}},
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
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
				Message: "force push is blocked",
			}},
			Ask: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{VerbIn: []string{"push", "reset", "rebase", "clean"}}},
				Message: "dangerous git operation requires confirmation",
			}},
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{VerbIn: []string{"status", "diff", "log", "show", "branch"}}},
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
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}},
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
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity", Profile: "prod", Region: "ap-northeast-1"}},
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
				Command: PermissionCommandSpec{Name: "kubectl", Semantic: &SemanticMatchSpec{Verb: "get", ResourceType: "pods", Namespace: "default", Context: "dev"}},
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
				Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Area: "api", Method: "GET", EndpointPrefix: "/repos/", Repo: "owner/repo"}},
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
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
		},
		{
			name:    "semicolon list",
			command: "git status; rm -rf /tmp/x",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
		},
		{
			name:    "pipe",
			command: "git status | sh",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
		},
		{
			name:    "redirect",
			command: "git status > /tmp/out",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
		},
		{
			name:    "comment",
			command: "git status # harmless-looking comment",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
		},
		{
			name:    "bash c compound",
			command: "bash -c 'git status && rm -rf /tmp/x'",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "bash"}},
		},
		{
			name:    "bash c redirect",
			command: "bash -c 'git status > /tmp/out'",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "bash"}},
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
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}},
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
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}},
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
		return PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: subcommand}}}
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
				Patterns: []string{`^\s*git\s+status\s*&&\s*git\s+diff\s*$`},
				Message:  "raw compound denied",
			}},
			Allow: []PermissionRuleSpec{
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "diff"}}},
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
		t.Fatalf("Message = %q, want patterns deny message; decision=%+v", got.Message, got)
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
				Patterns: []string{`^\s*git\s+status\s*&&\s*git\s+diff\s*$`},
				Message:  "raw compound asks",
			}},
			Allow: []PermissionRuleSpec{
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "diff"}}},
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
		t.Fatalf("Message = %q, want patterns ask message; decision=%+v", got.Message, got)
	}
	if steps := traceStepsByName(got.Trace, "composition"); len(steps) != 0 {
		t.Fatalf("composition trace steps = %d, want 0; trace=%+v", len(steps), got.Trace)
	}
	if last := got.Trace[len(got.Trace)-1]; last.RuleType != "raw" {
		t.Fatalf("rule_type=%q, want raw; trace=%+v", last.RuleType, got.Trace)
	}
}

func TestEvaluatePatternsAllowDoesNotBeatCompositionAsk(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{Patterns: []string{`^\s*git\s+status\s*&&\s*rm\s+-rf\s+/tmp/x\s*$`}}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status && rm -rf /tmp/x")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
	if steps := traceStepsByName(got.Trace, "composition"); len(steps) == 0 {
		t.Fatalf("composition trace missing; trace=%+v", got.Trace)
	}
}

func TestEvaluateRawAllowPatternWithoutUnsafeShellDoesNotBypassComposition(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Patterns: []string{`^\s*git\s+status\s*&&\s*rm\s+-rf\s+/tmp/x\s*$`},
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

func TestEvaluatePatternsAllowMatchesSimpleCommand(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Patterns: []string{`^\s*git\s+status\s*$`},
			}},
		},
	}, Source{})

	got, err := Evaluate(p, "git status")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
	}
}

func TestEvaluateStructuredDenyBeatsUnsafeRawAllow(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "rm"},
				Message: "rm denied",
			}},
			Allow: []PermissionRuleSpec{{
				Patterns: []string{`^\s*git\s+status\s*&&\s*rm\s+-rf\s+/tmp/x\s*$`},
				Message:  "trusted full compound",
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
				Command: PermissionCommandSpec{Name: "rm"},
				Message: "rm asks",
			}},
			Allow: []PermissionRuleSpec{{
				Patterns: []string{`^\s*git\s+status\s*&&\s*rm\s+-rf\s+/tmp/x\s*$`},
				Message:  "trusted full compound",
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
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
			},
			Deny: []PermissionRuleSpec{
				{Command: PermissionCommandSpec{Name: "rm"}},
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
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
			},
			Ask: []PermissionRuleSpec{
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "diff"}}},
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
	src := Source{Layer: "project", Path: "/repo/.cc-bash-guard/cc-bash-guard.yml"}
	gitRule := func(subcommand string) PermissionRuleSpec {
		return PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: subcommand}}}
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
				Deny:  []PermissionRuleSpec{{Command: PermissionCommandSpec{Name: "rm"}}},
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
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
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
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
				{Command: PermissionCommandSpec{Name: "sh"}},
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
					Allow: []PermissionRuleSpec{{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}}},
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
			deny:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "rm"}},
			wantCmd: "rm -rf /tmp/x",
		},
		{
			name:    "output process substitution",
			command: "echo >(sh)",
			deny:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "sh"}},
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
				{Command: PermissionCommandSpec{Name: "cat"}},
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
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
				{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}},
				{Command: PermissionCommandSpec{Name: "sh"}},
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

func containsIssue(issues []string, want string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, want) {
			return true
		}
	}
	return false
}

func TestEvaluatePatternAllowFailsClosedOnUnsafeShellExpressions(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Patterns: []string{`^\s*git\s+status\s*\|\s*sh$`},
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
				Patterns: []string{`.*`},
				Message:  "broad patterns allow",
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
				Patterns: []string{`^\s*rm\s+-rf\s+/tmp/x\s*&&`},
				Message:  "patterns deny wins",
			}},
			Allow: []PermissionRuleSpec{{
				Patterns: []string{`.*`},
				Message:  "broad patterns allow",
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
	if got.Message != "patterns deny wins" {
		t.Fatalf("Message = %q, want patterns deny message; decision=%+v", got.Message, got)
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
				Patterns: []string{`^\s*cat\s+<\(git\s+status\)\s*$`},
				Message:  "broad patterns allow",
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

func TestEvaluatePatternsAllowFailsClosedOnUnsafeShellExpressions(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Patterns: []string{`^\s*git\s+status\s*\|\s*sh$`},
				Message:  "allow trusted pipeline",
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

func TestEvaluatePatternsListAllowFailsClosedOnUnsafeShellExpressions(t *testing.T) {
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Patterns: []string{
					`^\s*git\s+status\s*\|\s*sh$`,
					`^\s*git\s+diff\s*\|\s*sh$`,
				},
				Message: "allow trusted pipelines",
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

func TestValidatePermissionRuleAcceptsPatternsAllow(t *testing.T) {
	issues := ValidatePermissionRule("permission.allow[0]", PermissionRuleSpec{
		Patterns: []string{`^\s*git\s+status$`},
		Test:     PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
	}, "allow")
	if len(issues) != 0 {
		t.Fatalf("issues=%#v", issues)
	}
}

func TestEvaluatePermissionPredicateCombinations(t *testing.T) {
	tests := []struct {
		name    string
		rule    PermissionRuleSpec
		effect  string
		command string
		want    string
	}{
		{
			name:    "command only allow",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git"}},
			effect:  "allow",
			command: "git status",
			want:    "allow",
		},
		{
			name:    "command semantic deny",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "push", Force: boolPtr(true)}}},
			effect:  "deny",
			command: "git push --force origin main",
			want:    "deny",
		},
		{
			name:    "command env allow",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "aws"}, Env: PermissionEnvSpec{Requires: []string{"AWS_PROFILE"}}},
			effect:  "allow",
			command: "AWS_PROFILE=dev aws sts get-caller-identity",
			want:    "allow",
		},
		{
			name:    "command env does not match different command",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "aws"}, Env: PermissionEnvSpec{Missing: []string{"AWS_PROFILE"}}},
			effect:  "deny",
			command: "git rebase main",
			want:    "abstain",
		},
		{
			name:    "command semantic env allow",
			rule:    PermissionRuleSpec{Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity"}}, Env: PermissionEnvSpec{Requires: []string{"AWS_PROFILE"}}},
			effect:  "allow",
			command: "AWS_PROFILE=dev aws sts get-caller-identity",
			want:    "allow",
		},
		{
			name:    "patterns env ask",
			rule:    PermissionRuleSpec{Patterns: []string{`^KUBECONFIG=.*helm\s+upgrade\b`}, Env: PermissionEnvSpec{Requires: []string{"KUBECONFIG"}}},
			effect:  "ask",
			command: "KUBECONFIG=prod helm upgrade app chart",
			want:    "ask",
		},
		{
			name:    "env only deny",
			rule:    PermissionRuleSpec{Env: PermissionEnvSpec{Requires: []string{"CI"}}},
			effect:  "deny",
			command: "CI=true git status",
			want:    "deny",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := PermissionSpec{}
			switch tt.effect {
			case "deny":
				spec.Deny = []PermissionRuleSpec{tt.rule}
			case "ask":
				spec.Ask = []PermissionRuleSpec{tt.rule}
			case "allow":
				spec.Allow = []PermissionRuleSpec{tt.rule}
			}
			got, err := Evaluate(NewPipeline(PipelineSpec{Permission: spec}, Source{}), tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != tt.want {
				t.Fatalf("Outcome=%q want %q decision=%+v", got.Outcome, tt.want, got)
			}
		})
	}
}

func TestEvaluatePermissionCommandEnvDenyDoesNotOverrideDifferentCommandAsk(t *testing.T) {
	pipeline := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Name:    "aws without AWS_PROFILE env",
				Command: PermissionCommandSpec{Name: "aws"},
				Env:     PermissionEnvSpec{Missing: []string{"AWS_PROFILE"}},
				Message: "aws commands must start with AWS_PROFILE=<profile>",
			}},
			Ask: []PermissionRuleSpec{{
				Name:    "git rebase ask",
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "rebase"}},
				Message: "git rebase rewrites history",
			}},
		},
	}, Source{})

	got, err := Evaluate(pipeline, "git rebase main")
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "ask" {
		t.Fatalf("Outcome = %q, want ask; decision=%+v", got.Outcome, got)
	}
	if got.Message != "git rebase rewrites history" {
		t.Fatalf("Message = %q, want git rebase message; decision=%+v", got.Message, got)
	}
}

func TestValidatePermissionPredicateInvalidForms(t *testing.T) {
	tests := []struct {
		name  string
		rule  PermissionRuleSpec
		issue string
	}{
		{
			name:  "command patterns invalid",
			rule:  PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git"}, Patterns: []string{`^git`}},
			issue: "permission.allow[0] cannot combine command and patterns",
		},
		{
			name:  "semantic without command name invalid",
			rule:  PermissionRuleSpec{Command: PermissionCommandSpec{Semantic: &SemanticMatchSpec{Verb: "status"}}},
			issue: "permission.allow[0].command.name must be set when semantic is used",
		},
		{
			name:  "empty command name invalid",
			rule:  PermissionRuleSpec{Command: PermissionCommandSpec{Name: " "}},
			issue: "permission.allow[0].command.name must be non-empty",
		},
		{
			name:  "empty env entry invalid",
			rule:  PermissionRuleSpec{Env: PermissionEnvSpec{Requires: []string{""}}},
			issue: "permission.allow[0].env.requires[0] must be non-empty",
		},
		{
			name:  "empty patterns entry invalid",
			rule:  PermissionRuleSpec{Patterns: []string{""}},
			issue: "permission.allow[0].patterns[0] must be non-empty",
		},
		{
			name:  "invalid regex invalid",
			rule:  PermissionRuleSpec{Patterns: []string{"["}},
			issue: "permission.allow[0].patterns[0] must compile",
		},
		{
			name:  "whitespace name invalid",
			rule:  PermissionRuleSpec{Name: " ", Command: PermissionCommandSpec{Name: "git"}},
			issue: "permission.allow[0].name must be non-empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := ValidatePermissionRule("permission.allow[0]", tt.rule, "allow")
			if !containsIssue(issues, tt.issue) {
				t.Fatalf("issues=%#v want containing %q", issues, tt.issue)
			}
		})
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
				Command: PermissionCommandSpec{Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].command.name must be set when semantic is used",
		},
		{
			name: "non git command",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "ls", Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].command.semantic is not available for command ls. Use patterns, or add a semantic schema/parser for ls.",
		},
		{
			name: "unknown command with semantic",
			spec: PipelineSpec{Permission: PermissionSpec{Ask: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "unknown-tool", Semantic: &SemanticMatchSpec{Verb: "delete"}},
			}}}},
			issue: "permission.ask[0].command.semantic is not available for command unknown-tool. Use patterns, or add a semantic schema/parser for unknown-tool.",
		},
		{
			name: "git command with aws semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Service: "sts"}},
			}}}},
			issue: "permission.deny[0].command.semantic contains fields not supported for command: git",
		},
		{
			name: "aws command with git semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Verb: "push"}},
			}}}},
			issue: "permission.deny[0].command.semantic contains fields not supported for command: aws",
		},
		{
			name: "aws command with kubectl semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{Namespace: "prod"}},
			}}}},
			issue: "permission.deny[0].command.semantic contains fields not supported for command: aws",
		},
		{
			name: "kubectl command with aws semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "kubectl", Semantic: &SemanticMatchSpec{Service: "s3"}},
			}}}},
			issue: "permission.deny[0].command.semantic contains fields not supported for command: kubectl",
		},
		{
			name: "git command with gh semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Area: "api"}},
			}}}},
			issue: "permission.deny[0].command.semantic contains fields not supported for command: git",
		},
		{
			name: "gh command with aws semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{Service: "sts"}},
			}}}},
			issue: "permission.deny[0].command.semantic contains fields not supported for command: gh",
		},
		{
			name: "git command with helmfile semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Environment: "prod"}},
			}}}},
			issue: "permission.deny[0].command.semantic contains fields not supported for command: git",
		},
		{
			name: "helmfile command with aws semantic fields",
			spec: PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "helmfile", Semantic: &SemanticMatchSpec{Service: "sts"}},
			}}}},
			issue: "permission.deny[0].command.semantic contains fields not supported for command: helmfile",
		},
		{
			name: "top level rewrite",
			spec: PipelineSpec{Rewrite: []map[string]any{{
				"match": map[string]any{
					"command": "gh",
				},
				"strip_command_path": true,
			}}},
			issue: "top-level rewrite is no longer supported; cc-bash-guard no longer rewrites commands. Use permission.command / env / patterns, and rely on parser-backed normalization for evaluation.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := ValidatePipeline(tt.spec)
			if !containsIssue(issues, tt.issue) {
				t.Fatalf("issues=%#v, want %q", issues, tt.issue)
			}
		})
	}
}

func TestValidateSemanticUnsupportedFieldSuggestsSupportedFields(t *testing.T) {
	issues := ValidatePipeline(PipelineSpec{Permission: PermissionSpec{Deny: []PermissionRuleSpec{{
		Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Namespace: "prod"}},
	}}}})
	want := "permission.deny[0].command.semantic.namespace is not supported for command git. Supported semantic fields for git:"
	for _, issue := range issues {
		if strings.Contains(issue, want) && strings.Contains(issue, "verb") && strings.Contains(issue, "flags_contains") {
			return
		}
	}
	t.Fatalf("issues=%#v, want supported-field suggestion", issues)
}

func TestRegisteredSemanticFieldsAreAcceptedByValidation(t *testing.T) {
	for _, schema := range semanticpkg.AllSchemas() {
		for _, field := range schema.Fields {
			t.Run(schema.Command+"/"+field.Name, func(t *testing.T) {
				semantic := semanticSpecWithField(t, field.Name, field.Type)
				issues := ValidatePermissionCommandSpec("permission.deny[0].command", PermissionCommandSpec{
					Name:     schema.Command,
					Semantic: &semantic,
				})
				for _, issue := range issues {
					if strings.Contains(issue, "not supported for command") {
						t.Fatalf("registered field rejected: %s", issue)
					}
				}
			})
		}
	}
}

func TestSemanticMatchSpecProjectsToToolSpecificSpecs(t *testing.T) {
	force := true
	semantic := SemanticMatchSpec{
		Verb:        "push",
		Force:       &force,
		Service:     "sts",
		Operation:   "get-caller-identity",
		Namespace:   "production",
		Area:        "api",
		Environment: "prod",
		AppName:     "payments",
	}

	if got := semantic.Git(); got.Verb != "push" || got.Force == nil || !*got.Force {
		t.Fatalf("Git() = %+v", got)
	}
	if got := semantic.AWS(); got.Service != "sts" || got.Operation != "get-caller-identity" {
		t.Fatalf("AWS() = %+v", got)
	}
	if got := semantic.Kubectl(); got.Verb != "push" || got.Namespace != "production" {
		t.Fatalf("Kubectl() = %+v", got)
	}
	if got := semantic.GH(); got.Area != "api" || got.Verb != "push" {
		t.Fatalf("GH() = %+v", got)
	}
	if got := semantic.Helmfile(); got.Verb != "push" || got.Environment != "prod" {
		t.Fatalf("Helmfile() = %+v", got)
	}
	if got := semantic.ArgoCD(); got.Verb != "push" || got.AppName != "payments" {
		t.Fatalf("ArgoCD() = %+v", got)
	}
}

func TestToolSpecificSemanticSpecsMatchLikeFlatSpec(t *testing.T) {
	force := true
	cases := []struct {
		name     string
		command  string
		semantic SemanticMatchSpec
		matches  func(SemanticMatchSpec, commandpkg.Command) bool
	}{
		{
			name:     "git",
			command:  "git push --force origin main",
			semantic: SemanticMatchSpec{Verb: "push", Force: &force},
			matches:  func(s SemanticMatchSpec, cmd commandpkg.Command) bool { return s.Git().matches(cmd) },
		},
		{
			name:     "aws",
			command:  "aws sts get-caller-identity",
			semantic: SemanticMatchSpec{Service: "sts", Operation: "get-caller-identity"},
			matches:  func(s SemanticMatchSpec, cmd commandpkg.Command) bool { return s.AWS().matches(cmd) },
		},
		{
			name:     "kubectl",
			command:  "kubectl delete pod nginx -n production",
			semantic: SemanticMatchSpec{Verb: "delete", ResourceType: "pod", Namespace: "production"},
			matches:  func(s SemanticMatchSpec, cmd commandpkg.Command) bool { return s.Kubectl().matches(cmd) },
		},
		{
			name:     "gh",
			command:  "gh api --method DELETE repos/OWNER/REPO",
			semantic: SemanticMatchSpec{Area: "api", Method: "DELETE"},
			matches:  func(s SemanticMatchSpec, cmd commandpkg.Command) bool { return s.GH().matches(cmd) },
		},
		{
			name:     "helmfile",
			command:  "helmfile -e prod destroy",
			semantic: SemanticMatchSpec{Verb: "destroy", Environment: "prod"},
			matches:  func(s SemanticMatchSpec, cmd commandpkg.Command) bool { return s.Helmfile().matches(cmd) },
		},
		{
			name:     "argocd",
			command:  "argocd app sync payments",
			semantic: SemanticMatchSpec{Verb: "app sync", AppName: "payments"},
			matches:  func(s SemanticMatchSpec, cmd commandpkg.Command) bool { return s.ArgoCD().matches(cmd) },
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			plan := commandpkg.Parse(tt.command)
			if len(plan.Commands) != 1 {
				t.Fatalf("commands = %d", len(plan.Commands))
			}
			cmd := plan.Commands[0]
			if !permissionSemanticMatches(tt.name, tt.semantic, cmd) {
				t.Fatalf("permissionSemanticMatches(%s) = false", tt.name)
			}
			if !tt.matches(tt.semantic, cmd) {
				t.Fatalf("tool-specific match = false")
			}
		})
	}
}

func semanticSpecWithField(t *testing.T, fieldName string, fieldType string) SemanticMatchSpec {
	t.Helper()
	var semantic SemanticMatchSpec
	v := reflect.ValueOf(&semantic).Elem()
	st := v.Type()
	for i := 0; i < st.NumField(); i++ {
		if strings.Split(st.Field(i).Tag.Get("yaml"), ",")[0] != fieldName {
			continue
		}
		f := v.Field(i)
		switch fieldType {
		case "string":
			f.SetString("value")
		case "[]string":
			f.Set(reflect.ValueOf([]string{"value"}))
		case "bool":
			b := true
			f.Set(reflect.ValueOf(&b))
		default:
			t.Fatalf("unknown semantic field type %q for %s", fieldType, fieldName)
		}
		return semantic
	}
	t.Fatalf("semantic field %q is registered but missing from SemanticMatchSpec", fieldName)
	return semantic
}

func TestEvaluateTraceIncludesMatchedRuleSource(t *testing.T) {
	src := Source{Layer: "project", Path: "/repo/.cc-bash-guard/cc-bash-guard.yml"}
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}},
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
		rules = append(rules, PermissionRuleSpec{Patterns: []string{`^\s*cmd-` + fmtIntForBenchmark(i) + `\s+.*$`}})
	}
	rules = append(rules, PermissionRuleSpec{Patterns: []string{`^\s*git\s+status\s*$`}})
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
