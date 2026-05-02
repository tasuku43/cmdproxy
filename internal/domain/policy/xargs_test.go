package policy

import "testing"

func TestEvaluateXargsSemanticRules(t *testing.T) {
	trueValue := true
	falseValue := false
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "xargs", Semantic: &SemanticMatchSpec{InnerCommand: "rm"}},
			}},
			Allow: []PermissionRuleSpec{
				{Command: PermissionCommandSpec{Name: "grep"}},
				{Command: PermissionCommandSpec{Name: "xargs", Semantic: &SemanticMatchSpec{
					InnerCommand: "grep", NullSeparated: &trueValue, NoRunIfEmpty: &trueValue,
					ReplaceMode: &falseValue, Parallel: &falseValue,
				}}},
			},
		},
	}, Source{})

	tests := []struct {
		command string
		want    string
	}{
		{command: "xargs -0 -r grep -n foo", want: "allow"},
		{command: "xargs grep -n foo", want: "abstain"},
		{command: "xargs rm -rf", want: "deny"},
		{command: "grep status", want: "allow"},
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

func TestEvaluatePipelineWithXargsAndToleratedRedirects(t *testing.T) {
	trueValue := true
	falseValue := false
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			ToleratedRedirects: ToleratedRedirectsSpec{
				Only: []string{"stdout_to_devnull", "stderr_to_devnull"},
			},
			Deny: []PermissionRuleSpec{{
				Command: PermissionCommandSpec{Name: "xargs", ShapeFlagsAny: []string{"redirect_stream_merge"}},
			}},
			Allow: []PermissionRuleSpec{
				{Command: PermissionCommandSpec{NameIn: []string{"find", "cd"}}},
				{Command: PermissionCommandSpec{Name: "grep"}},
				{Command: PermissionCommandSpec{Name: "xargs", Semantic: &SemanticMatchSpec{
					InnerCommandIn: []string{"grep"}, NoRunIfEmpty: &trueValue,
					ReplaceMode: &falseValue, Parallel: &falseValue,
				}}},
			},
		},
	}, Source{})

	tests := []struct {
		command string
		want    string
	}{
		{command: "find . -type f | xargs -r grep foo 2>/dev/null", want: "allow"},
		{command: "find . -type f | xargs -r grep foo > /tmp/out", want: "ask"},
		{command: "find . -type f | xargs -r grep foo 2>&1", want: "deny"},
		{command: "find . -type f | xargs -r rm 2>/dev/null", want: "ask"},
		{command: "cd repo && grep foo . 2>/dev/null", want: "ask"},
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

func TestEvaluatePipelineWithXargsAndRuleLocalToleratedRedirects(t *testing.T) {
	trueValue := true
	falseValue := false
	p := NewPipeline(PipelineSpec{
		Permission: PermissionSpec{
			Allow: []PermissionRuleSpec{
				{Command: PermissionCommandSpec{Name: "find"}},
				{Command: PermissionCommandSpec{
					Name: "xargs",
					Semantic: &SemanticMatchSpec{
						InnerCommand: "grep", NoRunIfEmpty: &trueValue,
						ReplaceMode: &falseValue, Parallel: &falseValue,
					},
					ToleratedRedirects: ToleratedRedirectsSpec{Only: []string{"stderr_to_devnull"}},
				}},
			},
		},
	}, Source{})

	got, err := Evaluate(p, "find . -type f | xargs -r grep foo 2>/dev/null")
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Outcome != "allow" {
		t.Fatalf("Outcome = %q, want allow; decision=%+v", got.Outcome, got)
	}
}
