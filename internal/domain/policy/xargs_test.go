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
