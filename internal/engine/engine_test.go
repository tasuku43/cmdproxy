package engine

import (
	"testing"

	"github.com/tasuku43/cmdguard/internal/input"
	"github.com/tasuku43/cmdguard/internal/rule"
)

func TestEvaluateFirstMatchWins(t *testing.T) {
	rules := []rule.Rule{
		{RuleSpec: rule.RuleSpec{ID: "first", Pattern: "^git", Message: "first"}},
		{RuleSpec: rule.RuleSpec{ID: "second", Pattern: "status$", Message: "second"}},
	}
	got, err := Evaluate(rules, input.ExecRequest{Action: "exec", Command: "git status"})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Allowed || got.Rule == nil || got.Rule.ID != "first" {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluatePredicateRule(t *testing.T) {
	rules := []rule.Rule{
		{
			RuleSpec: rule.RuleSpec{
				ID: "no-shell-dash-c",
				Matcher: rule.MatchSpec{
					CommandIn:    []string{"bash", "sh"},
					ArgsContains: []string{"-c"},
				},
				Message: "blocked",
			},
		},
	}

	got, err := Evaluate(rules, input.ExecRequest{Action: "exec", Command: "/usr/bin/env bash -c 'echo hi'"})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Allowed || got.Rule == nil || got.Rule.ID != "no-shell-dash-c" {
		t.Fatalf("got %+v", got)
	}
}
