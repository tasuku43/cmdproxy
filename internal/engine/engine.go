package engine

import (
	"regexp"

	"github.com/tasuku43/cmdguard/internal/input"
	"github.com/tasuku43/cmdguard/internal/rule"
)

type Decision struct {
	Allowed bool
	Rule    *rule.Rule
	Command string
}

func Evaluate(rules []rule.Rule, req input.ExecRequest) (Decision, error) {
	for i := range rules {
		matched, err := regexp.MatchString(rules[i].Pattern, req.Command)
		if err != nil {
			return Decision{}, err
		}
		if matched {
			return Decision{
				Allowed: false,
				Rule:    &rules[i],
				Command: req.Command,
			}, nil
		}
	}
	return Decision{Allowed: true, Command: req.Command}, nil
}
