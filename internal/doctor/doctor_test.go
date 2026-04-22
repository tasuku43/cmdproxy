package doctor

import (
	"testing"

	"github.com/tasuku43/cmdproxy/internal/config"
	"github.com/tasuku43/cmdproxy/internal/domain/policy"
)

func TestRunWarnsOnRelaxedRewriteContracts(t *testing.T) {
	strict := false
	loaded := config.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Rewrite: []policy.RewriteStepSpec{{
				Match: policy.MatchSpec{Command: "kubectl"},
				MoveFlagToEnv: policy.MoveFlagToEnvSpec{
					Flag: "--kubeconfig",
					Env:  "KUBECONFIG",
				},
				Strict: &strict,
				Test: policy.RewriteTestSpec{
					{In: "kubectl --kubeconfig /tmp/dev get pods", Out: "KUBECONFIG=/tmp/dev kubectl get pods"},
					{Pass: "KUBECONFIG=/tmp/dev kubectl get pods"},
				},
			}},
			Test: policy.PipelineTestSpec{{In: "kubectl --kubeconfig /tmp/dev get pods", Decision: "ask"}},
		}, policy.Source{}),
	}

	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if !hasCheck(report, "rewrite.relaxed-contracts", StatusWarn) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunPassesWhenPipelineTestsMatch(t *testing.T) {
	loaded := config.Loaded{
		Pipeline: policy.NewPipeline(policy.PipelineSpec{
			Permission: policy.PermissionSpec{
				Allow: []policy.PermissionRuleSpec{{
					Match: policy.MatchSpec{Command: "git", Subcommand: "status"},
					Test:  policy.PermissionTestSpec{Allow: []string{"git status"}, Pass: []string{"git diff"}},
				}},
			},
			Test: policy.PipelineTestSpec{{In: "git status", Decision: "allow"}},
		}, policy.Source{}),
	}
	report := Run(loaded, "claude", t.TempDir(), t.TempDir())
	if !hasCheck(report, "tests.pass", StatusPass) {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func hasCheck(report Report, id string, status Status) bool {
	for _, check := range report.Checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}
