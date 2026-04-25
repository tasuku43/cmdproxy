package command

import "testing"

func TestHelmfileParserExtractsSemanticFields(t *testing.T) {
	tests := []struct {
		name            string
		raw             string
		wantVerb        string
		wantEnvironment string
		wantFile        string
		wantNamespace   string
		wantKubeContext string
		wantSelectors   []string
		wantInteractive bool
		wantDryRun      bool
		wantPurge       bool
	}{
		{name: "sync", raw: "helmfile sync", wantVerb: "sync"},
		{name: "apply", raw: "helmfile apply", wantVerb: "apply"},
		{name: "destroy", raw: "helmfile destroy", wantVerb: "destroy"},
		{name: "delete purge", raw: "helmfile delete --purge", wantVerb: "delete", wantPurge: true},
		{name: "flags before verb", raw: "helmfile -e prod -f helmfile.prod.yaml sync", wantVerb: "sync", wantEnvironment: "prod", wantFile: "helmfile.prod.yaml"},
		{name: "flags after verb", raw: "helmfile sync -e prod -f helmfile.prod.yaml", wantVerb: "sync", wantEnvironment: "prod", wantFile: "helmfile.prod.yaml"},
		{name: "environment equals selectors", raw: "helmfile --environment=prod --selector app=foo --selector tier=backend apply", wantVerb: "apply", wantEnvironment: "prod", wantSelectors: []string{"app=foo", "tier=backend"}},
		{name: "context namespace", raw: "helmfile --kube-context prod-cluster -n prod sync", wantVerb: "sync", wantNamespace: "prod", wantKubeContext: "prod-cluster"},
		{name: "interactive", raw: "helmfile --interactive apply", wantVerb: "apply", wantInteractive: true},
		{name: "diff", raw: "helmfile diff", wantVerb: "diff"},
		{name: "env assignment", raw: "HELMFILE_ENVIRONMENT=prod helmfile sync", wantVerb: "sync", wantEnvironment: "prod"},
		{name: "dry run", raw: "helmfile apply --dry-run", wantVerb: "apply", wantDryRun: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := Parse(tt.raw)
			if len(plan.Commands) != 1 {
				t.Fatalf("len(Commands) = %d, want 1", len(plan.Commands))
			}
			cmd := plan.Commands[0]
			if cmd.Parser != "helmfile" || cmd.SemanticParser != "helmfile" || cmd.Helmfile == nil {
				t.Fatalf("parser state = (%q, %q, %v), want helmfile semantic", cmd.Parser, cmd.SemanticParser, cmd.Helmfile)
			}
			got := cmd.Helmfile
			if got.Verb != tt.wantVerb ||
				got.Environment != tt.wantEnvironment ||
				got.Namespace != tt.wantNamespace ||
				got.KubeContext != tt.wantKubeContext ||
				got.Interactive != tt.wantInteractive ||
				got.Purge != tt.wantPurge {
				t.Fatalf("Helmfile = %+v, want verb=%q env=%q namespace=%q kubeContext=%q interactive=%v purge=%v",
					got, tt.wantVerb, tt.wantEnvironment, tt.wantNamespace, tt.wantKubeContext, tt.wantInteractive, tt.wantPurge)
			}
			if tt.wantFile != "" {
				if len(got.Files) != 1 || got.Files[0] != tt.wantFile {
					t.Fatalf("Files=%#v, want [%q]", got.Files, tt.wantFile)
				}
			}
			for _, selector := range tt.wantSelectors {
				if !containsTestString(got.Selectors, selector) {
					t.Fatalf("Selectors=%#v, want %q", got.Selectors, selector)
				}
			}
			if tt.wantDryRun {
				if got.DryRun == nil || !*got.DryRun {
					t.Fatalf("DryRun=%v, want true", got.DryRun)
				}
			} else if got.DryRun != nil {
				t.Fatalf("DryRun=%v, want nil", got.DryRun)
			}
		})
	}
}

func containsTestString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
