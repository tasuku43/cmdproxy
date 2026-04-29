package policy

import "testing"

func regressionBoolPtr(v bool) *bool {
	return &v
}

func TestParserRegressionSemanticAllowBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		allow      PermissionRuleSpec
		allowed    []string
		notAllowed []string
	}{
		{
			name: "terraform plan only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "terraform", Semantic: &SemanticMatchSpec{
				Subcommand: "plan",
				Destroy:    regressionBoolPtr(false),
			}}},
			allowed: []string{
				"terraform plan",
				"terraform -chdir=infra plan",
			},
			notAllowed: []string{
				"terraform apply -auto-approve",
				"terraform destroy -auto-approve",
				"terraform plan -destroy",
				"terraform workspace select prod",
				"terraform state rm aws_instance.bad",
			},
		},
		{
			name: "docker read only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "docker", Semantic: &SemanticMatchSpec{
				VerbIn: []string{"ps", "images"},
			}}},
			allowed: []string{
				"docker ps",
				"docker images",
				"/usr/bin/docker ps",
				"command docker images",
				"env docker ps",
				"sudo docker ps",
				"timeout 10 docker ps",
				"bash -c 'docker ps'",
			},
			notAllowed: []string{
				"docker run --privileged alpine",
				"docker run -v /:/host alpine",
				"docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
				"docker system prune -a --volumes",
				"docker compose up",
				"docker compose exec web sh",
				"docker exec my-container sh",
			},
		},
		{
			name: "kubectl read only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "kubectl", Semantic: &SemanticMatchSpec{
				VerbIn: []string{"get", "describe"},
			}}},
			allowed: []string{
				"kubectl get pods",
				"kubectl describe pod x",
				"kubectl --context prod -n kube-system get pods",
				"kubectl get -- pods",
			},
			notAllowed: []string{
				"kubectl delete pod x",
				"kubectl apply -f file.yaml",
				"kubectl rollout restart deployment/x",
				"kubectl auth can-i delete pods",
			},
		},
		{
			name: "aws sts identity only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "aws", Semantic: &SemanticMatchSpec{
				Service:   "sts",
				Operation: "get-caller-identity",
			}}},
			allowed: []string{
				"aws sts get-caller-identity",
				"aws --profile dev sts get-caller-identity",
				"AWS_PROFILE=dev aws sts get-caller-identity",
				"aws --region us-east-1 sts get-caller-identity",
				"aws --region=us-east-1 sts get-caller-identity",
			},
			notAllowed: []string{
				"aws s3 rm s3://bucket/key",
				"aws iam delete-user --user-name alice",
				"aws eks update-kubeconfig --name prod",
				"aws cloudformation deploy --stack-name prod --template-file t.yml",
			},
		},
		{
			name: "gh read only areas",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{
				AreaIn: []string{"pr", "issue", "repo"},
				Verb:   "view",
			}}},
			allowed: []string{
				"gh pr view 123",
				"gh issue view 1",
				"gh repo view owner/repo",
			},
			notAllowed: []string{
				"gh pr merge 123",
				"gh issue close 1",
				"gh release delete v1.0.0",
				"gh secret set TOKEN",
				"gh api -X DELETE repos/o/r/issues/1",
				"gh api -X POST repos/o/r/issues",
				"gh api --method DELETE repos/o/r/issues/1",
			},
		},
		{
			name: "gh api get only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{
				Area:   "api",
				Method: "GET",
			}}},
			allowed: []string{
				"gh api repos/o/r",
				"gh api -X GET repos/o/r",
				"gh api --method GET repos/o/r",
			},
			notAllowed: []string{
				"gh api -X DELETE repos/o/r/issues/1",
				"gh api -X POST repos/o/r/issues",
				"gh api --method DELETE repos/o/r/issues/1",
				"gh api --method=POST repos/o/r/issues",
			},
		},
		{
			name: "gws read only list only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "gws", Semantic: &SemanticMatchSpec{
				Service:      "drive",
				ResourcePath: []string{"files"},
				Method:       "list",
			}}},
			allowed: []string{
				`gws drive files list --params '{"pageSize": 5}'`,
			},
			notAllowed: []string{
				`gws drive files delete --params '{"fileId":"abc"}'`,
				`gws auth export --unmasked`,
				`gws chat spaces messages create --params '{"parent":"spaces/xyz"}' --json '{"text":"hello"}'`,
				`gws gmail +send --to a@example.com --subject hi --body hello`,
			},
		},
		{
			name: "helm read only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "helm", Semantic: &SemanticMatchSpec{
				VerbIn: []string{"list", "status", "get"},
			}}},
			allowed: []string{
				"helm list",
				"helm status my-release",
				"helm get values my-release",
			},
			notAllowed: []string{
				"helm upgrade --install my-release ./chart",
				"helm uninstall my-release",
				"helm rollback my-release 1",
				"helm upgrade --dry-run my-release ./chart",
			},
		},
		{
			name: "helmfile diff only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "helmfile", Semantic: &SemanticMatchSpec{
				Verb: "diff",
			}}},
			allowed: []string{
				"helmfile diff",
				"helmfile --environment prod diff",
				"helmfile -e prod diff",
			},
			notAllowed: []string{
				"helmfile apply",
				"helmfile sync",
				"helmfile destroy",
				"helmfile --environment prod apply",
			},
		},
		{
			name: "argocd app get only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "argocd", Semantic: &SemanticMatchSpec{
				Verb: "app get",
			}}},
			allowed: []string{
				"argocd app get my-app",
				"argocd app get my-app --project prod",
				"argocd app get my-app --revision main",
			},
			notAllowed: []string{
				"argocd app sync my-app",
				"argocd app delete my-app",
			},
		},
		{
			name: "git read only",
			allow: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{
				VerbIn: []string{"status", "diff", "log"},
			}}},
			allowed: []string{
				"git status",
				"git diff",
				"git log",
				"git -C repo status",
			},
			notAllowed: []string{
				"git push --force origin main",
				"git reset --hard HEAD~1",
				"git clean -fdx",
			},
		},
	}

	for _, tt := range tests {
		p := NewPipeline(PipelineSpec{Permission: PermissionSpec{Allow: []PermissionRuleSpec{tt.allow}}}, Source{})
		t.Run(tt.name+"/allowed", func(t *testing.T) {
			for _, command := range tt.allowed {
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
		})
		t.Run(tt.name+"/near_miss", func(t *testing.T) {
			for _, command := range tt.notAllowed {
				t.Run(command, func(t *testing.T) {
					got, err := Evaluate(p, command)
					if err != nil {
						t.Fatalf("Evaluate() error = %v", err)
					}
					if got.Outcome == "allow" {
						t.Fatalf("near miss was allowed; decision=%+v", got)
					}
				})
			}
		})
	}
}

func TestParserRegressionStructuredDenyPrecedenceOverBroadAllows(t *testing.T) {
	tests := []struct {
		name    string
		command string
		deny    PermissionRuleSpec
	}{
		{
			name:    "terraform destroy beats broad allow",
			command: "terraform destroy -auto-approve",
			deny: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "terraform", Semantic: &SemanticMatchSpec{
				Subcommand: "destroy",
			}}},
		},
		{
			name:    "docker privileged run beats broad allow",
			command: "docker run --privileged alpine",
			deny: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "docker", Semantic: &SemanticMatchSpec{
				Verb:       "run",
				Privileged: regressionBoolPtr(true),
			}}},
		},
		{
			name:    "kubectl delete beats broad allow",
			command: "kubectl delete pod x",
			deny: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "kubectl", Semantic: &SemanticMatchSpec{
				Verb: "delete",
			}}},
		},
		{
			name:    "gh api delete beats broad allow",
			command: "gh api -X DELETE repos/o/r/issues/1",
			deny: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "gh", Semantic: &SemanticMatchSpec{
				Area:   "api",
				Method: "DELETE",
			}}},
		},
		{
			name:    "git force push beats broad allow through bash",
			command: "bash -c 'git push --force origin main'",
			deny: PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{
				Verb:  "push",
				Force: regressionBoolPtr(true),
			}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPipeline(PipelineSpec{Permission: PermissionSpec{
				Deny:  []PermissionRuleSpec{tt.deny},
				Allow: []PermissionRuleSpec{{Patterns: []string{`.*`}}},
			}}, Source{})
			got, err := Evaluate(p, tt.command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome != "deny" {
				t.Fatalf("Outcome = %q, want deny; decision=%+v", got.Outcome, got)
			}
		})
	}
}

func TestParserRegressionUnsafeShellShapesDoNotBecomeSemanticAllow(t *testing.T) {
	allowGitStatus := PermissionRuleSpec{Command: PermissionCommandSpec{Name: "git", Semantic: &SemanticMatchSpec{Verb: "status"}}}
	allowEcho := PermissionRuleSpec{Command: PermissionCommandSpec{Name: "echo"}}
	allowCat := PermissionRuleSpec{Command: PermissionCommandSpec{Name: "cat"}}
	p := NewPipeline(PipelineSpec{Permission: PermissionSpec{Allow: []PermissionRuleSpec{
		allowGitStatus,
		allowEcho,
		allowCat,
	}}}, Source{})

	tests := []string{
		"git status > /tmp/out",
		"echo $(git status)",
		"cat <(git status)",
		"(git status)",
		"git status &",
		"git status | sh",
		"git status; rm -rf /tmp/x",
		"git status && rm -rf /tmp/x",
		"git status || rm -rf /tmp/x",
	}

	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			got, err := Evaluate(p, command)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got.Outcome == "allow" {
				t.Fatalf("unsafe shell shape was allowed; decision=%+v", got)
			}
		})
	}
}
