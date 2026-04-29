package app

import (
	"errors"
	"regexp"
	"strings"

	commandpkg "github.com/tasuku43/cc-bash-guard/internal/domain/command"
	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
)

type SuggestOptions struct {
	Decision string
}

type SuggestResult struct {
	Command  string              `json:"command"`
	Decision string              `json:"decision"`
	Reason   string              `json:"reason,omitempty"`
	Policy   SuggestedPolicySpec `json:"policy"`
}

type SuggestedPolicySpec struct {
	Permission policy.PermissionSpec `yaml:"permission" json:"permission"`
}

func RunSuggest(command string, opts SuggestOptions) (SuggestResult, error) {
	decision := strings.TrimSpace(opts.Decision)
	if decision != "" && !validSuggestDecision(decision) {
		return SuggestResult{}, errors.New("decision must be one of allow, ask, deny")
	}
	plan := commandpkg.Parse(command)
	if len(plan.Diagnostics) > 0 || len(plan.Commands) == 0 {
		if decision == "" {
			decision = "ask"
		}
		rule := suggestedPatternRule(command, decision)
		return suggestResult(command, decision, "semantic parsing was not reliable; suggested a narrow anchored pattern", rule), nil
	}
	cmd := plan.Commands[0]
	if len(plan.Commands) != 1 || plan.Shape.Kind != commandpkg.ShellShapeSimple {
		if decision == "" {
			decision = "ask"
		}
		rule := suggestedPatternRule(command, decision)
		return suggestResult(command, decision, "compound or non-simple shell shape; suggested a narrow anchored pattern", rule), nil
	}

	rule, semanticOK := suggestedSemanticRule(cmd, command)
	if !semanticOK {
		if decision == "" {
			decision = "ask"
		}
		rule = suggestedPatternRule(command, decision)
		return suggestResult(command, decision, "no semantic parser is available for this command; suggested a narrow anchored pattern", rule), nil
	}
	if decision == "" {
		decision, _ = classifySuggestedDecision(cmd)
	}
	rule.Message = suggestedMessage(decision, rule.Name)
	addPositiveTest(&rule, decision, command)
	if nearMiss := suggestedNearMiss(cmd, decision); nearMiss != "" {
		rule.Test.Abstain = append(rule.Test.Abstain, nearMiss)
	}
	return suggestResult(command, decision, classificationReason(cmd, decision), rule), nil
}

func validSuggestDecision(decision string) bool {
	switch decision {
	case "allow", "ask", "deny":
		return true
	default:
		return false
	}
}

func suggestResult(command, decision, reason string, rule policy.PermissionRuleSpec) SuggestResult {
	spec := SuggestedPolicySpec{}
	switch decision {
	case "allow":
		spec.Permission.Allow = []policy.PermissionRuleSpec{rule}
	case "deny":
		spec.Permission.Deny = []policy.PermissionRuleSpec{rule}
	default:
		spec.Permission.Ask = []policy.PermissionRuleSpec{rule}
	}
	return SuggestResult{Command: command, Decision: decision, Reason: reason, Policy: spec}
}

func suggestedSemanticRule(cmd commandpkg.Command, raw string) (policy.PermissionRuleSpec, bool) {
	if _, ok := semanticpkg.Lookup(cmd.Program); !ok {
		return policy.PermissionRuleSpec{}, false
	}
	semantic := semanticSpecForCommand(cmd)
	if semantic == nil {
		return policy.PermissionRuleSpec{}, false
	}
	name := strings.TrimSpace(cmd.Program + " " + semanticName(cmd))
	return policy.PermissionRuleSpec{
		Name: name,
		Command: policy.PermissionCommandSpec{
			Name:     cmd.Program,
			Semantic: semantic,
		},
	}, true
}

func semanticSpecForCommand(cmd commandpkg.Command) *policy.SemanticMatchSpec {
	switch {
	case cmd.Git != nil:
		s := &policy.SemanticMatchSpec{Verb: cmd.Git.Verb}
		setBool(&s.Force, cmd.Git.Force)
		setBool(&s.ForceWithLease, cmd.Git.ForceWithLease)
		setBool(&s.ForceIfIncludes, cmd.Git.ForceIfIncludes)
		setBool(&s.Hard, cmd.Git.Hard)
		setBool(&s.Recursive, cmd.Git.Recursive)
		setBool(&s.IncludeIgnored, cmd.Git.IncludeIgnored)
		return nilIfEmptySemantic(s)
	case cmd.AWS != nil:
		s := &policy.SemanticMatchSpec{Service: cmd.AWS.Service, Operation: cmd.AWS.Operation}
		return nilIfEmptySemantic(s)
	case cmd.Kubectl != nil:
		s := &policy.SemanticMatchSpec{Verb: cmd.Kubectl.Verb, ResourceType: cmd.Kubectl.ResourceType, ResourceName: cmd.Kubectl.ResourceName, Namespace: cmd.Kubectl.Namespace}
		setBool(&s.Force, cmd.Kubectl.Force)
		return nilIfEmptySemantic(s)
	case cmd.Gh != nil:
		s := &policy.SemanticMatchSpec{Area: cmd.Gh.Area, Verb: cmd.Gh.Verb}
		setBool(&s.Force, cmd.Gh.Force)
		setBool(&s.Admin, cmd.Gh.Admin)
		return nilIfEmptySemantic(s)
	case cmd.Helmfile != nil:
		s := &policy.SemanticMatchSpec{Verb: cmd.Helmfile.Verb, Environment: cmd.Helmfile.Environment, Namespace: cmd.Helmfile.Namespace, KubeContext: cmd.Helmfile.KubeContext}
		setBool(&s.Interactive, cmd.Helmfile.Interactive)
		return nilIfEmptySemantic(s)
	case cmd.Gws != nil:
		s := &policy.SemanticMatchSpec{Service: cmd.Gws.Service, Method: cmd.Gws.Method}
		setBool(&s.ReadOnly, cmd.Gws.ReadOnly)
		setBool(&s.Mutating, cmd.Gws.Mutating)
		setBool(&s.Destructive, cmd.Gws.Destructive)
		return nilIfEmptySemantic(s)
	case cmd.Helm != nil:
		s := &policy.SemanticMatchSpec{Verb: cmd.Helm.Verb, Subverb: cmd.Helm.Subverb, Release: cmd.Helm.Release, Chart: cmd.Helm.Chart, Namespace: cmd.Helm.Namespace, KubeContext: cmd.Helm.KubeContext}
		setBool(&s.DryRun, cmd.Helm.DryRun)
		setBool(&s.Force, cmd.Helm.Force)
		return nilIfEmptySemantic(s)
	case cmd.Docker != nil:
		s := &policy.SemanticMatchSpec{Verb: cmd.Docker.Verb, Subverb: cmd.Docker.Subverb, Container: cmd.Docker.Container, Image: cmd.Docker.Image}
		setBool(&s.Force, cmd.Docker.Force)
		setBool(&s.Privileged, cmd.Docker.Privileged)
		return nilIfEmptySemantic(s)
	case cmd.Terraform != nil:
		s := &policy.SemanticMatchSpec{Subcommand: cmd.Terraform.Subcommand, WorkspaceSubcommand: cmd.Terraform.WorkspaceSubcommand, StateSubcommand: cmd.Terraform.StateSubcommand, GlobalChdir: cmd.Terraform.GlobalChdir}
		setBool(&s.Destroy, cmd.Terraform.Destroy)
		setBool(&s.AutoApprove, cmd.Terraform.AutoApprove)
		return nilIfEmptySemantic(s)
	case cmd.ArgoCD != nil:
		s := &policy.SemanticMatchSpec{Verb: cmd.ArgoCD.Verb, AppName: cmd.ArgoCD.AppName, Project: cmd.ArgoCD.Project}
		return nilIfEmptySemantic(s)
	default:
		return nil
	}
}

func nilIfEmptySemantic(s *policy.SemanticMatchSpec) *policy.SemanticMatchSpec {
	if s == nil || policy.IsZeroSemanticMatchSpec(*s) {
		return nil
	}
	return s
}

func setBool(dst **bool, value bool) {
	if value {
		v := true
		*dst = &v
	}
}

func semanticName(cmd commandpkg.Command) string {
	switch {
	case cmd.Git != nil:
		if cmd.Git.Force || cmd.Git.ForceWithLease || cmd.Git.ForceIfIncludes {
			return strings.TrimSpace(cmd.Git.Verb + " force")
		}
		return cmd.Git.Verb
	case cmd.AWS != nil:
		return strings.TrimSpace(cmd.AWS.Service + " " + cmd.AWS.Operation)
	case cmd.Kubectl != nil:
		return strings.TrimSpace(cmd.Kubectl.Verb + " " + cmd.Kubectl.ResourceType)
	case cmd.Gh != nil:
		return strings.TrimSpace(cmd.Gh.Area + " " + cmd.Gh.Verb)
	case cmd.Helmfile != nil:
		return cmd.Helmfile.Verb
	case cmd.ArgoCD != nil:
		return cmd.ArgoCD.Verb
	case cmd.Gws != nil:
		return strings.TrimSpace(cmd.Gws.Service + " " + cmd.Gws.Method)
	case cmd.Helm != nil:
		return strings.TrimSpace(cmd.Helm.Verb + " " + cmd.Helm.Subverb)
	case cmd.Docker != nil:
		return strings.TrimSpace(cmd.Docker.Verb + " " + cmd.Docker.Subverb)
	case cmd.Terraform != nil:
		return cmd.Terraform.Subcommand
	default:
		return cmd.Program
	}
}

func classifySuggestedDecision(cmd commandpkg.Command) (string, bool) {
	switch {
	case cmd.Git != nil:
		if cmd.Git.Force || cmd.Git.Hard || (cmd.Git.Verb == "clean" && cmd.Git.Force) {
			return "deny", true
		}
		if cmd.Git.Verb == "status" || cmd.Git.Verb == "diff" || cmd.Git.Verb == "log" || cmd.Git.Verb == "show" {
			return "allow", true
		}
	case cmd.AWS != nil:
		if cmd.AWS.Service == "sts" && cmd.AWS.Operation == "get-caller-identity" {
			return "allow", true
		}
	case cmd.Kubectl != nil:
		if cmd.Kubectl.Verb == "delete" || cmd.Kubectl.Verb == "apply" || cmd.Kubectl.Verb == "replace" || cmd.Kubectl.Verb == "patch" {
			return "ask", true
		}
		if cmd.Kubectl.Verb == "get" || cmd.Kubectl.Verb == "describe" {
			return "allow", true
		}
	case cmd.ArgoCD != nil:
		if cmd.ArgoCD.Verb == "app delete" {
			return "deny", true
		}
		if cmd.ArgoCD.Verb == "app get" || cmd.ArgoCD.Verb == "app list" || cmd.ArgoCD.Verb == "app diff" {
			return "allow", true
		}
	case cmd.Helmfile != nil:
		if cmd.Helmfile.Verb == "destroy" || cmd.Helmfile.Verb == "apply" || cmd.Helmfile.Verb == "sync" {
			return "ask", true
		}
		if cmd.Helmfile.Verb == "diff" || cmd.Helmfile.Verb == "lint" {
			return "allow", true
		}
	case cmd.Gws != nil:
		if cmd.Gws.Destructive || cmd.Gws.Mutating || cmd.Gws.Upload || cmd.Gws.Unmasked {
			return "ask", true
		}
		if cmd.Gws.ReadOnly {
			return "allow", true
		}
	case cmd.Helm != nil:
		if cmd.Helm.Force || cmd.Helm.Verb == "uninstall" || cmd.Helm.Verb == "upgrade" || cmd.Helm.Verb == "install" {
			return "ask", true
		}
		if cmd.Helm.Verb == "status" || cmd.Helm.Verb == "list" || cmd.Helm.Verb == "template" || cmd.Helm.Verb == "lint" {
			return "allow", true
		}
	case cmd.Docker != nil:
		if cmd.Docker.Privileged || cmd.Docker.Force || cmd.Docker.Verb == "run" || cmd.Docker.Verb == "exec" || cmd.Docker.Verb == "rm" {
			return "ask", true
		}
		if cmd.Docker.Verb == "ps" || cmd.Docker.Verb == "images" || cmd.Docker.Verb == "inspect" || cmd.Docker.Verb == "logs" {
			return "allow", true
		}
	case cmd.Terraform != nil:
		if cmd.Terraform.Destroy || cmd.Terraform.AutoApprove || cmd.Terraform.Subcommand == "apply" {
			return "ask", true
		}
		if cmd.Terraform.Subcommand == "plan" || cmd.Terraform.Subcommand == "validate" || cmd.Terraform.Subcommand == "fmt" || cmd.Terraform.Subcommand == "version" {
			return "allow", true
		}
	}
	return "ask", false
}

func classificationReason(cmd commandpkg.Command, decision string) string {
	if _, ok := classifySuggestedDecision(cmd); !ok {
		return "automatic classification was uncertain; defaulted to ask"
	}
	return "automatic classification selected " + decision
}

func suggestedMessage(decision, name string) string {
	switch decision {
	case "allow":
		return "allow " + name
	case "deny":
		return name + " is blocked"
	default:
		return "ask before " + name
	}
}

func addPositiveTest(rule *policy.PermissionRuleSpec, decision string, command string) {
	switch decision {
	case "allow":
		rule.Test.Allow = []string{command}
	case "deny":
		rule.Test.Deny = []string{command}
	default:
		rule.Test.Ask = []string{command}
	}
}

func suggestedNearMiss(cmd commandpkg.Command, decision string) string {
	switch {
	case cmd.Git != nil:
		switch cmd.Git.Verb {
		case "status":
			return "git push origin main"
		case "push":
			return "git push origin main"
		default:
			return "git status"
		}
	case cmd.AWS != nil:
		if cmd.AWS.Service == "sts" {
			return "aws iam list-users"
		}
		return "aws sts get-caller-identity"
	case cmd.ArgoCD != nil:
		if cmd.ArgoCD.Verb == "app delete" && cmd.ArgoCD.AppName != "" {
			return "argocd app delete other-app"
		}
		return "argocd app list"
	case cmd.Kubectl != nil:
		return "kubectl get pods"
	case cmd.Helmfile != nil:
		return "helmfile diff"
	case cmd.Gws != nil:
		return "gws drive files list"
	case cmd.Helm != nil:
		return "helm status other-release"
	case cmd.Docker != nil:
		return "docker ps"
	case cmd.Terraform != nil:
		return "terraform plan"
	default:
		return ""
	}
}

func suggestedPatternRule(command, decision string) policy.PermissionRuleSpec {
	name := "narrow pattern for " + firstWord(command)
	pattern := "^" + regexp.QuoteMeta(strings.TrimSpace(command)) + "$"
	rule := policy.PermissionRuleSpec{
		Name:     name,
		Patterns: []string{pattern},
		Message:  suggestedMessage(decision, name),
	}
	addPositiveTest(&rule, decision, command)
	rule.Test.Abstain = []string{command + " --other"}
	return rule
}

func firstWord(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "command"
	}
	return fields[0]
}
