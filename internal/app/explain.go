package app

import (
	"errors"
	"sort"
	"strings"

	"github.com/tasuku43/cc-bash-guard/internal/adapter/claude"
	commandpkg "github.com/tasuku43/cc-bash-guard/internal/domain/command"
	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
	configrepo "github.com/tasuku43/cc-bash-guard/internal/infra/config"
)

type ExplainResult struct {
	Command        string                `json:"command"`
	Parsed         ExplainParsed         `json:"parsed"`
	Policy         ExplainSourceDecision `json:"policy"`
	ClaudeSettings ExplainSourceDecision `json:"claude_settings"`
	Final          ExplainFinalDecision  `json:"final"`
	Trace          []policy.TraceStep    `json:"trace,omitempty"`
}

type ExplainParsed struct {
	Shape          string                 `json:"shape"`
	ShapeFlags     []string               `json:"shape_flags,omitempty"`
	Diagnostics    []string               `json:"diagnostics,omitempty"`
	Segments       []ExplainSegment       `json:"segments"`
	Normalized     []ExplainNormalization `json:"normalized,omitempty"`
	EvaluatedInner *ExplainSegment        `json:"evaluated_inner,omitempty"`
	EvaluationOnly bool                   `json:"evaluation_only_normalization,omitempty"`
}

type ExplainNormalization struct {
	ProgramToken string `json:"program_token"`
	CommandName  string `json:"command_name"`
	Reason       string `json:"reason"`
}

type ExplainSegment struct {
	CommandName  string         `json:"command_name,omitempty"`
	ProgramToken string         `json:"program_token,omitempty"`
	Parser       string         `json:"parser"`
	Semantic     map[string]any `json:"semantic,omitempty"`
	Raw          string         `json:"raw,omitempty"`
}

type ExplainSourceDecision struct {
	Outcome     string            `json:"outcome"`
	MatchedRule *ExplainRuleMatch `json:"matched_rule,omitempty"`
	Matched     any               `json:"matched"`
}

type ExplainRuleMatch struct {
	Name    string `json:"name,omitempty"`
	Source  string `json:"source,omitempty"`
	Bucket  string `json:"bucket,omitempty"`
	Index   int    `json:"index"`
	Message string `json:"message,omitempty"`
}

type ExplainFinalDecision struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
}

func RunExplain(command string, env Env) (ExplainResult, error) {
	result, _, err := EvaluateForCommand(command, env, false)
	return result, err
}

func EvaluateForCommand(command string, env Env, autoVerify bool) (ExplainResult, policy.Decision, error) {
	loaded, err := loadVerifiedPipelineForEvaluation(env, autoVerify)
	plan := commandpkg.Parse(command)
	result := ExplainResult{
		Command: command,
		Parsed:  explainParsed(plan),
	}
	if err != nil {
		result.Policy = ExplainSourceDecision{Outcome: "error", Matched: nil}
		result.ClaudeSettings = ExplainSourceDecision{Outcome: "abstain", Matched: nil}
		result.Final = ExplainFinalDecision{Outcome: "deny", Reason: err.Error() + "; run cc-bash-guard verify"}
		return result, policy.Decision{}, err
	}

	policyDecision, err := policy.Evaluate(loaded.Pipeline, command)
	if err != nil {
		result.Policy = ExplainSourceDecision{Outcome: "error", Matched: nil}
		result.ClaudeSettings = ExplainSourceDecision{Outcome: "abstain", Matched: nil}
		result.Final = ExplainFinalDecision{Outcome: "ask", Reason: err.Error()}
		return result, policy.Decision{}, err
	}

	claudeDecision := claude.ExplainCommand(command, env.Cwd, env.Home)
	finalDecision := claude.ApplyPermissionBridge(claude.Tool, policyDecision, env.Cwd, env.Home)

	result.Policy = explainPolicyDecision(policyDecision)
	result.ClaudeSettings = explainClaudeDecision(claudeDecision)
	result.Final = ExplainFinalDecision{Outcome: finalDecision.Outcome, Reason: finalReason(policyDecision, claudeDecision.Outcome, finalDecision)}
	result.Trace = finalDecision.Trace
	return result, finalDecision, nil
}

func loadVerifiedPipelineForEvaluation(env Env, autoVerify bool) (configrepo.Loaded, error) {
	loaded := configrepo.LoadEffectiveForHookTool(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, claude.Tool)
	if len(loaded.Errors) == 0 {
		return loaded, nil
	}
	if shouldAttemptImplicitVerify(loaded.Errors) {
		if !autoVerify {
			return loaded, errors.New("verified artifact missing or stale; run cc-bash-guard verify")
		}
		if err := ensureVerifiedArtifacts(env, claude.Tool); err == nil {
			loaded = configrepo.LoadEffectiveForHookTool(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, claude.Tool)
		} else {
			return loaded, err
		}
	}
	if len(loaded.Errors) > 0 {
		return loaded, errors.New(strings.Join(policy.ErrorStrings(loaded.Errors), "; "))
	}
	return loaded, nil
}

func explainParsed(plan commandpkg.CommandPlan) ExplainParsed {
	parsed := ExplainParsed{
		Shape:      string(plan.Shape.Kind),
		ShapeFlags: plan.Shape.Flags(),
		Segments:   make([]ExplainSegment, 0, len(plan.Commands)),
	}
	for _, diagnostic := range plan.Diagnostics {
		parsed.Diagnostics = append(parsed.Diagnostics, diagnostic.Message)
	}
	for _, cmd := range plan.Commands {
		parsed.Segments = append(parsed.Segments, explainSegment(cmd))
	}
	for _, normalized := range plan.Normalized {
		parsed.Normalized = append(parsed.Normalized, ExplainNormalization{
			ProgramToken: normalized.OriginalToken,
			CommandName:  normalized.CommandName,
			Reason:       normalized.Reason,
		})
		if normalized.Reason == "shell_dash_c" {
			parsed.Shape = "shell_c"
			parsed.EvaluationOnly = true
			if len(parsed.Segments) > 0 {
				inner := parsed.Segments[0]
				parsed.EvaluatedInner = &inner
			}
		}
	}
	return parsed
}

func explainSegment(cmd commandpkg.Command) ExplainSegment {
	parser := cmd.Parser
	if parser == "" {
		parser = "generic"
	}
	return ExplainSegment{
		CommandName:  cmd.Program,
		ProgramToken: cmd.ProgramToken,
		Parser:       parser,
		Semantic:     semanticMap(cmd),
		Raw:          cmd.Raw,
	}
}

func semanticMap(cmd commandpkg.Command) map[string]any {
	fields := map[string]any{}
	switch {
	case cmd.Git != nil:
		addString(fields, "verb", cmd.Git.Verb)
		addString(fields, "remote", cmd.Git.Remote)
		addString(fields, "branch", cmd.Git.Branch)
		addString(fields, "ref", cmd.Git.Ref)
		addBool(fields, "force", cmd.Git.Force)
		addBool(fields, "force_with_lease", cmd.Git.ForceWithLease)
		addBool(fields, "force_if_includes", cmd.Git.ForceIfIncludes)
		addBool(fields, "hard", cmd.Git.Hard)
		addBool(fields, "recursive", cmd.Git.Recursive)
		addBool(fields, "include_ignored", cmd.Git.IncludeIgnored)
		addBool(fields, "cached", cmd.Git.Cached)
		addBool(fields, "staged", cmd.Git.Staged)
	case cmd.AWS != nil:
		addString(fields, "service", cmd.AWS.Service)
		addString(fields, "operation", cmd.AWS.Operation)
		addString(fields, "profile", cmd.AWS.Profile)
		addString(fields, "region", cmd.AWS.Region)
	case cmd.Kubectl != nil:
		addString(fields, "verb", cmd.Kubectl.Verb)
		addString(fields, "subverb", cmd.Kubectl.Subverb)
		addString(fields, "resource_type", cmd.Kubectl.ResourceType)
		addString(fields, "resource_name", cmd.Kubectl.ResourceName)
		addString(fields, "namespace", cmd.Kubectl.Namespace)
		addString(fields, "context", cmd.Kubectl.Context)
	case cmd.Gh != nil:
		addString(fields, "area", cmd.Gh.Area)
		addString(fields, "verb", cmd.Gh.Verb)
		addString(fields, "repo", cmd.Gh.Repo)
		addString(fields, "hostname", cmd.Gh.Hostname)
	case cmd.Helmfile != nil:
		addString(fields, "verb", cmd.Helmfile.Verb)
		addString(fields, "environment", cmd.Helmfile.Environment)
		addString(fields, "namespace", cmd.Helmfile.Namespace)
		addString(fields, "kube_context", cmd.Helmfile.KubeContext)
	case cmd.ArgoCD != nil:
		addString(fields, "verb", cmd.ArgoCD.Verb)
		addString(fields, "app_name", cmd.ArgoCD.AppName)
		addString(fields, "project", cmd.ArgoCD.Project)
		addString(fields, "revision", cmd.ArgoCD.Revision)
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func addString(fields map[string]any, key string, value string) {
	if strings.TrimSpace(value) != "" {
		fields[key] = value
	}
}

func addBool(fields map[string]any, key string, value bool) {
	if value {
		fields[key] = value
	}
}

func explainPolicyDecision(decision policy.Decision) ExplainSourceDecision {
	outcome := decision.Outcome
	if outcome == "" {
		outcome = "abstain"
	}
	return ExplainSourceDecision{
		Outcome:     outcome,
		MatchedRule: matchedPolicyRule(decision.Trace, outcome),
		Matched:     nil,
	}
}

func matchedPolicyRule(trace []policy.TraceStep, outcome string) *ExplainRuleMatch {
	for i := len(trace) - 1; i >= 0; i-- {
		step := trace[i]
		if step.Action != "permission" || step.Effect != outcome || step.Name == "no_match" || step.Name == "fail_closed" || step.Name == "composition" || step.Name == "composition.command" {
			continue
		}
		bucket := ""
		index := 0
		source := ""
		if step.Source != nil {
			bucket = step.Source.Section
			index = step.Source.Index
			source = step.Source.Path
		}
		if bucket == "" && outcome != "" {
			bucket = "permission." + outcome
		}
		name := strings.TrimSpace(step.Name)
		if name == "" {
			name = bucket + "[" + itoa(index) + "]"
		}
		return &ExplainRuleMatch{Name: name, Source: source, Bucket: bucket, Index: index, Message: step.Message}
	}
	return nil
}

func explainClaudeDecision(decision claude.PermissionExplanation) ExplainSourceDecision {
	outcome := decision.Outcome
	if outcome == "" || outcome == "default" {
		outcome = "abstain"
	}
	var matched any
	if decision.Matched != nil {
		matched = decision.Matched
	}
	return ExplainSourceDecision{Outcome: outcome, Matched: matched}
}

func finalReason(policyDecision policy.Decision, claudeOutcome string, finalDecision policy.Decision) string {
	policyOutcome := policyDecision.Outcome
	if policyOutcome == "" {
		policyOutcome = "abstain"
	}
	if claudeOutcome == "" || claudeOutcome == "default" {
		claudeOutcome = "abstain"
	}
	switch {
	case policyOutcome == "deny":
		return "cc-bash-guard policy denied"
	case claudeOutcome == "deny":
		return "Claude settings denied"
	case policyOutcome == "ask" || claudeOutcome == "ask":
		return "at least one source asked"
	case policyOutcome == "allow" || claudeOutcome == "allow":
		return "at least one source allowed and no source denied or asked"
	default:
		if finalDecision.Reason == "default_fallback" {
			return "all permission sources abstained; fallback ask"
		}
		return "all permission sources abstained; fallback ask"
	}
}

func ExplainHasParseError(result ExplainResult) bool {
	for _, diagnostic := range result.Parsed.Diagnostics {
		if strings.TrimSpace(diagnostic) != "" {
			return true
		}
	}
	return false
}

func SortedSemanticKeys(fields map[string]any) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	n := v
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
