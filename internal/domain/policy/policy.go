package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	commandpkg "github.com/tasuku43/cc-bash-guard/internal/domain/command"
	"github.com/tasuku43/cc-bash-guard/internal/domain/invocation"
	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
	"gopkg.in/yaml.v3"
)

type PipelineSpec struct {
	Include []string `yaml:"include" json:"-"`
	// Rewrite is retained only to reject unsupported configs with guidance.
	// It is not a supported user-facing feature.
	Rewrite    []map[string]any `yaml:"rewrite" json:"rewrite,omitempty"`
	Permission PermissionSpec   `yaml:"permission" json:"permission,omitempty"`
	Test       PipelineTestSpec `yaml:"test" json:"test,omitempty"`
}

type PermissionSpec struct {
	Deny  []PermissionRuleSpec `yaml:"deny" json:"deny,omitempty"`
	Ask   []PermissionRuleSpec `yaml:"ask" json:"ask,omitempty"`
	Allow []PermissionRuleSpec `yaml:"allow" json:"allow,omitempty"`
}

type PermissionRuleSpec struct {
	Name     string                `yaml:"name" json:"name,omitempty"`
	Command  PermissionCommandSpec `yaml:"command" json:"command,omitempty"`
	Env      PermissionEnvSpec     `yaml:"env" json:"env,omitempty"`
	Patterns []string              `yaml:"patterns" json:"patterns,omitempty"`
	Message  string                `yaml:"message" json:"message,omitempty"`
	Test     PermissionTestSpec    `yaml:"test" json:"test,omitempty"`
	Source   Source                `yaml:"-" json:"source,omitempty"`
}

type PermissionCommandSpec struct {
	Name               string                 `yaml:"name" json:"name,omitempty"`
	NameIn             []string               `yaml:"name_in" json:"name_in,omitempty"`
	ShapeFlagsAny      []string               `yaml:"shape_flags_any" json:"shape_flags_any,omitempty"`
	ShapeFlagsAll      []string               `yaml:"shape_flags_all" json:"shape_flags_all,omitempty"`
	ShapeFlagsNone     []string               `yaml:"shape_flags_none" json:"shape_flags_none,omitempty"`
	ToleratedRedirects ToleratedRedirectsSpec `yaml:"tolerated_redirects" json:"tolerated_redirects,omitempty"`
	Semantic           *SemanticMatchSpec     `yaml:"semantic" json:"semantic,omitempty"`
}

type ToleratedRedirectsSpec struct {
	Only []string `yaml:"only" json:"only,omitempty"`
}

type PermissionEnvSpec struct {
	Requires []string `yaml:"requires" json:"requires,omitempty"`
	Missing  []string `yaml:"missing" json:"missing,omitempty"`
}

type PermissionTestSpec struct {
	Allow   []string `yaml:"allow" json:"allow,omitempty"`
	Ask     []string `yaml:"ask" json:"ask,omitempty"`
	Deny    []string `yaml:"deny" json:"deny,omitempty"`
	Abstain []string `yaml:"abstain" json:"abstain,omitempty"`
	Pass    []string `yaml:"pass" json:"pass,omitempty"`
}

type PipelineTestSpec []PipelineExpectCase

type PipelineExpectCase struct {
	In string `yaml:"in" json:"in,omitempty"`
	// Rewritten is retained only to reject unsupported tests with guidance.
	// cc-bash-guard tests assert permission decisions, not rewritten commands.
	Rewritten           string `yaml:"rewritten" json:"rewritten,omitempty"`
	Decision            string `yaml:"decision" json:"decision,omitempty"`
	AssertPolicyOutcome bool   `yaml:"-" json:"assert_policy_outcome,omitempty"`
	Source              Source `yaml:"-" json:"source,omitempty"`
}

func (s *PipelineTestSpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var cases []PipelineExpectCase
		if err := node.Decode(&cases); err != nil {
			return err
		}
		*s = cases
		return nil
	case yaml.MappingNode:
		var cases []PipelineExpectCase
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if seen[key] {
				return fmt.Errorf("test.%s is duplicated", key)
			}
			seen[key] = true
			switch key {
			case "deny", "ask", "allow", "abstain":
			default:
				return fmt.Errorf("test.%s is not supported; bucketed test keys must be one of deny, ask, allow, abstain", key)
			}
			var inputs []string
			if err := node.Content[i+1].Decode(&inputs); err != nil {
				return fmt.Errorf("test.%s must be a sequence of command strings: %w", key, err)
			}
			for _, in := range inputs {
				cases = append(cases, PipelineExpectCase{
					In:                  in,
					Decision:            key,
					AssertPolicyOutcome: key == "abstain",
				})
			}
		}
		*s = cases
		return nil
	default:
		return fmt.Errorf("test must be either a sequence of cases or a mapping of deny/ask/allow/abstain buckets")
	}
}

type MatchSpec struct {
	Command               string             `yaml:"command" json:"command,omitempty"`
	CommandIn             []string           `yaml:"command_in" json:"command_in,omitempty"`
	CommandIsAbsolutePath bool               `yaml:"command_is_absolute_path" json:"command_is_absolute_path,omitempty"`
	Subcommand            string             `yaml:"subcommand" json:"subcommand,omitempty"`
	ArgsContains          []string           `yaml:"args_contains" json:"args_contains,omitempty"`
	ArgsPrefixes          []string           `yaml:"args_prefixes" json:"args_prefixes,omitempty"`
	EnvRequires           []string           `yaml:"env_requires" json:"env_requires,omitempty"`
	EnvMissing            []string           `yaml:"env_missing" json:"env_missing,omitempty"`
	Semantic              *SemanticMatchSpec `yaml:"semantic" json:"semantic,omitempty"`
}

type Source struct {
	Layer   string `json:"layer"`
	Path    string `json:"path"`
	Section string `json:"section,omitempty"`
	Index   int    `json:"index"`
}

type Pipeline struct {
	PipelineSpec
	Source   Source `json:"source"`
	prepared preparedPipeline
}

type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Issues, "; ")
}

type Decision struct {
	Outcome         string
	Explicit        bool
	Reason          string
	Command         string
	OriginalCommand string
	Message         string
	Trace           []TraceStep
}

type TraceStep struct {
	Action              string   `json:"action"`
	Name                string   `json:"name,omitempty"`
	Effect              string   `json:"effect,omitempty"`
	Explicit            bool     `json:"explicit,omitempty"`
	RuleType            string   `json:"rule_type,omitempty"`
	From                string   `json:"from,omitempty"`
	To                  string   `json:"to,omitempty"`
	Message             string   `json:"message,omitempty"`
	Reason              string   `json:"reason,omitempty"`
	Command             string   `json:"command,omitempty"`
	CommandIndex        *int     `json:"command_index,omitempty"`
	Parser              string   `json:"parser,omitempty"`
	SemanticParser      string   `json:"semantic_parser,omitempty"`
	SemanticMatch       bool     `json:"semantic_match,omitempty"`
	SemanticFields      []string `json:"semantic_fields,omitempty"`
	AWSService          string   `json:"aws_service,omitempty"`
	AWSOperation        string   `json:"aws_operation,omitempty"`
	AWSProfile          string   `json:"aws_profile,omitempty"`
	AWSRegion           string   `json:"aws_region,omitempty"`
	KubectlVerb         string   `json:"kubectl_verb,omitempty"`
	KubectlSubverb      string   `json:"kubectl_subverb,omitempty"`
	KubectlResourceType string   `json:"kubectl_resource_type,omitempty"`
	KubectlResourceName string   `json:"kubectl_resource_name,omitempty"`
	KubectlNamespace    string   `json:"kubectl_namespace,omitempty"`
	KubectlContext      string   `json:"kubectl_context,omitempty"`
	GhArea              string   `json:"gh_area,omitempty"`
	GhVerb              string   `json:"gh_verb,omitempty"`
	GhRepo              string   `json:"gh_repo,omitempty"`
	GhHostname          string   `json:"gh_hostname,omitempty"`
	GhMethod            string   `json:"gh_method,omitempty"`
	GhEndpoint          string   `json:"gh_endpoint,omitempty"`
	HelmfileVerb        string   `json:"helmfile_verb,omitempty"`
	HelmfileEnvironment string   `json:"helmfile_environment,omitempty"`
	HelmfileFile        string   `json:"helmfile_file,omitempty"`
	HelmfileNamespace   string   `json:"helmfile_namespace,omitempty"`
	HelmfileKubeContext string   `json:"helmfile_kube_context,omitempty"`
	HelmfileSelectors   []string `json:"helmfile_selectors,omitempty"`
	HelmfileInteractive *bool    `json:"helmfile_interactive,omitempty"`
	ArgoCDVerb          string   `json:"argocd_verb,omitempty"`
	ArgoCDAppName       string   `json:"argocd_app_name,omitempty"`
	ArgoCDProject       string   `json:"argocd_project,omitempty"`
	ArgoCDRevision      string   `json:"argocd_revision,omitempty"`
	FromShape           string   `json:"from_shape,omitempty"`
	FromShapeFlags      []string `json:"from_shape_flags,omitempty"`
	FromSafe            *bool    `json:"from_safe,omitempty"`
	ToShape             string   `json:"to_shape,omitempty"`
	ToShapeFlags        []string `json:"to_shape_flags,omitempty"`
	ToSafe              *bool    `json:"to_safe,omitempty"`
	Program             string   `json:"program,omitempty"`
	ProgramToken        string   `json:"program_token,omitempty"`
	NormalizedCommand   string   `json:"normalized_command,omitempty"`
	NormalizedReason    string   `json:"normalized_reason,omitempty"`
	ActionPath          []string `json:"action_path,omitempty"`
	Shape               string   `json:"shape,omitempty"`
	ShapeFlags          []string `json:"shape_flags,omitempty"`
	Relaxed             bool     `json:"relaxed,omitempty"`
	Continue            bool     `json:"continue,omitempty"`
	Source              *Source  `json:"source,omitempty"`
}

const (
	permissionRuleTypeRaw        = "raw"
	permissionRuleTypeStructured = "structured"
)

type preparedPipeline struct {
	Ready bool
	Deny  []preparedPermissionRule
	Ask   []preparedPermissionRule
	Allow []preparedPermissionRule
}

type preparedPermissionRule struct {
	Spec     PermissionRuleSpec
	Selector preparedPermissionSelector
}

type preparedSelector struct {
	Match       MatchSpec
	HasPattern  bool
	Pattern     *regexp.Regexp
	HasPatterns bool
	Patterns    []*regexp.Regexp
}

type preparedPermissionSelector struct {
	Command     PermissionCommandSpec
	Env         PermissionEnvSpec
	HasPatterns bool
	Patterns    []*regexp.Regexp
}

func NewPipeline(spec PipelineSpec, src Source) Pipeline {
	spec = stampSources(spec, src)
	return Pipeline{PipelineSpec: spec, Source: src, prepared: preparePipeline(spec)}
}

func stampSources(spec PipelineSpec, src Source) PipelineSpec {
	for i := range spec.Permission.Deny {
		if spec.Permission.Deny[i].Source == (Source{}) {
			spec.Permission.Deny[i].Source = src
		}
	}
	for i := range spec.Permission.Ask {
		if spec.Permission.Ask[i].Source == (Source{}) {
			spec.Permission.Ask[i].Source = src
		}
	}
	for i := range spec.Permission.Allow {
		if spec.Permission.Allow[i].Source == (Source{}) {
			spec.Permission.Allow[i].Source = src
		}
	}
	for i := range spec.Test {
		if spec.Test[i].Source == (Source{}) {
			spec.Test[i].Source = src
		}
	}
	return spec
}

func preparePipeline(spec PipelineSpec) preparedPipeline {
	prepared := preparedPipeline{Ready: true}
	prepared.Deny = preparePermissionRules(spec.Permission.Deny)
	prepared.Ask = preparePermissionRules(spec.Permission.Ask)
	prepared.Allow = preparePermissionRules(spec.Permission.Allow)
	return prepared
}

func preparePermissionRules(rules []PermissionRuleSpec) []preparedPermissionRule {
	prepared := make([]preparedPermissionRule, 0, len(rules))
	for _, rule := range rules {
		prepared = append(prepared, preparedPermissionRule{
			Spec:     rule,
			Selector: preparePermissionSelector(rule),
		})
	}
	return prepared
}

func preparePermissionSelector(rule PermissionRuleSpec) preparedPermissionSelector {
	selector := preparedPermissionSelector{
		Command: rule.Command,
		Env:     rule.Env,
	}
	if len(rule.Patterns) > 0 {
		selector.HasPatterns = true
		selector.Patterns = make([]*regexp.Regexp, 0, len(rule.Patterns))
		for _, p := range rule.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				selector.Patterns = append(selector.Patterns, nil)
				continue
			}
			selector.Patterns = append(selector.Patterns, re)
		}
	}
	return selector
}

func prepareSelector(match MatchSpec, pattern string, patterns []string) preparedSelector {
	selector := preparedSelector{Match: match}
	if strings.TrimSpace(pattern) != "" {
		selector.HasPattern = true
		selector.Pattern, _ = regexp.Compile(pattern)
	}
	if len(patterns) > 0 {
		selector.HasPatterns = true
		selector.Patterns = make([]*regexp.Regexp, 0, len(patterns))
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				selector.Patterns = append(selector.Patterns, nil)
				continue
			}
			selector.Patterns = append(selector.Patterns, re)
		}
	}
	return selector
}

func sourcePtr(src Source) *Source {
	if src == (Source{}) {
		return nil
	}
	return &src
}

func Evaluate(p Pipeline, command string) (Decision, error) {
	trace := []TraceStep{}
	prepared := p.prepared
	if !prepared.Ready {
		prepared = preparePipeline(stampSources(p.PipelineSpec, p.Source))
	}

	plan := commandpkg.Parse(command)
	trace = append(trace, commandPlanTraceSteps(plan)...)
	safety := commandpkg.EvaluationSafetyForPlan(plan)
	if !safety.Safe {
		trace = append(trace, unsafeCommandTraceStep(plan, safety))
	}

	if rule, cmd, ok := firstPreparedPatternPermissionMatch(prepared.Deny, command, plan); ok {
		trace = append(trace, permissionPatternTraceStep("deny", rule, cmd))
		return Decision{Outcome: "deny", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredPermissionMatch(prepared.Deny, command); ok {
		trace = append(trace, permissionTraceStepForCommand("deny", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "deny", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if !safety.Safe {
		if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, false, false); ok {
			trace = append(trace, decision.Trace...)
			return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: command, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
		}
	}
	if rule, cmd, ok := firstPreparedPatternPermissionMatch(prepared.Ask, command, plan); ok {
		trace = append(trace, permissionPatternTraceStep("ask", rule, cmd))
		return Decision{Outcome: "ask", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredPermissionMatch(prepared.Ask, command); ok {
		trace = append(trace, permissionTraceStepForCommand("ask", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "ask", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if !safety.Safe {
		if rule, cmd, ok := firstPreparedStructuredAllowWithToleratedRedirects(prepared.Allow, plan); ok {
			trace = append(trace, permissionTraceStepForCommand("allow", permissionRuleTypeStructured, rule, cmd))
			return Decision{Outcome: "allow", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
		}
		if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, true, false); ok {
			trace = append(trace, decision.Trace...)
			return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: command, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
		}
		trace = append(trace, TraceStep{Action: "permission", Effect: "ask", Name: "fail_closed", Reason: strings.Join(safety.Reasons, ",")})
		return Decision{Outcome: "ask", Explicit: true, Reason: "fail_closed", Command: command, OriginalCommand: command, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredAllowPermissionMatch(prepared.Allow, command); ok {
		trace = append(trace, permissionTraceStepForCommand("allow", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "allow", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, false, true); ok {
		trace = append(trace, decision.Trace...)
		return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: command, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedPatternAllowPermissionMatch(prepared.Allow, command, plan); ok {
		trace = append(trace, permissionPatternTraceStep("allow", rule, cmd))
		return Decision{Outcome: "allow", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, true, true); ok {
		trace = append(trace, decision.Trace...)
		return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: command, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
	}

	trace = append(trace, TraceStep{Action: "permission", Effect: "abstain", Name: "no_match", Reason: "no permission rule matched"})
	return Decision{Outcome: "abstain", Reason: "no_match", Command: command, OriginalCommand: command, Trace: trace}, nil
}

func commandPlanTraceSteps(plan commandpkg.CommandPlan) []TraceStep {
	steps := make([]TraceStep, 0, len(plan.Normalized))
	for _, normalized := range plan.Normalized {
		steps = append(steps, TraceStep{
			Action:            "evaluate",
			Name:              "normalized_command",
			Command:           normalized.Raw,
			ProgramToken:      normalized.OriginalToken,
			NormalizedCommand: normalized.CommandName,
			NormalizedReason:  normalized.Reason,
		})
	}
	return steps
}

func boolPtr(v bool) *bool {
	return &v
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	deduped := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		deduped = append(deduped, value)
	}
	return deduped
}

func unsafeCommandTraceStep(plan commandpkg.CommandPlan, safety commandpkg.EvaluationSafety) TraceStep {
	return TraceStep{
		Action:     "permission",
		Name:       "fail_closed",
		Effect:     "ask",
		Reason:     strings.Join(safety.Reasons, ","),
		Shape:      string(plan.Shape.Kind),
		ShapeFlags: plan.Shape.Flags(),
	}
}

func permissionTraceStep(effect string, ruleType string, rule PermissionRuleSpec) TraceStep {
	predicate := permissionPredicateSummary(rule)
	name := strings.TrimSpace(rule.Name)
	if name == "" {
		name = predicate
	}
	return TraceStep{
		Action:   "permission",
		Name:     name,
		Effect:   effect,
		RuleType: ruleType,
		Message:  rule.Message,
		Reason:   predicate,
		Source:   sourcePtr(rule.Source),
	}
}

func permissionTraceStepForCommand(effect string, ruleType string, rule PermissionRuleSpec, cmd commandpkg.Command) TraceStep {
	step := permissionTraceStep(effect, ruleType, rule)
	step.Command = cmd.Raw
	step.Program = cmd.Program
	step.ActionPath = append([]string(nil), cmd.ActionPath...)
	step.Parser = cmd.Parser
	step.SemanticParser = cmd.SemanticParser
	if cmd.AWS != nil {
		step.AWSService = cmd.AWS.Service
		step.AWSOperation = cmd.AWS.Operation
		step.AWSProfile = cmd.AWS.Profile
		step.AWSRegion = cmd.AWS.Region
	}
	if cmd.Kubectl != nil {
		step.KubectlVerb = cmd.Kubectl.Verb
		step.KubectlSubverb = cmd.Kubectl.Subverb
		step.KubectlResourceType = cmd.Kubectl.ResourceType
		step.KubectlResourceName = cmd.Kubectl.ResourceName
		step.KubectlNamespace = cmd.Kubectl.Namespace
		step.KubectlContext = cmd.Kubectl.Context
	}
	if cmd.Gh != nil {
		step.GhArea = cmd.Gh.Area
		step.GhVerb = cmd.Gh.Verb
		step.GhRepo = cmd.Gh.Repo
		step.GhHostname = cmd.Gh.Hostname
		step.GhMethod = cmd.Gh.Method
		step.GhEndpoint = cmd.Gh.Endpoint
	}
	if cmd.Helmfile != nil {
		step.HelmfileVerb = cmd.Helmfile.Verb
		step.HelmfileEnvironment = cmd.Helmfile.Environment
		step.HelmfileFile = firstString(cmd.Helmfile.Files)
		step.HelmfileNamespace = cmd.Helmfile.Namespace
		step.HelmfileKubeContext = cmd.Helmfile.KubeContext
		step.HelmfileSelectors = append([]string(nil), cmd.Helmfile.Selectors...)
		step.HelmfileInteractive = boolPtr(cmd.Helmfile.Interactive)
	}
	if cmd.ArgoCD != nil {
		step.ArgoCDVerb = cmd.ArgoCD.Verb
		step.ArgoCDAppName = cmd.ArgoCD.AppName
		step.ArgoCDProject = cmd.ArgoCD.Project
		step.ArgoCDRevision = cmd.ArgoCD.Revision
	}
	if rule.Command.Semantic != nil {
		step.SemanticMatch = true
		step.SemanticFields = rule.Command.Semantic.fieldsUsed()
	}
	return step
}

func permissionPatternTraceStep(effect string, rule PermissionRuleSpec, cmd commandpkg.Command) TraceStep {
	if cmd.Program != "" {
		return permissionTraceStepForCommand(effect, permissionRuleTypeRaw, rule, cmd)
	}
	return permissionTraceStep(effect, permissionRuleTypeRaw, rule)
}

func firstPreparedPatternPermissionMatch(rules []preparedPermissionRule, command string, plan commandpkg.CommandPlan) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesPatterns(command) {
			return rule.Spec, commandpkg.Command{}, true
		}
		for _, cmd := range plan.Commands {
			if rule.Selector.matchesCommandPatternsValue(cmd) {
				return rule.Spec, cmd, true
			}
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

func firstPreparedStructuredPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if cmd, ok := rule.Selector.matchesCommand(command); ok {
			return rule.Spec, cmd, true
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

func firstPreparedStructuredAllowPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if !allowRuleCanMatch(rule.Spec, command) {
			continue
		}
		if cmd, ok := rule.Selector.matchesCommand(command); ok {
			return rule.Spec, cmd, true
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

func firstPreparedStructuredAllowWithToleratedRedirects(rules []preparedPermissionRule, plan commandpkg.CommandPlan) (PermissionRuleSpec, commandpkg.Command, bool) {
	if !planHasOnlyTolerableRedirectUnsafeShape(plan) || len(plan.Commands) != 1 {
		return PermissionRuleSpec{}, commandpkg.Command{}, false
	}
	cmd := plan.Commands[0]
	for _, rule := range rules {
		if len(rule.Spec.Command.ToleratedRedirects.Only) == 0 {
			continue
		}
		if !rule.Selector.matchesCommandValue(cmd) {
			continue
		}
		if toleratedRedirectsMatch(rule.Spec.Command.ToleratedRedirects, cmd.ShapeFlags) {
			return rule.Spec, cmd, true
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

func planHasOnlyTolerableRedirectUnsafeShape(plan commandpkg.CommandPlan) bool {
	shape := plan.Shape
	return shape.HasRedirection &&
		!shape.HasPipeline &&
		!shape.HasConditional &&
		!shape.HasSequence &&
		!shape.HasBackground &&
		!shape.HasSubshell &&
		!shape.HasCommandSubstitution &&
		!shape.HasProcessSubstitution &&
		shape.Kind != commandpkg.ShellShapeUnknown
}

func firstPreparedPatternAllowPermissionMatch(rules []preparedPermissionRule, command string, plan commandpkg.CommandPlan) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if !allowRuleCanMatch(rule.Spec, command) {
			continue
		}
		if rule.Selector.matchesPatterns(command) {
			return rule.Spec, commandpkg.Command{}, true
		}
		if len(plan.Commands) == 1 && commandAllowRuleCanMatch(plan.Commands[0]) && rule.Selector.matchesCommandPatternsValue(plan.Commands[0]) {
			return rule.Spec, plan.Commands[0], true
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

type commandDecision struct {
	Outcome  string
	Rule     PermissionRuleSpec
	Matched  bool
	Explicit bool
	RuleType string
	Command  commandpkg.Command
}

type compositionDecision struct {
	Outcome  string
	Message  string
	Reason   string
	Source   Source
	RuleType string
	Trace    []TraceStep
}

func evaluateCommandPlanComposition(deny []preparedPermissionRule, ask []preparedPermissionRule, allow []preparedPermissionRule, plan commandpkg.CommandPlan, includeDefaultAsk bool, allowComposition bool) (compositionDecision, bool) {
	if plan.Shape.Kind == commandpkg.ShellShapeSimple || len(plan.Commands) == 0 {
		return compositionDecision{}, false
	}

	decisions := make([]commandDecision, 0, len(plan.Commands))
	for _, cmd := range plan.Commands {
		decisions = append(decisions, evaluatePreparedCommand(deny, ask, allow, cmd))
	}

	if decision, index, ok := firstCommandDecision(decisions, "deny", true); ok {
		decision := compositionDecision{
			Outcome:  "deny",
			Message:  decision.Rule.Message,
			Source:   decision.Rule.Source,
			RuleType: decision.RuleType,
			Reason:   fmt.Sprintf("command[%d] denied", index),
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	}
	if decision, index, ok := firstCommandDecision(decisions, "ask", !includeDefaultAsk); ok {
		decision := compositionDecision{
			Outcome:  "ask",
			Message:  decision.Rule.Message,
			Source:   decision.Rule.Source,
			RuleType: decision.RuleType,
			Reason:   fmt.Sprintf("command[%d] asked", index),
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	}

	allAllowed := true
	for _, decision := range decisions {
		if decision.Outcome != "allow" {
			allAllowed = false
			break
		}
	}
	if !allAllowed {
		return compositionDecision{}, false
	}
	if !allowComposition {
		if includeDefaultAsk {
			decision := compositionDecision{
				Outcome: "ask",
				Reason:  unsafeCompositionReason(plan.Shape),
			}
			decision.Trace = compositionTrace(plan, decisions, decision)
			return decision, true
		}
		return compositionDecision{}, false
	}

	if isAllowableCompositionShape(plan.Shape) {
		decision := compositionDecision{
			Outcome:  "allow",
			Message:  decisions[0].Rule.Message,
			Source:   decisions[0].Rule.Source,
			RuleType: permissionRuleTypeStructured,
			Reason:   "all commands allowed",
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	}

	if includeDefaultAsk {
		decision := compositionDecision{
			Outcome: "ask",
			Reason:  unsafeCompositionReason(plan.Shape),
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	}
	return compositionDecision{}, false
}

func isAllowableCompositionShape(shape commandpkg.ShellShape) bool {
	if shape.Kind != commandpkg.ShellShapeCompound {
		return false
	}
	if shape.HasBackground ||
		shape.HasRedirection ||
		shape.HasSubshell ||
		shape.HasCommandSubstitution ||
		shape.HasProcessSubstitution {
		return false
	}
	if shape.HasPipeline && (shape.HasConditional || shape.HasSequence) {
		return false
	}
	return shape.HasPipeline || shape.HasConditional || shape.HasSequence
}

func unsafeCompositionReason(shape commandpkg.ShellShape) string {
	switch {
	case shape.HasProcessSubstitution:
		return "process substitution requires confirmation"
	case shape.HasCommandSubstitution:
		return "command substitution requires confirmation"
	case shape.HasRedirection:
		return "redirection requires confirmation"
	case shape.HasSubshell:
		return "subshell requires confirmation"
	case shape.HasBackground:
		return "background execution requires confirmation"
	case shape.HasPipeline && (shape.HasConditional || shape.HasSequence):
		return "pipeline compound shape requires confirmation"
	case shape.Kind == commandpkg.ShellShapeUnknown:
		return "unknown shell shape"
	default:
		return "unsafe command shape"
	}
}

func evaluatePreparedCommand(deny []preparedPermissionRule, ask []preparedPermissionRule, allow []preparedPermissionRule, cmd commandpkg.Command) commandDecision {
	if rule, ok := firstPreparedCommandPatternMatch(deny, cmd); ok {
		return commandDecision{Outcome: "deny", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeRaw, Command: cmd}
	}
	if rule, ok := firstPreparedCommandMatch(deny, cmd); ok {
		return commandDecision{Outcome: "deny", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeStructured, Command: cmd}
	}
	if rule, ok := firstPreparedCommandPatternMatch(ask, cmd); ok {
		return commandDecision{Outcome: "ask", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeRaw, Command: cmd}
	}
	if rule, ok := firstPreparedCommandMatch(ask, cmd); ok {
		return commandDecision{Outcome: "ask", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeStructured, Command: cmd}
	}
	if hasUnresolvedSemanticGuard(deny, cmd) || hasUnresolvedSemanticGuard(ask, cmd) {
		return commandDecision{Outcome: "ask", Explicit: true, Command: cmd}
	}
	if rule, ok := firstPreparedCommandAllowMatch(allow, cmd); ok {
		return commandDecision{Outcome: "allow", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeStructured, Command: cmd}
	}
	if rule, ok := firstPreparedCommandPatternAllowMatch(allow, cmd); ok {
		return commandDecision{Outcome: "allow", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeRaw, Command: cmd}
	}
	return commandDecision{Outcome: "ask", Command: cmd}
}

func firstCommandDecision(decisions []commandDecision, outcome string, explicitOnly bool) (commandDecision, int, bool) {
	for i, decision := range decisions {
		if explicitOnly && !decision.Matched {
			continue
		}
		if decision.Outcome == outcome {
			return decision, i, true
		}
	}
	return commandDecision{}, -1, false
}

func compositionTrace(plan commandpkg.CommandPlan, decisions []commandDecision, decision compositionDecision) []TraceStep {
	trace := make([]TraceStep, 0, len(decisions)+1)
	for i, commandDecision := range decisions {
		index := i
		cmd := commandDecision.Command
		trace = append(trace, TraceStep{
			Action:              "permission",
			Name:                "composition.command",
			Effect:              commandDecision.Outcome,
			Explicit:            commandDecision.Explicit,
			RuleType:            commandDecision.RuleType,
			Command:             cmd.Raw,
			CommandIndex:        &index,
			Parser:              cmd.Parser,
			SemanticParser:      cmd.SemanticParser,
			AWSService:          awsTraceService(cmd),
			AWSOperation:        awsTraceOperation(cmd),
			AWSProfile:          awsTraceProfile(cmd),
			AWSRegion:           awsTraceRegion(cmd),
			KubectlVerb:         kubectlTraceVerb(cmd),
			KubectlSubverb:      kubectlTraceSubverb(cmd),
			KubectlResourceType: kubectlTraceResourceType(cmd),
			KubectlResourceName: kubectlTraceResourceName(cmd),
			KubectlNamespace:    kubectlTraceNamespace(cmd),
			KubectlContext:      kubectlTraceContext(cmd),
			GhArea:              ghTraceArea(cmd),
			GhVerb:              ghTraceVerb(cmd),
			GhRepo:              ghTraceRepo(cmd),
			GhHostname:          ghTraceHostname(cmd),
			GhMethod:            ghTraceMethod(cmd),
			GhEndpoint:          ghTraceEndpoint(cmd),
			HelmfileVerb:        helmfileTraceVerb(cmd),
			HelmfileEnvironment: helmfileTraceEnvironment(cmd),
			HelmfileFile:        helmfileTraceFile(cmd),
			HelmfileNamespace:   helmfileTraceNamespace(cmd),
			HelmfileKubeContext: helmfileTraceKubeContext(cmd),
			HelmfileSelectors:   helmfileTraceSelectors(cmd),
			HelmfileInteractive: helmfileTraceInteractive(cmd),
			ArgoCDVerb:          argocdTraceVerb(cmd),
			ArgoCDAppName:       argocdTraceAppName(cmd),
			ArgoCDProject:       argocdTraceProject(cmd),
			ArgoCDRevision:      argocdTraceRevision(cmd),
			Program:             cmd.Program,
			ActionPath:          append([]string(nil), cmd.ActionPath...),
			Source:              sourcePtr(commandDecision.Rule.Source),
		})
	}
	trace = append(trace, TraceStep{
		Action:     "permission",
		Effect:     decision.Outcome,
		Name:       "composition",
		RuleType:   decision.RuleType,
		Message:    decision.Message,
		Reason:     decision.Reason,
		Shape:      string(plan.Shape.Kind),
		ShapeFlags: plan.Shape.Flags(),
		Source:     sourcePtr(decision.Source),
	})
	return trace
}

func awsTraceService(cmd commandpkg.Command) string {
	if cmd.AWS == nil {
		return ""
	}
	return cmd.AWS.Service
}

func awsTraceOperation(cmd commandpkg.Command) string {
	if cmd.AWS == nil {
		return ""
	}
	return cmd.AWS.Operation
}

func awsTraceProfile(cmd commandpkg.Command) string {
	if cmd.AWS == nil {
		return ""
	}
	return cmd.AWS.Profile
}

func awsTraceRegion(cmd commandpkg.Command) string {
	if cmd.AWS == nil {
		return ""
	}
	return cmd.AWS.Region
}

func kubectlTraceVerb(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.Verb
}

func kubectlTraceSubverb(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.Subverb
}

func kubectlTraceResourceType(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.ResourceType
}

func kubectlTraceResourceName(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.ResourceName
}

func kubectlTraceNamespace(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.Namespace
}

func kubectlTraceContext(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.Context
}

func ghTraceArea(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Area
}

func ghTraceVerb(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Verb
}

func ghTraceRepo(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Repo
}

func ghTraceHostname(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Hostname
}

func ghTraceMethod(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Method
}

func ghTraceEndpoint(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Endpoint
}

func helmfileTraceVerb(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return cmd.Helmfile.Verb
}

func helmfileTraceEnvironment(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return cmd.Helmfile.Environment
}

func helmfileTraceFile(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return firstString(cmd.Helmfile.Files)
}

func helmfileTraceNamespace(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return cmd.Helmfile.Namespace
}

func helmfileTraceKubeContext(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return cmd.Helmfile.KubeContext
}

func helmfileTraceSelectors(cmd commandpkg.Command) []string {
	if cmd.Helmfile == nil {
		return nil
	}
	return append([]string(nil), cmd.Helmfile.Selectors...)
}

func helmfileTraceInteractive(cmd commandpkg.Command) *bool {
	if cmd.Helmfile == nil {
		return nil
	}
	return boolPtr(cmd.Helmfile.Interactive)
}

func argocdTraceVerb(cmd commandpkg.Command) string {
	if cmd.ArgoCD == nil {
		return ""
	}
	return cmd.ArgoCD.Verb
}

func argocdTraceAppName(cmd commandpkg.Command) string {
	if cmd.ArgoCD == nil {
		return ""
	}
	return cmd.ArgoCD.AppName
}

func argocdTraceProject(cmd commandpkg.Command) string {
	if cmd.ArgoCD == nil {
		return ""
	}
	return cmd.ArgoCD.Project
}

func argocdTraceRevision(cmd commandpkg.Command) string {
	if cmd.ArgoCD == nil {
		return ""
	}
	return cmd.ArgoCD.Revision
}

func firstPreparedCommandMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesCommandValue(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedCommandAllowMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesCommandValue(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedCommandPatternMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesCommandPatternsValue(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedCommandPatternAllowMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if !commandAllowRuleCanMatch(cmd) {
			continue
		}
		if rule.Selector.matchesCommandPatternsValue(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func hasUnresolvedSemanticGuard(rules []preparedPermissionRule, cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "" {
		return false
	}
	for _, rule := range rules {
		if !rule.Selector.hasCommandSelector() {
			continue
		}
		if rule.Selector.Command.Semantic != nil && permissionCommandStructuralScopeMatches(rule.Selector.Command, rule.Selector.Env, cmd) {
			return true
		}
	}
	return false
}

func matchRequiresSemantic(match MatchSpec) bool {
	return match.Subcommand != "" || match.Semantic != nil
}

func matchStructuralScopeMatches(match MatchSpec, cmd commandpkg.Command) bool {
	if match.Command != "" && cmd.Program != match.Command {
		return false
	}
	if len(match.CommandIn) > 0 && !containsString(match.CommandIn, cmd.Program) {
		return false
	}
	if match.CommandIsAbsolutePath && !invocation.IsAbsoluteCommand(cmd.ProgramToken) {
		return false
	}
	for _, env := range match.EnvRequires {
		if _, ok := cmd.Env[env]; !ok {
			return false
		}
	}
	for _, env := range match.EnvMissing {
		if _, ok := cmd.Env[env]; ok {
			return false
		}
	}
	return true
}

func permissionCommandStructuralScopeMatches(command PermissionCommandSpec, env PermissionEnvSpec, cmd commandpkg.Command) bool {
	if cmd.Program == "" {
		return false
	}
	if strings.TrimSpace(command.Name) != "" {
		if cmd.Program != strings.TrimSpace(command.Name) {
			return false
		}
		return permissionEnvMatches(env, cmd)
	}
	if len(command.NameIn) == 0 || !containsTrimmedString(command.NameIn, cmd.Program) {
		return false
	}
	return permissionEnvMatches(env, cmd)
}

func permissionEnvMatches(env PermissionEnvSpec, cmd commandpkg.Command) bool {
	for _, name := range env.Requires {
		if _, ok := cmd.Env[name]; !ok {
			return false
		}
	}
	for _, name := range env.Missing {
		if _, ok := cmd.Env[name]; ok {
			return false
		}
	}
	return true
}

func permissionPredicateSummary(rule PermissionRuleSpec) string {
	var groups []string
	if strings.TrimSpace(rule.Command.Name) != "" || len(rule.Command.NameIn) > 0 {
		groups = append(groups, "command")
		if rule.Command.Semantic != nil {
			groups = append(groups, "semantic")
		}
		if permissionCommandUsesShapeFlags(rule.Command) {
			groups = append(groups, "shape_flags")
		}
	}
	if len(rule.Patterns) > 0 {
		groups = append(groups, "patterns")
	}
	if !IsZeroPermissionEnvSpec(rule.Env) {
		groups = append(groups, "env")
	}
	if len(groups) == 0 {
		return "rule"
	}
	return strings.Join(groups, "+")
}

func allowRuleCanMatch(rule PermissionRuleSpec, command string) bool {
	plan := commandpkg.Parse(command)
	if !commandpkg.IsSafeForEvaluation(plan) {
		return false
	}
	if invocation.IsStructuredSafeForAllow(command) {
		return true
	}
	return len(plan.Commands) == 1 && commandAllowRuleCanMatch(plan.Commands[0])
}

func commandAllowRuleCanMatch(cmd commandpkg.Command) bool {
	plan := commandpkg.Parse(cmd.Raw)
	return commandpkg.IsSafeForEvaluation(plan) && invocation.IsStructuredSafeForAllow(cmd.Raw)
}

func (m MatchSpec) MatchMatches(command string) bool {
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return false
	}
	return m.matches(plan.Commands[0])
}

func PermissionRuleMatches(rule PermissionRuleSpec, command string) bool {
	selector := preparePermissionSelector(rule)
	if selector.hasCommandSelector() {
		_, ok := selector.matchesCommand(command)
		return ok
	}
	plan := commandpkg.Parse(command)
	prepared := preparedPermissionRule{Spec: rule, Selector: selector}
	_, _, ok := firstPreparedPatternPermissionMatch([]preparedPermissionRule{prepared}, command, plan)
	return ok
}

func PermissionAllowRuleMatches(rule PermissionRuleSpec, command string) bool {
	selector := preparePermissionSelector(rule)
	if selector.hasCommandSelector() {
		plan := commandpkg.Parse(command)
		if !commandpkg.IsSafeForEvaluation(plan) {
			return false
		}
		if len(plan.Commands) == 0 {
			return false
		}
		for _, cmd := range plan.Commands {
			if !selector.matchesCommandValue(cmd) {
				return false
			}
		}
		return true
	}
	plan := commandpkg.Parse(command)
	prepared := preparedPermissionRule{Spec: rule, Selector: selector}
	_, _, ok := firstPreparedPatternAllowPermissionMatch([]preparedPermissionRule{prepared}, command, plan)
	return ok
}

func selectorMatches(command string, match MatchSpec, pattern string, patterns []string) bool {
	switch {
	case !IsZeroMatchSpec(match):
		return match.MatchMatches(command)
	case strings.TrimSpace(pattern) != "":
		return patternMatches(command, pattern)
	case len(patterns) > 0:
		for _, p := range patterns {
			if patternMatches(command, p) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func (s preparedSelector) matches(command string) bool {
	switch {
	case !IsZeroMatchSpec(s.Match):
		return s.Match.MatchMatches(command)
	case s.HasPattern:
		if s.Pattern == nil {
			return false
		}
		return s.Pattern.MatchString(command)
	case s.HasPatterns:
		for _, re := range s.Patterns {
			if re != nil && re.MatchString(command) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func (s preparedSelector) hasRawSelector() bool {
	return s.HasPattern || s.HasPatterns
}

func (s preparedSelector) hasStructuredSelector() bool {
	return !IsZeroMatchSpec(s.Match)
}

func (s preparedSelector) matchesRaw(command string) bool {
	if !s.hasRawSelector() {
		return false
	}
	if s.HasPattern {
		return s.Pattern != nil && s.Pattern.MatchString(command)
	}
	for _, re := range s.Patterns {
		if re != nil && re.MatchString(command) {
			return true
		}
	}
	return false
}

func (s preparedSelector) matchesStructured(command string) (commandpkg.Command, bool) {
	if !s.hasStructuredSelector() {
		return commandpkg.Command{}, false
	}
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return commandpkg.Command{}, false
	}
	cmd := plan.Commands[0]
	return cmd, s.Match.matches(cmd)
}

func (s preparedSelector) matchesStructuredCommand(cmd commandpkg.Command) bool {
	return s.hasStructuredSelector() && s.Match.matches(cmd)
}

func (s preparedPermissionSelector) hasCommandSelector() bool {
	return strings.TrimSpace(s.Command.Name) != "" || len(s.Command.NameIn) > 0
}

func (s preparedPermissionSelector) matchesCommand(command string) (commandpkg.Command, bool) {
	if !s.hasCommandSelector() {
		return commandpkg.Command{}, false
	}
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return commandpkg.Command{}, false
	}
	cmd := plan.Commands[0]
	return cmd, s.matchesCommandValue(cmd)
}

func (s preparedPermissionSelector) matchesCommandValue(cmd commandpkg.Command) bool {
	if !s.hasCommandSelector() {
		return false
	}
	if !permissionCommandStructuralScopeMatches(s.Command, s.Env, cmd) {
		return false
	}
	if !permissionCommandShapeFlagsMatch(s.Command, cmd.ShapeFlags) {
		return false
	}
	if s.Command.Semantic != nil {
		return permissionSemanticMatches(s.Command.Name, *s.Command.Semantic, cmd)
	}
	return true
}

func permissionCommandUsesShapeFlags(command PermissionCommandSpec) bool {
	return len(command.ShapeFlagsAny) > 0 || len(command.ShapeFlagsAll) > 0 || len(command.ShapeFlagsNone) > 0
}

func permissionCommandShapeFlagsMatch(command PermissionCommandSpec, flags []string) bool {
	if len(command.ShapeFlagsAny) > 0 && !containsAnyString(flags, command.ShapeFlagsAny) {
		return false
	}
	for _, flag := range command.ShapeFlagsAll {
		if !containsString(flags, strings.TrimSpace(flag)) {
			return false
		}
	}
	for _, flag := range command.ShapeFlagsNone {
		if containsString(flags, strings.TrimSpace(flag)) {
			return false
		}
	}
	return true
}

func toleratedRedirectsMatch(spec ToleratedRedirectsSpec, flags []string) bool {
	redirectFlags := toleratedRedirectFlags(flags)
	if len(redirectFlags) == 0 {
		return true
	}
	for _, flag := range redirectFlags {
		if !containsString(spec.Only, flag) {
			return false
		}
	}
	return true
}

func toleratedRedirectFlags(flags []string) []string {
	out := make([]string, 0, len(flags))
	for _, flag := range flags {
		flag = strings.TrimSpace(flag)
		switch flag {
		case "stdout_to_devnull", "stderr_to_devnull", "stdin_from_devnull":
			out = append(out, flag)
		case "redirect_stream_merge", "redirect_file_write", "redirect_append_file", "redirect_output_dup", "redirect_input_dup", "redirect_stdin_from_file", "redirect_heredoc", "redirect_unknown":
			out = append(out, flag)
		}
	}
	return out
}

func (s preparedPermissionSelector) matchesPatterns(command string) bool {
	if s.hasCommandSelector() {
		return false
	}
	if !s.HasPatterns {
		return s.matchesEnvOnly(command)
	}
	if !s.patternMatches(command) {
		return false
	}
	if IsZeroPermissionEnvSpec(s.Env) {
		return true
	}
	return s.matchesEnvOnly(command)
}

func (s preparedPermissionSelector) matchesCommandPatternsValue(cmd commandpkg.Command) bool {
	if !s.HasPatterns {
		return false
	}
	if !s.patternMatches(cmd.Raw) {
		return false
	}
	if IsZeroPermissionEnvSpec(s.Env) {
		return true
	}
	return permissionEnvMatches(s.Env, cmd)
}

func (s preparedPermissionSelector) patternMatches(command string) bool {
	for _, re := range s.Patterns {
		if re != nil && re.MatchString(command) {
			return true
		}
	}
	return false
}

func (s preparedPermissionSelector) matchesEnvOnly(command string) bool {
	if IsZeroPermissionEnvSpec(s.Env) {
		return false
	}
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return false
	}
	return permissionEnvMatches(s.Env, plan.Commands[0])
}

func patternMatches(command string, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(command)
}

func (m MatchSpec) matches(cmd commandpkg.Command) bool {
	if cmd.Program == "" {
		return false
	}
	if m.Command != "" && cmd.Program != m.Command {
		return false
	}
	if len(m.CommandIn) > 0 && !containsString(m.CommandIn, cmd.Program) {
		return false
	}
	if m.CommandIsAbsolutePath && !invocation.IsAbsoluteCommand(cmd.ProgramToken) {
		return false
	}
	if m.Subcommand != "" && commandSubcommand(cmd) != m.Subcommand {
		return false
	}
	args := commandMatchArgs(cmd)
	for _, arg := range m.ArgsContains {
		if !containsString(args, arg) {
			return false
		}
	}
	for _, prefix := range m.ArgsPrefixes {
		if !containsPrefix(args, prefix) {
			return false
		}
	}
	for _, env := range m.EnvRequires {
		if _, ok := cmd.Env[env]; !ok {
			return false
		}
	}
	for _, env := range m.EnvMissing {
		if _, ok := cmd.Env[env]; ok {
			return false
		}
	}
	if m.Semantic != nil {
		if !permissionSemanticMatches(m.Command, *m.Semantic, cmd) {
			return false
		}
	}
	return true
}

func commandSubcommand(cmd commandpkg.Command) string {
	if len(cmd.ActionPath) == 0 {
		return structuralSubcommand(cmd)
	}
	return cmd.ActionPath[0]
}

func structuralSubcommand(cmd commandpkg.Command) string {
	for _, word := range cmd.RawWords {
		if strings.HasPrefix(word, "-") && word != "-" {
			continue
		}
		return word
	}
	return ""
}

func commandMatchArgs(cmd commandpkg.Command) []string {
	if len(cmd.RawWords) > 0 {
		return cmd.RawWords
	}
	return cmd.Args
}

func ValidatePipeline(spec PipelineSpec) []string {
	var issues []string
	if len(spec.Rewrite) > 0 {
		issues = append(issues, "top-level rewrite is no longer supported; cc-bash-guard policy evaluation no longer rewrites commands. Use permission.command / env / patterns, and rely on parser-backed normalization for evaluation.")
	}
	if IsZeroPermissionSpec(spec.Permission) {
		issues = append(issues, "must set at least one permission entry")
	}
	for i, rule := range spec.Permission.Deny {
		issues = append(issues, ValidatePermissionRule(fmt.Sprintf("permission.deny[%d]", i), rule, "deny")...)
	}
	for i, rule := range spec.Permission.Ask {
		issues = append(issues, ValidatePermissionRule(fmt.Sprintf("permission.ask[%d]", i), rule, "ask")...)
	}
	for i, rule := range spec.Permission.Allow {
		issues = append(issues, ValidatePermissionRule(fmt.Sprintf("permission.allow[%d]", i), rule, "allow")...)
	}
	issues = append(issues, ValidatePipelineTest("test", spec.Test)...)
	return issues
}

func ValidatePermissionRule(prefix string, rule PermissionRuleSpec, effect string) []string {
	var issues []string
	if strings.TrimSpace(rule.Name) == "" && rule.Name != "" {
		issues = append(issues, prefix+".name must be non-empty")
	}
	issues = append(issues, ValidatePermissionPredicates(prefix, rule, effect)...)
	issues = append(issues, ValidatePermissionTest(prefix+".test", rule.Test, effect)...)
	return issues
}

func ValidatePermissionPredicates(prefix string, rule PermissionRuleSpec, effect string) []string {
	var issues []string
	count := 0
	if !IsZeroPermissionCommandSpec(rule.Command) {
		count++
		issues = append(issues, ValidatePermissionCommandSpec(prefix+".command", rule.Command, effect)...)
	}
	if len(rule.Patterns) > 0 {
		count++
		issues = append(issues, validateNonEmptyStrings(prefix+".patterns", rule.Patterns)...)
		for i, p := range rule.Patterns {
			if _, err := regexp.Compile(p); err != nil {
				issues = append(issues, fmt.Sprintf("%s.patterns[%d] must compile: %s", prefix, i, err.Error()))
			}
		}
	}
	if !IsZeroPermissionEnvSpec(rule.Env) {
		issues = append(issues, ValidatePermissionEnvSpec(prefix+".env", rule.Env)...)
	}
	if count == 0 && IsZeroPermissionEnvSpec(rule.Env) {
		issues = append(issues, prefix+" must set one of command, env, or patterns")
	}
	if !IsZeroPermissionCommandSpec(rule.Command) && len(rule.Patterns) > 0 {
		issues = append(issues, prefix+" cannot combine command and patterns")
	}
	return issues
}

func ValidatePermissionCommandSpec(prefix string, command PermissionCommandSpec, effect string) []string {
	var issues []string
	if command.Name != "" && len(command.NameIn) > 0 {
		issues = append(issues, prefix+".name and "+prefix+".name_in cannot both be set")
	}
	if strings.TrimSpace(command.Name) == "" {
		if command.Name != "" {
			issues = append(issues, prefix+".name must be non-empty")
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".name_in", command.NameIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".shape_flags_any", command.ShapeFlagsAny)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".shape_flags_all", command.ShapeFlagsAll)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".shape_flags_none", command.ShapeFlagsNone)...)
	if len(command.ToleratedRedirects.Only) > 0 {
		if effect != "allow" {
			issues = append(issues, prefix+".tolerated_redirects is only supported in permission.allow rules")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".tolerated_redirects.only", command.ToleratedRedirects.Only)...)
		for i, value := range command.ToleratedRedirects.Only {
			if !isSupportedToleratedRedirect(strings.TrimSpace(value)) {
				issues = append(issues, fmt.Sprintf("%s.tolerated_redirects.only[%d] is not supported: %s", prefix, i, value))
			}
		}
	}
	if strings.TrimSpace(command.Name) == "" && len(command.NameIn) == 0 {
		issues = append(issues, prefix+".name or "+prefix+".name_in must be set")
	}
	if command.Semantic != nil {
		if len(command.NameIn) > 0 {
			issues = append(issues, prefix+".name_in cannot be used with semantic")
		}
		if strings.TrimSpace(command.Name) == "" {
			issues = append(issues, prefix+".name must be set when semantic is used")
			return issues
		}
		name := strings.TrimSpace(command.Name)
		if _, ok := semanticpkg.Lookup(name); !ok {
			issues = append(issues, unsupportedSemanticCommandIssue(prefix, name))
			return issues
		}
		unsupportedFields := unsupportedSemanticFields(name, *command.Semantic)
		if len(unsupportedFields) > 0 {
			issues = append(issues, prefix+".semantic contains fields not supported for command: "+name)
			for _, field := range unsupportedFields {
				issues = append(issues, unsupportedSemanticFieldIssue(prefix, name, field))
			}
		}
		issues = append(issues, validateSemanticMatchSpec(name, prefix+".semantic", *command.Semantic)...)
	}
	return issues
}

func isSupportedToleratedRedirect(value string) bool {
	switch value {
	case "stdout_to_devnull", "stderr_to_devnull", "stdin_from_devnull":
		return true
	default:
		return false
	}
}

func ValidatePermissionEnvSpec(prefix string, env PermissionEnvSpec) []string {
	var issues []string
	issues = append(issues, validateNonEmptyStrings(prefix+".requires", env.Requires)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".missing", env.Missing)...)
	return issues
}

func ValidateSelector(prefix string, match MatchSpec, pattern string, patterns []string, required bool, allowSemantic bool) []string {
	var issues []string
	count := 0
	if !IsZeroMatchSpec(match) {
		count++
		issues = append(issues, validateMatchSpec(prefix+".match", match, allowSemantic)...)
	}
	if strings.TrimSpace(pattern) != "" {
		count++
		if _, err := regexp.Compile(pattern); err != nil {
			issues = append(issues, prefix+".pattern must compile: "+err.Error())
		}
	}
	if len(patterns) > 0 {
		count++
		issues = append(issues, validateNonEmptyStrings(prefix+".patterns", patterns)...)
		for i, p := range patterns {
			if _, err := regexp.Compile(p); err != nil {
				issues = append(issues, fmt.Sprintf("%s.patterns[%d] must compile: %s", prefix, i, err.Error()))
			}
		}
	}
	if required && count == 0 {
		issues = append(issues, prefix+" must set one of match, pattern, or patterns")
	}
	if count > 1 {
		issues = append(issues, prefix+" may set only one of match, pattern, or patterns")
	}
	return issues
}

func ValidateMatchSpec(prefix string, match MatchSpec) []string {
	return validateMatchSpec(prefix, match, true)
}

func validateMatchSpec(prefix string, match MatchSpec, allowSemantic bool) []string {
	var issues []string
	if IsZeroMatchSpec(match) {
		return []string{prefix + " must not be empty"}
	}
	if strings.TrimSpace(match.Command) == "" && match.Command != "" {
		issues = append(issues, prefix+".command must be non-empty")
	}
	if strings.TrimSpace(match.Subcommand) == "" && match.Subcommand != "" {
		issues = append(issues, prefix+".subcommand must be non-empty")
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".command_in", match.CommandIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".args_contains", match.ArgsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".args_prefixes", match.ArgsPrefixes)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".env_requires", match.EnvRequires)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".env_missing", match.EnvMissing)...)
	if match.Semantic != nil {
		if !allowSemantic {
			issues = append(issues, prefix+".semantic is not supported; semantic match is currently permission-only")
		}
		if strings.TrimSpace(match.Command) == "" {
			issues = append(issues, prefix+".command must be set when semantic is used")
		}
		if len(match.CommandIn) > 0 {
			issues = append(issues, prefix+".command_in cannot be used with semantic")
		}
		if match.Subcommand != "" {
			issues = append(issues, prefix+".subcommand cannot be used with semantic")
		}
		if match.Command != "" {
			if _, ok := semanticpkg.Lookup(match.Command); !ok {
				issues = append(issues, unsupportedSemanticCommandIssue(prefix, match.Command))
				return issues
			}
			unsupportedFields := unsupportedSemanticFields(match.Command, *match.Semantic)
			if len(unsupportedFields) > 0 {
				issues = append(issues, prefix+".semantic contains fields not supported for command: "+match.Command)
			}
			for _, field := range unsupportedFields {
				issues = append(issues, unsupportedSemanticFieldIssue(prefix, match.Command, field))
			}
		}
		issues = append(issues, validateSemanticMatchSpec(match.Command, prefix+".semantic", *match.Semantic)...)
	}
	return issues
}

func unsupportedSemanticFields(command string, semantic SemanticMatchSpec) []string {
	var unsupported []string
	for _, field := range semantic.fieldsUsed() {
		if !semanticpkg.IsFieldSupported(command, field) {
			unsupported = append(unsupported, field)
		}
	}
	return unsupported
}

func unsupportedSemanticFieldIssue(prefix, command, field string) string {
	return fmt.Sprintf("%s.semantic.%s is not supported for command %s. Supported semantic fields for %s: %s. See cc-bash-guard help semantic %s or docs/user/SEMANTIC_SCHEMAS.md.", prefix, field, command, command, strings.Join(semanticpkg.FieldNames(command), ", "), command)
}

func unsupportedSemanticCommandIssue(prefix, command string) string {
	return fmt.Sprintf("%s.semantic is not available for command %s. Use patterns, or add a semantic schema/parser for %s. Supported semantic commands: %s. See cc-bash-guard help semantic and docs/user/SEMANTIC_SCHEMAS.md.", prefix, command, command, strings.Join(semanticpkg.SupportedCommands(), ", "))
}

func ValidatePermissionTest(prefix string, test PermissionTestSpec, effect string) []string {
	var issues []string
	switch effect {
	case "allow":
		if len(test.Allow) == 0 {
			issues = append(issues, prefix+".allow must be non-empty")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".allow", test.Allow)...)
		if len(test.Ask) > 0 || len(test.Deny) > 0 {
			issues = append(issues, prefix+" may only use allow and abstain")
		}
	case "ask":
		if len(test.Ask) == 0 {
			issues = append(issues, prefix+".ask must be non-empty")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".ask", test.Ask)...)
		if len(test.Allow) > 0 || len(test.Deny) > 0 {
			issues = append(issues, prefix+" may only use ask and abstain")
		}
	case "deny":
		if len(test.Deny) == 0 {
			issues = append(issues, prefix+".deny must be non-empty")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".deny", test.Deny)...)
		if len(test.Allow) > 0 || len(test.Ask) > 0 {
			issues = append(issues, prefix+" may only use deny and abstain")
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".abstain", test.Abstain)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".pass", test.Pass)...)
	if len(test.Abstain) == 0 && len(test.Pass) == 0 {
		issues = append(issues, prefix+".abstain must be non-empty")
	}
	return issues
}

func ValidatePipelineTest(prefix string, test PipelineTestSpec) []string {
	var issues []string
	if len(test) == 0 {
		issues = append(issues, prefix+" must be non-empty")
	}
	for i, c := range test {
		if strings.TrimSpace(c.In) == "" {
			issues = append(issues, fmt.Sprintf("%s[%d].in must be non-empty", prefix, i))
		}
		if strings.TrimSpace(c.Rewritten) != "" {
			issues = append(issues, fmt.Sprintf("%s[%d].rewritten is no longer supported; cc-bash-guard policy evaluation does not rewrite commands", prefix, i))
		}
		switch c.Decision {
		case "allow", "ask", "deny":
			if c.AssertPolicyOutcome {
				issues = append(issues, fmt.Sprintf("%s[%d].decision cannot use policy-outcome assertion for %s", prefix, i, c.Decision))
			}
		case "abstain":
			if !c.AssertPolicyOutcome {
				issues = append(issues, fmt.Sprintf("%s[%d].decision abstain is only valid in bucketed test.abstain; final hook decisions are deny, ask, or allow", prefix, i))
			}
		default:
			issues = append(issues, fmt.Sprintf("%s[%d].decision must be one of allow, ask, deny", prefix, i))
		}
	}
	return issues
}

func ErrorStrings(errs []error) []string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			parts = append(parts, ve.Issues...)
			continue
		}
		parts = append(parts, err.Error())
	}
	slices.Sort(parts)
	return parts
}

func IsZeroPermissionSpec(spec PermissionSpec) bool {
	return len(spec.Deny) == 0 && len(spec.Ask) == 0 && len(spec.Allow) == 0
}

func IsZeroPermissionCommandSpec(command PermissionCommandSpec) bool {
	return command.Name == "" &&
		len(command.NameIn) == 0 &&
		len(command.ShapeFlagsAny) == 0 &&
		len(command.ShapeFlagsAll) == 0 &&
		len(command.ShapeFlagsNone) == 0 &&
		len(command.ToleratedRedirects.Only) == 0 &&
		command.Semantic == nil
}

func IsZeroPermissionEnvSpec(env PermissionEnvSpec) bool {
	return len(env.Requires) == 0 && len(env.Missing) == 0
}

func IsZeroMatchSpec(match MatchSpec) bool {
	return match.Command == "" &&
		len(match.CommandIn) == 0 &&
		!match.CommandIsAbsolutePath &&
		match.Subcommand == "" &&
		len(match.ArgsContains) == 0 &&
		len(match.ArgsPrefixes) == 0 &&
		len(match.EnvRequires) == 0 &&
		len(match.EnvMissing) == 0 &&
		match.Semantic == nil
}

func validateNonEmptyStrings(prefix string, values []string) []string {
	var issues []string
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, fmt.Sprintf("%s[%d] must be non-empty", prefix, i))
		}
	}
	return issues
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func equalStrings(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsTrimmedString(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func containsStringFoldUpper(values []string, want string) bool {
	for _, value := range values {
		if strings.ToUpper(value) == want {
			return true
		}
	}
	return false
}

func containsAnyString(values []string, wants []string) bool {
	for _, want := range wants {
		if containsString(values, want) {
			return true
		}
	}
	return false
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func containsSubstring(values []string, substr string) bool {
	for _, value := range values {
		if strings.Contains(value, substr) {
			return true
		}
	}
	return false
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
