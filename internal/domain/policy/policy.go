package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	commandpkg "github.com/tasuku43/cc-bash-proxy/internal/domain/command"
	"github.com/tasuku43/cc-bash-proxy/internal/domain/directive"
	"github.com/tasuku43/cc-bash-proxy/internal/domain/invocation"
)

type PipelineSpec struct {
	ClaudePermissionMergeMode string            `yaml:"claude_permission_merge_mode" json:"claude_permission_merge_mode,omitempty"`
	Rewrite                   []RewriteStepSpec `yaml:"rewrite" json:"rewrite,omitempty"`
	Permission                PermissionSpec    `yaml:"permission" json:"permission,omitempty"`
	Test                      PipelineTestSpec  `yaml:"test" json:"test,omitempty"`
}

type RewriteStepSpec struct {
	Match            MatchSpec         `yaml:"match" json:"match,omitempty"`
	Pattern          string            `yaml:"pattern" json:"pattern,omitempty"`
	Patterns         []string          `yaml:"patterns" json:"patterns,omitempty"`
	UnwrapShellDashC bool              `yaml:"unwrap_shell_dash_c" json:"unwrap_shell_dash_c,omitempty"`
	UnwrapWrapper    UnwrapWrapperSpec `yaml:"unwrap_wrapper" json:"unwrap_wrapper,omitempty"`
	MoveFlagToEnv    MoveFlagToEnvSpec `yaml:"move_flag_to_env" json:"move_flag_to_env,omitempty"`
	MoveEnvToFlag    MoveEnvToFlagSpec `yaml:"move_env_to_flag" json:"move_env_to_flag,omitempty"`
	StripCommandPath bool              `yaml:"strip_command_path" json:"strip_command_path,omitempty"`
	Strict           *bool             `yaml:"strict" json:"strict,omitempty"`
	Continue         bool              `yaml:"continue" json:"continue,omitempty"`
	Test             RewriteTestSpec   `yaml:"test" json:"test,omitempty"`
	Source           Source            `yaml:"-" json:"source,omitempty"`
}

type PermissionSpec struct {
	Deny  []PermissionRuleSpec `yaml:"deny" json:"deny,omitempty"`
	Ask   []PermissionRuleSpec `yaml:"ask" json:"ask,omitempty"`
	Allow []PermissionRuleSpec `yaml:"allow" json:"allow,omitempty"`
}

type PermissionRuleSpec struct {
	Match            MatchSpec          `yaml:"match" json:"match,omitempty"`
	Pattern          string             `yaml:"pattern" json:"pattern,omitempty"`
	Patterns         []string           `yaml:"patterns" json:"patterns,omitempty"`
	AllowUnsafeShell bool               `yaml:"allow_unsafe_shell" json:"allow_unsafe_shell,omitempty"`
	Message          string             `yaml:"message" json:"message,omitempty"`
	Test             PermissionTestSpec `yaml:"test" json:"test,omitempty"`
	Source           Source             `yaml:"-" json:"source,omitempty"`
}

type PermissionTestSpec struct {
	Allow []string `yaml:"allow" json:"allow,omitempty"`
	Ask   []string `yaml:"ask" json:"ask,omitempty"`
	Deny  []string `yaml:"deny" json:"deny,omitempty"`
	Pass  []string `yaml:"pass" json:"pass,omitempty"`
}

type PipelineTestSpec []PipelineExpectCase

type PipelineExpectCase struct {
	In        string `yaml:"in" json:"in,omitempty"`
	Rewritten string `yaml:"rewritten" json:"rewritten,omitempty"`
	Decision  string `yaml:"decision" json:"decision,omitempty"`
}

type MoveFlagToEnvSpec struct {
	Flag string `yaml:"flag" json:"flag,omitempty"`
	Env  string `yaml:"env" json:"env,omitempty"`
}

type MoveEnvToFlagSpec struct {
	Env  string `yaml:"env" json:"env,omitempty"`
	Flag string `yaml:"flag" json:"flag,omitempty"`
}

type UnwrapWrapperSpec struct {
	Wrappers []string `yaml:"wrappers" json:"wrappers,omitempty"`
}

type RewriteTestSpec []RewriteTestCase

type RewriteTestCase struct {
	In   string `yaml:"in" json:"in,omitempty"`
	Out  string `yaml:"out" json:"out,omitempty"`
	Pass string `yaml:"pass" json:"pass,omitempty"`
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

type SemanticMatchSpec struct {
	Verb           string   `yaml:"verb" json:"verb,omitempty"`
	VerbIn         []string `yaml:"verb_in" json:"verb_in,omitempty"`
	Remote         string   `yaml:"remote" json:"remote,omitempty"`
	RemoteIn       []string `yaml:"remote_in" json:"remote_in,omitempty"`
	Branch         string   `yaml:"branch" json:"branch,omitempty"`
	BranchIn       []string `yaml:"branch_in" json:"branch_in,omitempty"`
	Ref            string   `yaml:"ref" json:"ref,omitempty"`
	RefIn          []string `yaml:"ref_in" json:"ref_in,omitempty"`
	Force          *bool    `yaml:"force" json:"force,omitempty"`
	Hard           *bool    `yaml:"hard" json:"hard,omitempty"`
	Recursive      *bool    `yaml:"recursive" json:"recursive,omitempty"`
	IncludeIgnored *bool    `yaml:"include_ignored" json:"include_ignored,omitempty"`
	Cached         *bool    `yaml:"cached" json:"cached,omitempty"`
	Staged         *bool    `yaml:"staged" json:"staged,omitempty"`
	FlagsContains  []string `yaml:"flags_contains" json:"flags_contains,omitempty"`
	FlagsPrefixes  []string `yaml:"flags_prefixes" json:"flags_prefixes,omitempty"`
}

type Source struct {
	Layer string `json:"layer"`
	Path  string `json:"path"`
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
	Action         string   `json:"action"`
	Name           string   `json:"name,omitempty"`
	Effect         string   `json:"effect,omitempty"`
	RuleType       string   `json:"rule_type,omitempty"`
	From           string   `json:"from,omitempty"`
	To             string   `json:"to,omitempty"`
	Message        string   `json:"message,omitempty"`
	Reason         string   `json:"reason,omitempty"`
	Command        string   `json:"command,omitempty"`
	CommandIndex   *int     `json:"command_index,omitempty"`
	Parser         string   `json:"parser,omitempty"`
	SemanticParser string   `json:"semantic_parser,omitempty"`
	SemanticMatch  bool     `json:"semantic_match,omitempty"`
	SemanticFields []string `json:"semantic_fields,omitempty"`
	FromShape      string   `json:"from_shape,omitempty"`
	FromShapeFlags []string `json:"from_shape_flags,omitempty"`
	FromSafe       *bool    `json:"from_safe,omitempty"`
	ToShape        string   `json:"to_shape,omitempty"`
	ToShapeFlags   []string `json:"to_shape_flags,omitempty"`
	ToSafe         *bool    `json:"to_safe,omitempty"`
	Program        string   `json:"program,omitempty"`
	ActionPath     []string `json:"action_path,omitempty"`
	Shape          string   `json:"shape,omitempty"`
	ShapeFlags     []string `json:"shape_flags,omitempty"`
	Relaxed        bool     `json:"relaxed,omitempty"`
	Continue       bool     `json:"continue,omitempty"`
	Source         *Source  `json:"source,omitempty"`
}

const (
	permissionRuleTypeRaw        = "raw"
	permissionRuleTypeStructured = "structured"
)

type preparedPipeline struct {
	Ready   bool
	Rewrite []preparedRewriteStep
	Deny    []preparedPermissionRule
	Ask     []preparedPermissionRule
	Allow   []preparedPermissionRule
}

type preparedRewriteStep struct {
	Spec     RewriteStepSpec
	Selector preparedSelector
}

type preparedPermissionRule struct {
	Spec     PermissionRuleSpec
	Selector preparedSelector
}

type preparedSelector struct {
	Match       MatchSpec
	HasPattern  bool
	Pattern     *regexp.Regexp
	HasPatterns bool
	Patterns    []*regexp.Regexp
}

func NewPipeline(spec PipelineSpec, src Source) Pipeline {
	spec = stampSources(spec, src)
	return Pipeline{PipelineSpec: spec, Source: src, prepared: preparePipeline(spec)}
}

func stampSources(spec PipelineSpec, src Source) PipelineSpec {
	for i := range spec.Rewrite {
		if spec.Rewrite[i].Source == (Source{}) {
			spec.Rewrite[i].Source = src
		}
	}
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
	return spec
}

func preparePipeline(spec PipelineSpec) preparedPipeline {
	prepared := preparedPipeline{Ready: true}
	prepared.Rewrite = make([]preparedRewriteStep, 0, len(spec.Rewrite))
	for _, step := range spec.Rewrite {
		prepared.Rewrite = append(prepared.Rewrite, preparedRewriteStep{
			Spec:     step,
			Selector: prepareSelector(step.Match, step.Pattern, step.Patterns),
		})
	}
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
			Selector: prepareSelector(rule.Match, rule.Pattern, rule.Patterns),
		})
	}
	return prepared
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
	current := command
	trace := []TraceStep{}
	rewriteSafetyReasons := []string{}
	prepared := p.prepared
	if !prepared.Ready {
		prepared = preparePipeline(stampSources(p.PipelineSpec, p.Source))
	}

	for _, step := range prepared.Rewrite {
		if !step.Selector.matches(current) {
			continue
		}
		beforePlan := commandpkg.Parse(current)
		beforeSafety := commandpkg.EvaluationSafetyForPlan(beforePlan)
		rewritten, ok := applyRewriteStep(step.Spec, current)
		if !ok {
			continue
		}
		afterPlan := commandpkg.Parse(rewritten)
		afterSafety := commandpkg.EvaluationSafetyForPlan(afterPlan)
		invariantReasons := rewriteInvariantViolationReasons(beforePlan, beforeSafety, afterPlan, afterSafety)
		effect := ""
		if len(invariantReasons) > 0 {
			effect = "fail_closed"
			rewriteSafetyReasons = append(rewriteSafetyReasons, invariantReasons...)
		}
		trace = append(trace, TraceStep{
			Action:         "rewrite",
			Name:           rewritePrimitiveName(step.Spec),
			Effect:         effect,
			From:           current,
			To:             rewritten,
			Reason:         strings.Join(invariantReasons, ","),
			Relaxed:        !RewriteStrict(step.Spec),
			Continue:       step.Spec.Continue,
			Source:         sourcePtr(step.Spec.Source),
			FromShape:      string(beforePlan.Shape.Kind),
			FromShapeFlags: beforePlan.Shape.Flags(),
			FromSafe:       boolPtr(beforeSafety.Safe),
			ToShape:        string(afterPlan.Shape.Kind),
			ToShapeFlags:   afterPlan.Shape.Flags(),
			ToSafe:         boolPtr(afterSafety.Safe),
		})
		current = rewritten
		if len(invariantReasons) > 0 {
			break
		}
		if !step.Spec.Continue {
			break
		}
	}

	plan := commandpkg.Parse(current)
	safety := commandpkg.EvaluationSafetyForPlan(plan)
	if len(rewriteSafetyReasons) > 0 {
		safety.Safe = false
		safety.Reasons = dedupeStrings(append(safety.Reasons, rewriteSafetyReasons...))
	}
	if !safety.Safe {
		trace = append(trace, unsafeCommandTraceStep(plan, safety))
	}

	if rule, ok := firstPreparedRawPermissionMatch(prepared.Deny, current); ok {
		trace = append(trace, permissionTraceStep("deny", permissionRuleTypeRaw, rule))
		return Decision{Outcome: "deny", Explicit: true, Reason: "rule_match", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredPermissionMatch(prepared.Deny, current); ok {
		trace = append(trace, permissionTraceStepForCommand("deny", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "deny", Explicit: true, Reason: "rule_match", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if !safety.Safe {
		if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, false, false); ok {
			trace = append(trace, decision.Trace...)
			return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: current, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
		}
	}
	if rule, ok := firstPreparedRawPermissionMatch(prepared.Ask, current); ok {
		trace = append(trace, permissionTraceStep("ask", permissionRuleTypeRaw, rule))
		return Decision{Outcome: "ask", Explicit: true, Reason: "rule_match", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredPermissionMatch(prepared.Ask, current); ok {
		trace = append(trace, permissionTraceStepForCommand("ask", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "ask", Explicit: true, Reason: "rule_match", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if !safety.Safe {
		if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, true, false); ok {
			trace = append(trace, decision.Trace...)
			return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: current, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
		}
		trace = append(trace, TraceStep{Action: "permission", Effect: "ask", Name: "fail_closed", Reason: strings.Join(safety.Reasons, ",")})
		return Decision{Outcome: "ask", Explicit: true, Reason: "fail_closed", Command: current, OriginalCommand: command, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredAllowPermissionMatch(prepared.Allow, current); ok {
		trace = append(trace, permissionTraceStepForCommand("allow", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "allow", Explicit: true, Reason: "rule_match", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, false, true); ok {
		trace = append(trace, decision.Trace...)
		return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: current, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
	}
	if rule, ok := firstPreparedRawAllowPermissionMatch(prepared.Allow, current); ok {
		trace = append(trace, permissionTraceStep("allow", permissionRuleTypeRaw, rule))
		return Decision{Outcome: "allow", Explicit: true, Reason: "rule_match", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, true, true); ok {
		trace = append(trace, decision.Trace...)
		return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: current, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
	}

	trace = append(trace, TraceStep{Action: "permission", Effect: "abstain", Name: "no_match", Reason: "no permission rule matched"})
	return Decision{Outcome: "abstain", Reason: "no_match", Command: current, OriginalCommand: command, Trace: trace}, nil
}

func boolPtr(v bool) *bool {
	return &v
}

func rewriteInvariantViolationReasons(beforePlan commandpkg.CommandPlan, beforeSafety commandpkg.EvaluationSafety, afterPlan commandpkg.CommandPlan, afterSafety commandpkg.EvaluationSafety) []string {
	var reasons []string
	if beforeSafety.Safe && !afterSafety.Safe {
		reasons = append(reasons, "rewrite_safe_to_unsafe")
	}
	if beforePlan.Shape.Kind == commandpkg.ShellShapeSimple && afterPlan.Shape.Kind != commandpkg.ShellShapeSimple {
		reasons = append(reasons, "rewrite_simple_to_"+string(afterPlan.Shape.Kind))
	}
	if afterPlan.Shape.Kind == commandpkg.ShellShapeUnknown {
		reasons = append(reasons, "rewrite_unknown_shape")
	}
	if !afterSafety.Safe {
		for _, reason := range afterSafety.Reasons {
			reasons = append(reasons, "rewrite_"+reason)
		}
	}
	return dedupeStrings(reasons)
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
	return TraceStep{
		Action:   "permission",
		Effect:   effect,
		RuleType: ruleType,
		Message:  rule.Message,
		Source:   sourcePtr(rule.Source),
	}
}

func permissionTraceStepForCommand(effect string, ruleType string, rule PermissionRuleSpec, cmd commandpkg.Command) TraceStep {
	step := permissionTraceStep(effect, ruleType, rule)
	step.Parser = cmd.Parser
	step.SemanticParser = cmd.SemanticParser
	if rule.Match.Semantic != nil {
		step.SemanticMatch = true
		step.SemanticFields = rule.Match.Semantic.fieldsUsed()
	}
	return step
}

func firstPreparedRawPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesRaw(command) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedStructuredPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if cmd, ok := rule.Selector.matchesStructured(command); ok {
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
		if cmd, ok := rule.Selector.matchesStructured(command); ok {
			return rule.Spec, cmd, true
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

func firstPreparedRawAllowPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if !rule.Spec.AllowUnsafeShell {
			continue
		}
		if !allowRuleCanMatch(rule.Spec, command) {
			continue
		}
		if rule.Selector.matchesRaw(command) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

type commandDecision struct {
	Outcome  string
	Rule     PermissionRuleSpec
	Matched  bool
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
	if rule, ok := firstPreparedCommandMatch(deny, cmd); ok {
		return commandDecision{Outcome: "deny", Rule: rule, Matched: true, RuleType: permissionRuleTypeStructured, Command: cmd}
	}
	if rule, ok := firstPreparedCommandMatch(ask, cmd); ok {
		return commandDecision{Outcome: "ask", Rule: rule, Matched: true, RuleType: permissionRuleTypeStructured, Command: cmd}
	}
	if hasUnresolvedSemanticGuard(deny, cmd) || hasUnresolvedSemanticGuard(ask, cmd) {
		return commandDecision{Outcome: "ask", Command: cmd}
	}
	if rule, ok := firstPreparedCommandAllowMatch(allow, cmd); ok {
		return commandDecision{Outcome: "allow", Rule: rule, Matched: true, RuleType: permissionRuleTypeStructured, Command: cmd}
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
			Action:         "permission",
			Name:           "composition.command",
			Effect:         commandDecision.Outcome,
			RuleType:       commandDecision.RuleType,
			Command:        cmd.Raw,
			CommandIndex:   &index,
			Parser:         cmd.Parser,
			SemanticParser: cmd.SemanticParser,
			Program:        cmd.Program,
			ActionPath:     append([]string(nil), cmd.ActionPath...),
			Source:         sourcePtr(commandDecision.Rule.Source),
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

func firstPreparedCommandMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesStructuredCommand(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedCommandAllowMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Spec.AllowUnsafeShell {
			continue
		}
		if rule.Selector.matchesStructuredCommand(cmd) {
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
		if !rule.Selector.hasStructuredSelector() {
			continue
		}
		if matchRequiresSemantic(rule.Selector.Match) && matchStructuralScopeMatches(rule.Selector.Match, cmd) {
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

func allowRuleCanMatch(rule PermissionRuleSpec, command string) bool {
	plan := commandpkg.Parse(command)
	if !commandpkg.IsSafeForEvaluation(plan) {
		return false
	}
	if rule.AllowUnsafeShell {
		return true
	}
	return invocation.IsStructuredSafeForAllow(command)
}

func applyRewriteStep(step RewriteStepSpec, command string) (string, bool) {
	if step.UnwrapShellDashC {
		return directive.UnwrapShellDashC(command)
	}
	if !IsZeroUnwrapWrapperSpec(step.UnwrapWrapper) {
		return directive.UnwrapWrapper(command, step.UnwrapWrapper.Wrappers)
	}
	if !IsZeroMoveFlagToEnvSpec(step.MoveFlagToEnv) {
		return directive.MoveFlagToEnv(command, step.MoveFlagToEnv.Flag, step.MoveFlagToEnv.Env)
	}
	if !IsZeroMoveEnvToFlagSpec(step.MoveEnvToFlag) {
		return directive.MoveEnvToFlag(command, step.MoveEnvToFlag.Env, step.MoveEnvToFlag.Flag)
	}
	if step.StripCommandPath {
		return directive.StripCommandPath(command)
	}
	return "", false
}

func ApplyRewriteStepForTest(step RewriteStepSpec, command string) (string, bool) {
	return applyRewriteStep(step, command)
}

func RewriteStepName(step RewriteStepSpec) string {
	return rewritePrimitiveName(step)
}

func (m MatchSpec) MatchMatches(command string) bool {
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return false
	}
	return m.matches(plan.Commands[0])
}

func RewriteStepMatches(step RewriteStepSpec, command string) bool {
	return selectorMatches(command, step.Match, step.Pattern, step.Patterns)
}

func PermissionRuleMatches(rule PermissionRuleSpec, command string) bool {
	return selectorMatches(command, rule.Match, rule.Pattern, rule.Patterns)
}

func PermissionAllowRuleMatches(rule PermissionRuleSpec, command string) bool {
	selector := prepareSelector(rule.Match, rule.Pattern, rule.Patterns)
	if selector.hasStructuredSelector() {
		_, ok := selector.matchesStructured(command)
		return allowRuleCanMatch(rule, command) && ok
	}
	return allowRuleCanMatch(rule, command) && rule.AllowUnsafeShell && selector.matchesRaw(command)
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

func patternMatches(command string, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(command)
}

func rewritePrimitiveName(step RewriteStepSpec) string {
	switch {
	case step.UnwrapShellDashC:
		return "unwrap_shell_dash_c"
	case !IsZeroUnwrapWrapperSpec(step.UnwrapWrapper):
		return "unwrap_wrapper"
	case !IsZeroMoveFlagToEnvSpec(step.MoveFlagToEnv):
		return "move_flag_to_env"
	case !IsZeroMoveEnvToFlagSpec(step.MoveEnvToFlag):
		return "move_env_to_flag"
	case step.StripCommandPath:
		return "strip_command_path"
	default:
		return "rewrite"
	}
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
	if m.Semantic != nil && !m.Semantic.matchesGit(cmd) {
		return false
	}
	return true
}

func (s SemanticMatchSpec) matchesGit(cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "git" || cmd.Git == nil {
		return false
	}
	git := cmd.Git
	if s.Verb != "" && git.Verb != s.Verb {
		return false
	}
	if len(s.VerbIn) > 0 && !containsString(s.VerbIn, git.Verb) {
		return false
	}
	if s.Remote != "" && git.Remote != s.Remote {
		return false
	}
	if len(s.RemoteIn) > 0 && !containsString(s.RemoteIn, git.Remote) {
		return false
	}
	if s.Branch != "" && git.Branch != s.Branch {
		return false
	}
	if len(s.BranchIn) > 0 && !containsString(s.BranchIn, git.Branch) {
		return false
	}
	if s.Ref != "" && git.Ref != s.Ref {
		return false
	}
	if len(s.RefIn) > 0 && !containsString(s.RefIn, git.Ref) {
		return false
	}
	if s.Force != nil && git.Force != *s.Force {
		return false
	}
	if s.Hard != nil && git.Hard != *s.Hard {
		return false
	}
	if s.Recursive != nil && git.Recursive != *s.Recursive {
		return false
	}
	if s.IncludeIgnored != nil && git.IncludeIgnored != *s.IncludeIgnored {
		return false
	}
	if s.Cached != nil && git.Cached != *s.Cached {
		return false
	}
	if s.Staged != nil && git.Staged != *s.Staged {
		return false
	}
	for _, flag := range s.FlagsContains {
		if !containsString(git.Flags, flag) {
			return false
		}
	}
	for _, prefix := range s.FlagsPrefixes {
		if !containsPrefix(git.Flags, prefix) {
			return false
		}
	}
	return true
}

func (s SemanticMatchSpec) fieldsUsed() []string {
	var fields []string
	if s.Verb != "" {
		fields = append(fields, "verb")
	}
	if len(s.VerbIn) > 0 {
		fields = append(fields, "verb_in")
	}
	if s.Remote != "" {
		fields = append(fields, "remote")
	}
	if len(s.RemoteIn) > 0 {
		fields = append(fields, "remote_in")
	}
	if s.Branch != "" {
		fields = append(fields, "branch")
	}
	if len(s.BranchIn) > 0 {
		fields = append(fields, "branch_in")
	}
	if s.Ref != "" {
		fields = append(fields, "ref")
	}
	if len(s.RefIn) > 0 {
		fields = append(fields, "ref_in")
	}
	if s.Force != nil {
		fields = append(fields, "force")
	}
	if s.Hard != nil {
		fields = append(fields, "hard")
	}
	if s.Recursive != nil {
		fields = append(fields, "recursive")
	}
	if s.IncludeIgnored != nil {
		fields = append(fields, "include_ignored")
	}
	if s.Cached != nil {
		fields = append(fields, "cached")
	}
	if s.Staged != nil {
		fields = append(fields, "staged")
	}
	if len(s.FlagsContains) > 0 {
		fields = append(fields, "flags_contains")
	}
	if len(s.FlagsPrefixes) > 0 {
		fields = append(fields, "flags_prefixes")
	}
	return fields
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
	if len(spec.Rewrite) == 0 && IsZeroPermissionSpec(spec.Permission) {
		issues = append(issues, "must set at least one rewrite or permission entry")
	}
	switch strings.TrimSpace(spec.ClaudePermissionMergeMode) {
	case "", "migration_compat", "strict", "cc_bash_proxy_authoritative":
	default:
		issues = append(issues, "claude_permission_merge_mode must be one of migration_compat, strict, or cc_bash_proxy_authoritative")
	}
	for i, step := range spec.Rewrite {
		prefix := fmt.Sprintf("rewrite[%d]", i)
		issues = append(issues, ValidateRewriteStep(prefix, step)...)
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

func ValidateRewriteStep(prefix string, step RewriteStepSpec) []string {
	var issues []string
	issues = append(issues, ValidateSelector(prefix, step.Match, step.Pattern, step.Patterns, false, false)...)
	primitiveCount := 0
	if step.UnwrapShellDashC {
		primitiveCount++
	}
	if !IsZeroUnwrapWrapperSpec(step.UnwrapWrapper) {
		primitiveCount++
		issues = append(issues, validateNonEmptyStrings(prefix+".unwrap_wrapper.wrappers", step.UnwrapWrapper.Wrappers)...)
	}
	if !IsZeroMoveFlagToEnvSpec(step.MoveFlagToEnv) {
		primitiveCount++
		if strings.TrimSpace(step.MoveFlagToEnv.Flag) == "" {
			issues = append(issues, prefix+".move_flag_to_env.flag must be non-empty")
		}
		if strings.TrimSpace(step.MoveFlagToEnv.Env) == "" {
			issues = append(issues, prefix+".move_flag_to_env.env must be non-empty")
		}
	}
	if !IsZeroMoveEnvToFlagSpec(step.MoveEnvToFlag) {
		primitiveCount++
		if strings.TrimSpace(step.MoveEnvToFlag.Env) == "" {
			issues = append(issues, prefix+".move_env_to_flag.env must be non-empty")
		}
		if strings.TrimSpace(step.MoveEnvToFlag.Flag) == "" {
			issues = append(issues, prefix+".move_env_to_flag.flag must be non-empty")
		}
	}
	if step.StripCommandPath {
		primitiveCount++
	}
	switch {
	case primitiveCount == 0:
		issues = append(issues, prefix+" must set exactly one rewrite primitive")
	case primitiveCount > 1:
		issues = append(issues, prefix+" must set exactly one rewrite primitive")
	}
	issues = append(issues, ValidateRewriteTest(prefix+".test", step.Test)...)
	return issues
}

func ValidatePermissionRule(prefix string, rule PermissionRuleSpec, effect string) []string {
	var issues []string
	issues = append(issues, ValidateSelector(prefix, rule.Match, rule.Pattern, rule.Patterns, true, true)...)
	if rule.AllowUnsafeShell && strings.TrimSpace(rule.Message) == "" {
		issues = append(issues, prefix+".message must be non-empty when allow_unsafe_shell is true")
	}
	issues = append(issues, ValidatePermissionTest(prefix+".test", rule.Test, effect)...)
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
		if match.Command != "" && match.Command != "git" {
			issues = append(issues, prefix+".semantic is only supported for command: git")
		}
		if match.Subcommand != "" {
			issues = append(issues, prefix+".subcommand cannot be used with semantic.verb")
		}
		issues = append(issues, ValidateGitSemanticMatchSpec(prefix+".semantic", *match.Semantic)...)
	}
	return issues
}

func ValidateGitSemanticMatchSpec(prefix string, semantic SemanticMatchSpec) []string {
	var issues []string
	if IsZeroSemanticMatchSpec(semantic) {
		issues = append(issues, prefix+" must not be empty")
	}
	if strings.TrimSpace(semantic.Verb) == "" && semantic.Verb != "" {
		issues = append(issues, prefix+".verb must be non-empty")
	}
	if strings.TrimSpace(semantic.Remote) == "" && semantic.Remote != "" {
		issues = append(issues, prefix+".remote must be non-empty")
	}
	if strings.TrimSpace(semantic.Branch) == "" && semantic.Branch != "" {
		issues = append(issues, prefix+".branch must be non-empty")
	}
	if strings.TrimSpace(semantic.Ref) == "" && semantic.Ref != "" {
		issues = append(issues, prefix+".ref must be non-empty")
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".verb_in", semantic.VerbIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".remote_in", semantic.RemoteIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".branch_in", semantic.BranchIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".ref_in", semantic.RefIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_contains", semantic.FlagsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_prefixes", semantic.FlagsPrefixes)...)
	return issues
}

func ValidateRewriteTest(prefix string, test RewriteTestSpec) []string {
	var issues []string
	if len(test) == 0 {
		issues = append(issues, prefix+" must be non-empty")
	}
	for i, c := range test {
		hasPass := strings.TrimSpace(c.Pass) != ""
		hasIn := strings.TrimSpace(c.In) != ""
		hasOut := strings.TrimSpace(c.Out) != ""
		switch {
		case hasPass && (hasIn || hasOut):
			issues = append(issues, fmt.Sprintf("%s[%d] must use either pass or in/out", prefix, i))
		case hasPass:
			continue
		case hasIn && hasOut:
			continue
		default:
			issues = append(issues, fmt.Sprintf("%s[%d] must set pass or both in and out", prefix, i))
		}
	}
	return issues
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
			issues = append(issues, prefix+" may only use allow and pass")
		}
	case "ask":
		if len(test.Ask) == 0 {
			issues = append(issues, prefix+".ask must be non-empty")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".ask", test.Ask)...)
		if len(test.Allow) > 0 || len(test.Deny) > 0 {
			issues = append(issues, prefix+" may only use ask and pass")
		}
	case "deny":
		if len(test.Deny) == 0 {
			issues = append(issues, prefix+".deny must be non-empty")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".deny", test.Deny)...)
		if len(test.Allow) > 0 || len(test.Ask) > 0 {
			issues = append(issues, prefix+" may only use deny and pass")
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".pass", test.Pass)...)
	if len(test.Pass) == 0 {
		issues = append(issues, prefix+".pass must be non-empty")
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
		switch c.Decision {
		case "allow", "ask", "deny":
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

func IsZeroSemanticMatchSpec(semantic SemanticMatchSpec) bool {
	return semantic.Verb == "" &&
		len(semantic.VerbIn) == 0 &&
		semantic.Remote == "" &&
		len(semantic.RemoteIn) == 0 &&
		semantic.Branch == "" &&
		len(semantic.BranchIn) == 0 &&
		semantic.Ref == "" &&
		len(semantic.RefIn) == 0 &&
		semantic.Force == nil &&
		semantic.Hard == nil &&
		semantic.Recursive == nil &&
		semantic.IncludeIgnored == nil &&
		semantic.Cached == nil &&
		semantic.Staged == nil &&
		len(semantic.FlagsContains) == 0 &&
		len(semantic.FlagsPrefixes) == 0
}

func IsZeroMoveFlagToEnvSpec(spec MoveFlagToEnvSpec) bool {
	return strings.TrimSpace(spec.Flag) == "" && strings.TrimSpace(spec.Env) == ""
}

func IsZeroMoveEnvToFlagSpec(spec MoveEnvToFlagSpec) bool {
	return strings.TrimSpace(spec.Env) == "" && strings.TrimSpace(spec.Flag) == ""
}

func IsZeroUnwrapWrapperSpec(spec UnwrapWrapperSpec) bool {
	return len(spec.Wrappers) == 0
}

func RewriteStrict(step RewriteStepSpec) bool {
	if step.Strict == nil {
		return true
	}
	return *step.Strict
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

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}
