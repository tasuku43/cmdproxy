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
	Command               string   `yaml:"command" json:"command,omitempty"`
	CommandIn             []string `yaml:"command_in" json:"command_in,omitempty"`
	CommandIsAbsolutePath bool     `yaml:"command_is_absolute_path" json:"command_is_absolute_path,omitempty"`
	Subcommand            string   `yaml:"subcommand" json:"subcommand,omitempty"`
	ArgsContains          []string `yaml:"args_contains" json:"args_contains,omitempty"`
	ArgsPrefixes          []string `yaml:"args_prefixes" json:"args_prefixes,omitempty"`
	EnvRequires           []string `yaml:"env_requires" json:"env_requires,omitempty"`
	EnvMissing            []string `yaml:"env_missing" json:"env_missing,omitempty"`
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
	Program        string   `json:"program,omitempty"`
	ActionPath     []string `json:"action_path,omitempty"`
	Shape          string   `json:"shape,omitempty"`
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
	prepared := p.prepared
	if !prepared.Ready {
		prepared = preparePipeline(stampSources(p.PipelineSpec, p.Source))
	}

	for _, step := range prepared.Rewrite {
		if !step.Selector.matches(current) {
			continue
		}
		rewritten, ok := applyRewriteStep(step.Spec, current)
		if !ok {
			continue
		}
		trace = append(trace, TraceStep{
			Action:   "rewrite",
			Name:     rewritePrimitiveName(step.Spec),
			From:     current,
			To:       rewritten,
			Relaxed:  !RewriteStrict(step.Spec),
			Continue: step.Spec.Continue,
			Source:   sourcePtr(step.Spec.Source),
		})
		current = rewritten
		if !step.Spec.Continue {
			break
		}
	}

	if rule, ok := firstPreparedRawPermissionMatch(prepared.Deny, current); ok {
		trace = append(trace, permissionTraceStep("deny", permissionRuleTypeRaw, rule))
		return Decision{Outcome: "deny", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, ok := firstPreparedStructuredPermissionMatch(prepared.Deny, current); ok {
		trace = append(trace, permissionTraceStep("deny", permissionRuleTypeStructured, rule))
		return Decision{Outcome: "deny", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, ok := firstPreparedRawPermissionMatch(prepared.Ask, current); ok {
		trace = append(trace, permissionTraceStep("ask", permissionRuleTypeRaw, rule))
		return Decision{Outcome: "ask", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, ok := firstPreparedStructuredPermissionMatch(prepared.Ask, current); ok {
		trace = append(trace, permissionTraceStep("ask", permissionRuleTypeStructured, rule))
		return Decision{Outcome: "ask", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, ok := firstPreparedStructuredAllowPermissionMatch(prepared.Allow, current); ok {
		trace = append(trace, permissionTraceStep("allow", permissionRuleTypeStructured, rule))
		return Decision{Outcome: "allow", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, current, false); ok {
		trace = append(trace, decision.Trace...)
		return Decision{Outcome: decision.Outcome, Command: current, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
	}
	if rule, ok := firstPreparedRawAllowPermissionMatch(prepared.Allow, current); ok {
		trace = append(trace, permissionTraceStep("allow", permissionRuleTypeRaw, rule))
		return Decision{Outcome: "allow", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, current, true); ok {
		trace = append(trace, decision.Trace...)
		return Decision{Outcome: decision.Outcome, Command: current, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
	}

	trace = append(trace, TraceStep{Action: "permission", Effect: "ask", Name: "default"})
	return Decision{Outcome: "ask", Command: current, OriginalCommand: command, Trace: trace}, nil
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

func firstPreparedRawPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesRaw(command) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedStructuredPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesStructured(command) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedStructuredAllowPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if !allowRuleCanMatch(rule.Spec, command) {
			continue
		}
		if rule.Selector.matchesStructured(command) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedRawAllowPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if !rule.Spec.AllowUnsafeShell {
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

func evaluateCommandPlanComposition(deny []preparedPermissionRule, ask []preparedPermissionRule, allow []preparedPermissionRule, raw string, includeDefaultAsk bool) (compositionDecision, bool) {
	plan := commandpkg.Parse(raw)
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

	switch plan.Shape.Kind {
	case commandpkg.ShellShapeAndList, commandpkg.ShellShapeSequence, commandpkg.ShellShapeOrList, commandpkg.ShellShapePipeline:
		decision := compositionDecision{
			Outcome:  "allow",
			Message:  decisions[0].Rule.Message,
			Source:   decisions[0].Rule.Source,
			RuleType: permissionRuleTypeStructured,
			Reason:   "all commands allowed",
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	case commandpkg.ShellShapeBackground, commandpkg.ShellShapeRedirect, commandpkg.ShellShapeSubshell, commandpkg.ShellShapeUnknown:
		if !includeDefaultAsk {
			return compositionDecision{}, false
		}
		if plan.Shape.HasProcessSubstitution {
			decision := compositionDecision{
				Outcome: "ask",
				Reason:  "process substitution requires confirmation",
			}
			decision.Trace = compositionTrace(plan, decisions, decision)
			return decision, true
		}
		return compositionDecision{}, false
	default:
		return compositionDecision{}, false
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
		Action:   "permission",
		Effect:   decision.Outcome,
		Name:     "composition",
		RuleType: decision.RuleType,
		Message:  decision.Message,
		Reason:   decision.Reason,
		Shape:    string(plan.Shape.Kind),
		Source:   sourcePtr(decision.Source),
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
	return match.Subcommand != ""
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
		return allowRuleCanMatch(rule, command) && selector.matchesStructured(command)
	}
	return rule.AllowUnsafeShell && selector.matchesRaw(command)
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

func (s preparedSelector) matchesStructured(command string) bool {
	return s.hasStructuredSelector() && s.Match.MatchMatches(command)
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
	issues = append(issues, ValidateSelector(prefix, step.Match, step.Pattern, step.Patterns, false)...)
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
	issues = append(issues, ValidateSelector(prefix, rule.Match, rule.Pattern, rule.Patterns, true)...)
	if rule.AllowUnsafeShell && strings.TrimSpace(rule.Message) == "" {
		issues = append(issues, prefix+".message must be non-empty when allow_unsafe_shell is true")
	}
	issues = append(issues, ValidatePermissionTest(prefix+".test", rule.Test, effect)...)
	return issues
}

func ValidateSelector(prefix string, match MatchSpec, pattern string, patterns []string, required bool) []string {
	var issues []string
	count := 0
	if !IsZeroMatchSpec(match) {
		count++
		issues = append(issues, ValidateMatchSpec(prefix+".match", match)...)
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
		len(match.EnvMissing) == 0
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
