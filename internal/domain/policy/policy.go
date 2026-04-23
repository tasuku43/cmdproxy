package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/directive"
	"github.com/tasuku43/cc-bash-proxy/internal/domain/invocation"
)

type PipelineSpec struct {
	Rewrite    []RewriteStepSpec `yaml:"rewrite" json:"rewrite,omitempty"`
	Permission PermissionSpec    `yaml:"permission" json:"permission,omitempty"`
	Test       PipelineTestSpec  `yaml:"test" json:"test,omitempty"`
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
}

type PermissionSpec struct {
	Deny  []PermissionRuleSpec `yaml:"deny" json:"deny,omitempty"`
	Ask   []PermissionRuleSpec `yaml:"ask" json:"ask,omitempty"`
	Allow []PermissionRuleSpec `yaml:"allow" json:"allow,omitempty"`
}

type PermissionRuleSpec struct {
	Match    MatchSpec          `yaml:"match" json:"match,omitempty"`
	Pattern  string             `yaml:"pattern" json:"pattern,omitempty"`
	Patterns []string           `yaml:"patterns" json:"patterns,omitempty"`
	Message  string             `yaml:"message" json:"message,omitempty"`
	Test     PermissionTestSpec `yaml:"test" json:"test,omitempty"`
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
	Source Source `json:"source"`
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
	Action   string `json:"action"`
	Name     string `json:"name,omitempty"`
	Effect   string `json:"effect,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Message  string `json:"message,omitempty"`
	Relaxed  bool   `json:"relaxed,omitempty"`
	Continue bool   `json:"continue,omitempty"`
}

func NewPipeline(spec PipelineSpec, src Source) Pipeline {
	return Pipeline{PipelineSpec: spec, Source: src}
}

func Evaluate(p Pipeline, command string) (Decision, error) {
	current := command
	trace := []TraceStep{}

	for _, step := range p.Rewrite {
		if !RewriteStepMatches(step, current) {
			continue
		}
		rewritten, ok := applyRewriteStep(step, current)
		if !ok {
			continue
		}
		trace = append(trace, TraceStep{
			Action:   "rewrite",
			Name:     rewritePrimitiveName(step),
			From:     current,
			To:       rewritten,
			Relaxed:  !RewriteStrict(step),
			Continue: step.Continue,
		})
		current = rewritten
		if !step.Continue {
			break
		}
	}

	if rule, ok := firstPermissionMatch(p.Permission.Deny, current); ok {
		trace = append(trace, TraceStep{Action: "permission", Effect: "deny", Message: rule.Message})
		return Decision{Outcome: "deny", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, ok := firstPermissionMatch(p.Permission.Ask, current); ok {
		trace = append(trace, TraceStep{Action: "permission", Effect: "ask", Message: rule.Message})
		return Decision{Outcome: "ask", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, ok := firstPermissionMatch(p.Permission.Allow, current); ok {
		trace = append(trace, TraceStep{Action: "permission", Effect: "allow", Message: rule.Message})
		return Decision{Outcome: "allow", Command: current, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}

	trace = append(trace, TraceStep{Action: "permission", Effect: "ask", Name: "default"})
	return Decision{Outcome: "ask", Command: current, OriginalCommand: command, Trace: trace}, nil
}

func firstPermissionMatch(rules []PermissionRuleSpec, command string) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if PermissionRuleMatches(rule, command) {
			return rule, true
		}
	}
	return PermissionRuleSpec{}, false
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
	return m.matches(invocation.Parse(command))
}

func RewriteStepMatches(step RewriteStepSpec, command string) bool {
	return selectorMatches(command, step.Match, step.Pattern, step.Patterns)
}

func PermissionRuleMatches(rule PermissionRuleSpec, command string) bool {
	return selectorMatches(command, rule.Match, rule.Pattern, rule.Patterns)
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

func (m MatchSpec) matches(parsed invocation.Parsed) bool {
	if parsed.Command == "" {
		return false
	}
	if m.Command != "" && parsed.Command != m.Command {
		return false
	}
	if len(m.CommandIn) > 0 && !containsString(m.CommandIn, parsed.Command) {
		return false
	}
	if m.CommandIsAbsolutePath && !invocation.IsAbsoluteCommand(parsed.CommandToken) {
		return false
	}
	if m.Subcommand != "" && parsed.Subcommand != m.Subcommand {
		return false
	}
	for _, arg := range m.ArgsContains {
		if !containsString(parsed.Args, arg) {
			return false
		}
	}
	for _, prefix := range m.ArgsPrefixes {
		if !containsPrefix(parsed.Args, prefix) {
			return false
		}
	}
	for _, env := range m.EnvRequires {
		if _, ok := parsed.EnvAssignments[env]; !ok {
			return false
		}
	}
	for _, env := range m.EnvMissing {
		if _, ok := parsed.EnvAssignments[env]; ok {
			return false
		}
	}
	return true
}

func ValidatePipeline(spec PipelineSpec) []string {
	var issues []string
	if len(spec.Rewrite) == 0 && IsZeroPermissionSpec(spec.Permission) {
		issues = append(issues, "must set at least one rewrite or permission entry")
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
