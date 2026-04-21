package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/tasuku43/cmdproxy/internal/domain/directive"
	"github.com/tasuku43/cmdproxy/internal/domain/invocation"
)

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type RuleSpec struct {
	ID      string      `yaml:"id"`
	Pattern string      `yaml:"pattern"`
	Matcher MatchSpec   `yaml:"match"`
	Reject  RejectSpec  `yaml:"reject"`
	Rewrite RewriteSpec `yaml:"rewrite"`
}

type RejectSpec struct {
	Message string         `yaml:"message" json:"message,omitempty"`
	Test    RejectTestSpec `yaml:"test" json:"test,omitempty"`
}

type RewriteSpec struct {
	UnwrapShellDashC bool              `yaml:"unwrap_shell_dash_c" json:"unwrap_shell_dash_c,omitempty"`
	UnwrapWrapper    UnwrapWrapperSpec `yaml:"unwrap_wrapper" json:"unwrap_wrapper,omitempty"`
	MoveFlagToEnv    MoveFlagToEnvSpec `yaml:"move_flag_to_env" json:"move_flag_to_env,omitempty"`
	MoveEnvToFlag    MoveEnvToFlagSpec `yaml:"move_env_to_flag" json:"move_env_to_flag,omitempty"`
	StripCommandPath bool              `yaml:"strip_command_path" json:"strip_command_path,omitempty"`
	Continue         bool              `yaml:"continue" json:"continue,omitempty"`
	Test             RewriteTestSpec   `yaml:"test" json:"test,omitempty"`
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

type RejectTestSpec struct {
	Expect []string `yaml:"expect" json:"expect,omitempty"`
	Pass   []string `yaml:"pass" json:"pass,omitempty"`
}

type RewriteTestSpec struct {
	Expect []RewriteExpectCase `yaml:"expect" json:"expect,omitempty"`
	Pass   []string            `yaml:"pass" json:"pass,omitempty"`
}

type RewriteExpectCase struct {
	In  string `yaml:"in" json:"in,omitempty"`
	Out string `yaml:"out" json:"out,omitempty"`
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

type Rule struct {
	RuleSpec
	Source Source `json:"source"`
	re     *regexp.Regexp
}

type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Issues, "; ")
}

type Decision struct {
	Outcome         string
	Rule            *Rule
	Command         string
	OriginalCommand string
	Trace           []TraceStep
}

type TraceStep struct {
	RuleID   string `json:"rule_id"`
	Action   string `json:"action"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Message  string `json:"message,omitempty"`
	Continue bool   `json:"continue,omitempty"`
}

const maxRewritePasses = 4

func NewRule(spec RuleSpec, src Source) Rule {
	r := Rule{RuleSpec: spec, Source: src}
	if strings.TrimSpace(spec.Pattern) != "" {
		r.re, _ = regexp.Compile(spec.Pattern)
	}
	return r
}

func Evaluate(rules []Rule, command string) (Decision, error) {
	current := command
	var lastRewriteRule *Rule
	trace := []TraceStep{}
	for pass := 0; pass < maxRewritePasses; pass++ {
		restarted := false
		for i := range rules {
			matched, err := rules[i].Match(current)
			if err != nil {
				return Decision{}, err
			}
			if !matched {
				continue
			}
			if !IsZeroRewriteSpec(rules[i].Rewrite) {
				rewritten, ok := rules[i].RewriteCommand(current)
				if !ok {
					continue
				}
				step := TraceStep{
					RuleID:   rules[i].ID,
					Action:   "rewrite",
					From:     current,
					To:       rewritten,
					Continue: rules[i].Rewrite.Continue,
				}
				trace = append(trace, step)
				if rules[i].Rewrite.Continue {
					if rewritten == current {
						return Decision{}, fmt.Errorf("rewrite rule %s produced no-op continue", rules[i].ID)
					}
					lastRewriteRule = &rules[i]
					current = rewritten
					restarted = true
					break
				}
				return Decision{Outcome: "rewrite", Rule: &rules[i], Command: rewritten, OriginalCommand: command, Trace: trace}, nil
			}
			trace = append(trace, TraceStep{
				RuleID:  rules[i].ID,
				Action:  "reject",
				From:    current,
				Message: rules[i].RejectMessage(),
			})
			return Decision{Outcome: "reject", Rule: &rules[i], Command: current, OriginalCommand: command, Trace: trace}, nil
		}
		if restarted {
			continue
		}
		if current != command {
			return Decision{Outcome: "rewrite", Rule: lastRewriteRule, Command: current, OriginalCommand: command, Trace: trace}, nil
		}
		return Decision{Outcome: "pass", Command: current, OriginalCommand: command, Trace: trace}, nil
	}
	return Decision{}, fmt.Errorf("rewrite evaluation exceeded %d passes", maxRewritePasses)
}

func (r Rule) Match(command string) (bool, error) {
	if !IsZeroMatchSpec(r.Matcher) {
		return r.Matcher.matches(invocation.Parse(command)), nil
	}
	if r.re != nil {
		return r.re.MatchString(command), nil
	}
	compiled, err := regexp.Compile(r.Pattern)
	if err != nil {
		return false, err
	}
	return compiled.MatchString(command), nil
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

func ValidateRuleMatcher(prefix string, pattern string, match MatchSpec) []string {
	var issues []string
	hasPattern := strings.TrimSpace(pattern) != ""
	hasMatch := !IsZeroMatchSpec(match)
	switch {
	case hasPattern && hasMatch:
		issues = append(issues, prefix+" must not set both pattern and match")
	case !hasPattern && !hasMatch:
		issues = append(issues, prefix+" must set exactly one of pattern or match")
	case hasPattern:
		if _, err := regexp.Compile(pattern); err != nil {
			issues = append(issues, prefix+".pattern failed to compile: "+err.Error())
		}
	case hasMatch:
		issues = append(issues, ValidateMatchSpec(prefix+".match", match)...)
	}
	return issues
}

func ValidateDirective(prefix string, reject RejectSpec, rewrite RewriteSpec) []string {
	hasReject := strings.TrimSpace(reject.Message) != ""
	hasRewrite := !IsZeroRewriteSpec(rewrite)
	switch {
	case countDirectiveKinds(hasReject, hasRewrite) > 1:
		return []string{prefix + " must set exactly one directive kind"}
	case countDirectiveKinds(hasReject, hasRewrite) == 0:
		return []string{prefix + " must set one directive"}
	case hasRewrite:
		return ValidateRewrite(prefix+".rewrite", rewrite)
	case hasReject:
		return ValidateReject(prefix+".reject", reject)
	default:
		return nil
	}
}

func ValidateRewrite(prefix string, rewrite RewriteSpec) []string {
	var issues []string
	primitiveCount := 0
	if rewrite.UnwrapShellDashC {
		primitiveCount++
	}
	if !IsZeroUnwrapWrapperSpec(rewrite.UnwrapWrapper) {
		primitiveCount++
		issues = append(issues, validateNonEmptyStrings(prefix+".unwrap_wrapper.wrappers", rewrite.UnwrapWrapper.Wrappers)...)
	}
	if !IsZeroMoveFlagToEnvSpec(rewrite.MoveFlagToEnv) {
		primitiveCount++
		if strings.TrimSpace(rewrite.MoveFlagToEnv.Flag) == "" {
			issues = append(issues, prefix+".move_flag_to_env.flag must be non-empty")
		}
		if strings.TrimSpace(rewrite.MoveFlagToEnv.Env) == "" {
			issues = append(issues, prefix+".move_flag_to_env.env must be non-empty")
		}
	}
	if !IsZeroMoveEnvToFlagSpec(rewrite.MoveEnvToFlag) {
		primitiveCount++
		if strings.TrimSpace(rewrite.MoveEnvToFlag.Env) == "" {
			issues = append(issues, prefix+".move_env_to_flag.env must be non-empty")
		}
		if strings.TrimSpace(rewrite.MoveEnvToFlag.Flag) == "" {
			issues = append(issues, prefix+".move_env_to_flag.flag must be non-empty")
		}
	}
	if rewrite.StripCommandPath {
		primitiveCount++
	}
	switch {
	case primitiveCount == 0:
		issues = append(issues, prefix+" must not be empty")
	case primitiveCount > 1:
		issues = append(issues, prefix+" must set exactly one rewrite primitive")
	}
	issues = append(issues, ValidateRewriteTest(prefix+".test", rewrite.Test)...)
	return issues
}

func ValidateReject(prefix string, reject RejectSpec) []string {
	var issues []string
	if strings.TrimSpace(reject.Message) == "" {
		issues = append(issues, prefix+".message must be non-empty")
	}
	issues = append(issues, ValidateRejectTest(prefix+".test", reject.Test)...)
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

func ValidateRules(rules []RuleSpec) []string {
	var issues []string
	seen := map[string]struct{}{}
	for i, r := range rules {
		prefix := fmt.Sprintf("rules[%d]", i)
		if !ruleIDPattern.MatchString(r.ID) {
			issues = append(issues, prefix+".id must match [a-z0-9][a-z0-9-]*")
		}
		if _, ok := seen[r.ID]; ok && r.ID != "" {
			issues = append(issues, prefix+".id duplicates another rule in the same file")
		}
		seen[r.ID] = struct{}{}
		issues = append(issues, ValidateRuleMatcher(prefix, r.Pattern, r.Matcher)...)
		issues = append(issues, ValidateDirective(prefix, r.Reject, r.Rewrite)...)
	}
	return issues
}

func ValidateDuplicateIDs(rules []Rule) []error {
	seen := map[string]Source{}
	var errs []error
	for _, r := range rules {
		if prev, ok := seen[r.ID]; ok {
			errs = append(errs, fmt.Errorf("duplicate rule id %q across %s and %s", r.ID, prev.Path, r.Source.Path))
			continue
		}
		seen[r.ID] = r.Source
	}
	return errs
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

func (r Rule) RejectMessage() string {
	return r.Reject.Message
}

func (r Rule) RewriteCommand(command string) (string, bool) {
	if r.Rewrite.UnwrapShellDashC {
		return directive.UnwrapShellDashC(command)
	}
	if !IsZeroUnwrapWrapperSpec(r.Rewrite.UnwrapWrapper) {
		return directive.UnwrapWrapper(command, r.Rewrite.UnwrapWrapper.Wrappers)
	}
	if !IsZeroMoveFlagToEnvSpec(r.Rewrite.MoveFlagToEnv) {
		return directive.MoveFlagToEnv(command, r.Rewrite.MoveFlagToEnv.Flag, r.Rewrite.MoveFlagToEnv.Env)
	}
	if !IsZeroMoveEnvToFlagSpec(r.Rewrite.MoveEnvToFlag) {
		return directive.MoveEnvToFlag(command, r.Rewrite.MoveEnvToFlag.Env, r.Rewrite.MoveEnvToFlag.Flag)
	}
	if r.Rewrite.StripCommandPath {
		return directive.StripCommandPath(command)
	}
	return "", false
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

func IsZeroRewriteSpec(rewrite RewriteSpec) bool {
	return !rewrite.UnwrapShellDashC &&
		IsZeroUnwrapWrapperSpec(rewrite.UnwrapWrapper) &&
		IsZeroMoveFlagToEnvSpec(rewrite.MoveFlagToEnv) &&
		IsZeroMoveEnvToFlagSpec(rewrite.MoveEnvToFlag) &&
		!rewrite.StripCommandPath
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

func countDirectiveKinds(hasReject bool, hasRewrite bool) int {
	n := 0
	if hasReject {
		n++
	}
	if hasRewrite {
		n++
	}
	return n
}

func ValidateRejectTest(prefix string, test RejectTestSpec) []string {
	var issues []string
	if len(test.Expect) == 0 {
		issues = append(issues, prefix+".expect must be non-empty")
	}
	if len(test.Pass) == 0 {
		issues = append(issues, prefix+".pass must be non-empty")
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".expect", test.Expect)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".pass", test.Pass)...)
	return issues
}

func ValidateRewriteTest(prefix string, test RewriteTestSpec) []string {
	var issues []string
	if len(test.Expect) == 0 {
		issues = append(issues, prefix+".expect must be non-empty")
	}
	if len(test.Pass) == 0 {
		issues = append(issues, prefix+".pass must be non-empty")
	}
	for i, c := range test.Expect {
		if strings.TrimSpace(c.In) == "" {
			issues = append(issues, fmt.Sprintf("%s.expect[%d].in must be non-empty", prefix, i))
		}
		if strings.TrimSpace(c.Out) == "" {
			issues = append(issues, fmt.Sprintf("%s.expect[%d].out must be non-empty", prefix, i))
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".pass", test.Pass)...)
	return issues
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
