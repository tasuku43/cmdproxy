package app

import (
	"errors"
	"regexp"
	"strings"

	"github.com/tasuku43/cc-bash-guard/internal/adapter/claude"
	"github.com/tasuku43/cc-bash-guard/internal/app/doctoring"
	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
	"github.com/tasuku43/cc-bash-guard/internal/infra/buildinfo"
	configrepo "github.com/tasuku43/cc-bash-guard/internal/infra/config"
)

func RunVerify(env Env) VerifyResult {
	return RunVerifyWithOptions(env, VerifyOptions{})
}

func RunVerifyWithOptions(env Env, opts VerifyOptions) VerifyResult {
	tool := claude.Tool
	inputs := configrepo.ResolveEffectiveInputs(env.Cwd, env.Home, env.XDGConfigHome, tool)
	loaded := configrepo.LoadEffectiveForTool(env.Cwd, env.Home, env.XDGConfigHome, tool)
	report := doctoring.Run(loaded, tool, env.Cwd, env.Home)
	report.Tool = tool
	report.ConfigSources = inputs.ConfigFiles
	report.SettingsPaths = inputs.SettingsPaths
	report.EffectiveFingerprint = inputs.Fingerprint
	info := buildinfo.Read()
	ok, reasons := VerifyStatus(report, info, tool)
	artifactBuilt := false
	permissionRules := len(loaded.Pipeline.Permission.Deny) + len(loaded.Pipeline.Permission.Ask) + len(loaded.Pipeline.Permission.Allow)
	tests := len(loaded.Pipeline.Test)
	failures := verifyFailures(loaded, tool, env.Cwd, env.Home, opts.AllFailures)
	warnings := verifyWarnings(loaded)
	for _, reason := range reasons {
		if !diagnosticMessageExists(failures, reason) {
			failures = append(failures, VerifyDiagnostic{Kind: "verify_check_failed", Title: "Verify check failed", Message: reason})
		}
	}
	if len(failures) > 0 {
		ok = false
	}
	if ok {
		rules, err := configrepo.VerifyEffectiveToAllCaches(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, tool, info.Version)
		if err != nil {
			ok = false
			reasons = append(reasons, err.Error())
			failures = append(failures, VerifyDiagnostic{Kind: "artifact_write_failed", Title: "Artifact write failed", Message: err.Error()})
		} else if len(rules.Rewrite) > 0 || !policy.IsZeroPermissionSpec(rules.Permission) || len(rules.Test) > 0 {
			artifactBuilt = true
			permissionRules = len(rules.Permission.Deny) + len(rules.Permission.Ask) + len(rules.Permission.Allow)
			tests = len(rules.Test)
		}
	}
	summary := VerifySummary{
		ConfigFiles:     len(inputs.ConfigFiles),
		PermissionRules: permissionRules,
		Tests:           tests,
		Failures:        len(failures),
		Warnings:        len(warnings),
	}

	return VerifyResult{
		Tool:            tool,
		BuildInfo:       info,
		Report:          report,
		Verified:        ok,
		ArtifactBuilt:   artifactBuilt,
		ArtifactCache:   configrepo.HookCacheDirs(env.Home, env.XDGCacheHome),
		PermissionRules: permissionRules,
		Tests:           tests,
		ConfigFiles:     len(inputs.ConfigFiles),
		Failures:        reasons,
		Diagnostics:     failures,
		Warnings:        warnings,
		Summary:         summary,
	}
}

func diagnosticMessageExists(diags []VerifyDiagnostic, message string) bool {
	for _, diag := range diags {
		if diag.Message == message || strings.Contains(message, diag.Message) || strings.Contains(diag.Message, message) {
			return true
		}
	}
	return false
}

func VerifyStatus(report doctoring.Report, info buildinfo.Info, tool string) (bool, []string) {
	var reasons []string

	for _, check := range report.Checks {
		if check.Status == doctoring.StatusFail {
			reasons = append(reasons, check.ID+": "+check.Message)
			continue
		}
		if tool == claude.Tool && check.ID == "install.claude-registered" && check.Status == doctoring.StatusWarn && !strings.Contains(check.Message, "settings.json not found") {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
		if tool == claude.Tool && check.ID == "install.claude-hook-path" && check.Status == doctoring.StatusWarn {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
		if tool == claude.Tool && (check.ID == "install.claude-hook-target" || check.ID == "install.claude-hook-binary-match") && check.Status == doctoring.StatusWarn {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
	}
	return len(reasons) == 0, reasons
}

func verifyFailures(loaded configrepo.Loaded, tool string, cwd string, home string, all bool) []VerifyDiagnostic {
	var failures []VerifyDiagnostic
	for _, err := range loaded.Errors {
		failures = append(failures, diagnosticsFromError(err)...)
	}
	if len(loaded.Errors) > 0 {
		return failures
	}
	for _, failure := range doctoring.CollectTestFailures(loaded.Pipeline, tool, cwd, home, all) {
		failures = append(failures, diagnosticFromTestFailure(failure))
	}
	failures = append(failures, verifyPolicyFailures(loaded)...)
	return failures
}

func verifyPolicyFailures(loaded configrepo.Loaded) []VerifyDiagnostic {
	var failures []VerifyDiagnostic
	for _, rule := range loaded.Pipeline.Permission.Allow {
		failures = append(failures, broadAllowRuleFailures(rule)...)
		failures = append(failures, broadAllowPatternFailures(rule)...)
	}
	failures = append(failures, semanticAllowSubsumptionFailures(loaded.Pipeline.Permission.Allow)...)
	return failures
}

func broadAllowRuleFailures(rule policy.PermissionRuleSpec) []VerifyDiagnostic {
	var failures []VerifyDiagnostic
	if policy.IsZeroPermissionCommandSpec(rule.Command) && len(rule.Patterns) == 0 && !policy.IsZeroPermissionEnvSpec(rule.Env) {
		failures = append(failures, broadAllowRuleFailure(rule, "", "env-only allow can allow any command when the environment matches"))
	}
	if cmd := strings.TrimSpace(rule.Command.Name); cmd != "" && rule.Command.Semantic == nil {
		if _, ok := semanticpkg.Lookup(cmd); ok {
			failures = append(failures, broadAllowRuleFailure(rule, cmd, "command.name allows the whole "+cmd+" command namespace without semantic constraints"))
		} else if isScriptRunnerOrInterpreter(cmd) {
			failures = append(failures, broadAllowRuleFailure(rule, cmd, "command.name allows script runner or generic interpreter "+cmd+" without a narrow semantic or pattern constraint"))
		}
	}
	if len(rule.Command.NameIn) > 0 && rule.Command.Semantic == nil {
		for _, name := range rule.Command.NameIn {
			cmd := strings.TrimSpace(name)
			if cmd == "" {
				continue
			}
			if _, ok := semanticpkg.Lookup(cmd); ok {
				failures = append(failures, broadAllowRuleFailure(rule, cmd, "command.name_in includes supported semantic command "+cmd+" without semantic constraints"))
				continue
			}
			if isScriptRunnerOrInterpreter(cmd) {
				failures = append(failures, broadAllowRuleFailure(rule, cmd, "command.name_in includes script runner or generic interpreter "+cmd+" without a narrow pattern constraint"))
			}
		}
	}
	return failures
}

func broadAllowRuleFailure(rule policy.PermissionRuleSpec, cmd string, reason string) VerifyDiagnostic {
	return VerifyDiagnostic{
		Kind:             "broad_allow_rule",
		Title:            "Broad allow rule",
		Source:           sourceFromPolicy(rule.Source, rule.Name),
		Command:          cmd,
		Message:          "permission.allow rule is broad: " + reason,
		Reason:           reason,
		Hint:             "Move broad namespace rules to permission.ask. For supported commands, replace broad allow with command.semantic fields and keep rule-local allow/abstain tests; use narrow anchored patterns only as fallback.",
		SaferAlternative: broadAllowRuleAlternative(cmd),
	}
}

func broadAllowRuleAlternative(cmd string) string {
	if cmd == "" {
		return "Add command.name plus command.semantic for supported commands, or move this rule from permission.allow to permission.ask."
	}
	if _, supported := semanticpkg.Lookup(cmd); supported {
		return "Use command.semantic for " + cmd + " or move the broad namespace rule from permission.allow to permission.ask."
	}
	return "Use a narrow anchored pattern for the exact safe invocation, or move this rule from permission.allow to permission.ask."
}

func semanticAllowSubsumptionFailures(rules []policy.PermissionRuleSpec) []VerifyDiagnostic {
	var failures []VerifyDiagnostic
	for narrowIndex, narrow := range rules {
		cmd := strings.TrimSpace(narrow.Command.Name)
		if cmd == "" || narrow.Command.Semantic == nil {
			continue
		}
		if _, ok := semanticpkg.Lookup(cmd); !ok {
			continue
		}
		for broadIndex, broad := range rules {
			if narrowIndex == broadIndex {
				continue
			}
			reason, ok := broadAllowSubsumesSemanticCommand(broad, cmd)
			if !ok {
				continue
			}
			failures = append(failures, semanticAllowSubsumptionFailure(narrow, broad, cmd, reason))
		}
	}
	return failures
}

func broadAllowSubsumesSemanticCommand(rule policy.PermissionRuleSpec, cmd string) (string, bool) {
	if rule.Command.Semantic != nil {
		return "", false
	}
	if strings.TrimSpace(rule.Command.Name) == cmd {
		return "command.name allows the whole " + cmd + " command namespace without semantic constraints", true
	}
	for _, name := range rule.Command.NameIn {
		if strings.TrimSpace(name) == cmd {
			return "command.name_in includes " + cmd + " without semantic constraints", true
		}
	}
	if policy.IsZeroPermissionCommandSpec(rule.Command) && len(rule.Patterns) == 0 && !policy.IsZeroPermissionEnvSpec(rule.Env) {
		return "env-only allow can allow any command when the environment matches", true
	}
	for _, pattern := range rule.Patterns {
		if patternCommand, ok := broadCommandPrefixPattern(strings.TrimSpace(pattern)); ok && patternCommand == cmd {
			return "patterns allow the " + cmd + " command namespace without semantic constraints", true
		}
	}
	return "", false
}

func semanticAllowSubsumptionFailure(narrow policy.PermissionRuleSpec, broad policy.PermissionRuleSpec, cmd string, reason string) VerifyDiagnostic {
	broadName := strings.TrimSpace(broad.Name)
	if broadName == "" {
		broadName = "unnamed allow rule"
	}
	return VerifyDiagnostic{
		Kind:             "semantic_allow_subsumed_by_broad_allow",
		Title:            "Semantic allow subsumed by broad allow",
		Source:           sourceFromPolicy(narrow.Source, narrow.Name),
		First:            sourceFromPolicy(narrow.Source, narrow.Name),
		Second:           sourceFromPolicy(broad.Source, broad.Name),
		Command:          cmd,
		Message:          "semantic allow for command " + cmd + " is subsumed by broader allow rule `" + broadName + "`; use command.semantic on the broader rule, move broad behavior to permission.ask, or remove the broad allow.",
		Reason:           reason,
		Hint:             "Move broad namespace rules to permission.ask. Keep permission.allow narrow with command.semantic fields and add explicit deny rules for known dangerous operations where appropriate.",
		SaferAlternative: "Use command.semantic for " + cmd + ", move the broad rule from permission.allow to permission.ask, or remove the broad allow.",
	}
}

func verifyWarnings(loaded configrepo.Loaded) []VerifyDiagnostic {
	var warnings []VerifyDiagnostic
	for _, rule := range loaded.Pipeline.Permission.Allow {
		if policy.IsZeroPermissionCommandSpec(rule.Command) && len(rule.Patterns) == 0 && !policy.IsZeroPermissionEnvSpec(rule.Env) {
			warnings = append(warnings, VerifyDiagnostic{
				Kind:    "env_only_allow_rule",
				Title:   "env-only allow rule",
				Source:  sourceFromPolicy(rule.Source, rule.Name),
				Message: "env-only allow can allow any command when env matches",
			})
		}
	}
	warnings = append(warnings, deprecatedPassWarnings(loaded.Pipeline)...)
	warnings = append(warnings, duplicateRuleNameWarnings(loaded.Pipeline)...)
	return warnings
}

func deprecatedPassWarnings(p policy.Pipeline) []VerifyDiagnostic {
	var warnings []VerifyDiagnostic
	visit := func(rules []policy.PermissionRuleSpec) {
		for _, rule := range rules {
			if len(rule.Test.Pass) == 0 {
				continue
			}
			warnings = append(warnings, VerifyDiagnostic{
				Kind:    "deprecated_test_pass",
				Title:   "Deprecated test.pass",
				Source:  sourceFromPolicy(rule.Source, rule.Name),
				Message: "test.pass is deprecated; use test.abstain",
			})
		}
	}
	visit(p.Permission.Deny)
	visit(p.Permission.Ask)
	visit(p.Permission.Allow)
	return warnings
}

func broadAllowPatternFailures(rule policy.PermissionRuleSpec) []VerifyDiagnostic {
	var failures []VerifyDiagnostic
	for _, pattern := range rule.Patterns {
		if failure, ok := broadAllowPatternFailure(rule, pattern); ok {
			failures = append(failures, failure)
		}
	}
	return failures
}

func broadAllowPatternFailure(rule policy.PermissionRuleSpec, pattern string) (VerifyDiagnostic, bool) {
	p := strings.TrimSpace(pattern)
	var reasons []string

	if p == ".*" || p == "^.*" || p == "^.*$" {
		reasons = append(reasons, "matches nearly any command")
	}
	if p != "" && !strings.HasPrefix(p, "^") {
		reasons = append(reasons, "is not anchored at the beginning, so it can match after another command or argument")
	}
	if cmd, ok := broadCommandPrefixPattern(p); ok {
		reasons = append(reasons, "allows the "+cmd+" command namespace without a meaningful subcommand boundary")
	}
	if broadShellMetacharPattern(p) {
		reasons = append(reasons, "uses a broad wildcard that can also match shell metacharacters such as ;, &, |, backticks, $(), redirects, or subshell syntax")
	}
	if len(reasons) == 0 {
		return VerifyDiagnostic{}, false
	}

	return VerifyDiagnostic{
		Kind:             "broad_allow_pattern",
		Title:            "Broad allow pattern",
		Source:           sourceFromPolicy(rule.Source, rule.Name),
		Pattern:          pattern,
		Message:          "allow.patterns rule is broad: " + strings.Join(reasons, "; "),
		Reason:           strings.Join(reasons, "; "),
		Hint:             saferPatternHint(pattern),
		SaferAlternative: saferPatternAlternative(pattern),
	}, true
}

func broadCommandPrefixPattern(pattern string) (string, bool) {
	pattern = trimLeadingRegexWhitespace(pattern)
	for _, cmd := range broadPatternCommands() {
		prefix := "^" + cmd
		if !strings.HasPrefix(pattern, prefix) {
			continue
		}
		rest := strings.TrimPrefix(pattern, prefix)
		if rest == "" || rest == "$" {
			return cmd, true
		}
		if startsLiteralCommandContinuation(rest) {
			continue
		}
		if strings.HasPrefix(rest, ".*") || strings.HasPrefix(rest, ".+") {
			return cmd, true
		}
		if strings.HasPrefix(rest, `\b`) || strings.HasPrefix(rest, `(\s|$)`) || strings.HasPrefix(rest, `(?:\s|$)`) {
			return cmd, true
		}
		afterBoundary, ok := trimRegexWhitespaceBoundary(rest)
		if !ok {
			return cmd, true
		}
		afterBoundary = strings.TrimSpace(afterBoundary)
		if afterBoundary == "" || afterBoundary == "$" || strings.HasPrefix(afterBoundary, ".*") || strings.HasPrefix(afterBoundary, ".+") {
			return cmd, true
		}
	}
	return "", false
}

func broadPatternCommands() []string {
	return []string{"git", "aws", "kubectl", "gh", "gws", "helm", "helmfile", "argocd", "terraform", "docker", "bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl", "make", "npm", "yarn", "pnpm", "npx", "xargs", "ssh"}
}

func isScriptRunnerOrInterpreter(cmd string) bool {
	switch cmd {
	case "bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl", "make", "npm", "yarn", "pnpm", "npx", "xargs", "ssh":
		return true
	default:
		return false
	}
}

func trimLeadingRegexWhitespace(pattern string) string {
	if strings.HasPrefix(pattern, `^\s*`) {
		return "^" + strings.TrimPrefix(pattern, `^\s*`)
	}
	if strings.HasPrefix(pattern, `^[[:space:]]*`) {
		return "^" + strings.TrimPrefix(pattern, `^[[:space:]]*`)
	}
	if strings.HasPrefix(pattern, `^ *`) {
		return "^" + strings.TrimPrefix(pattern, `^ *`)
	}
	return pattern
}

func startsLiteralCommandContinuation(s string) bool {
	if s == "" {
		return false
	}
	r := rune(s[0])
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-'
}

func trimRegexWhitespaceBoundary(s string) (string, bool) {
	for _, prefix := range []string{`\s+`, `\s*`, `[[:space:]]+`, `[[:space:]]*`, ` +`, ` *`} {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimPrefix(s, prefix), true
		}
	}
	return s, false
}

func broadShellMetacharPattern(pattern string) bool {
	if !strings.Contains(pattern, ".*") && !strings.Contains(pattern, ".+") {
		return false
	}
	if strings.Contains(pattern, `[^;&|`) || strings.Contains(pattern, `[^;|&`) {
		return false
	}
	return true
}

func saferPatternHint(pattern string) string {
	if cmd, ok := anchoredCommandName(pattern); ok {
		if _, supported := semanticpkg.Lookup(cmd); supported {
			return "Prefer permission.allow.command with command.name: " + cmd + " and command.semantic fields for the intended read-only operation. Move broad namespace matching to permission.ask; if a raw fallback is required, use a narrower regex anchored with ^ and $ that excludes shell metacharacters."
		}
	}
	return "Move broad namespace matching to permission.ask. If permission.allow needs a raw fallback, use a narrower regex anchored with ^ and $, include an explicit subcommand, and exclude shell metacharacters."
}

func saferPatternAlternative(pattern string) string {
	if cmd, ok := anchoredCommandName(pattern); ok {
		if _, supported := semanticpkg.Lookup(cmd); supported {
			return "command.semantic for " + cmd
		}
		return "^" + cmd + `\s+<read-only-subcommand>(\s|$)[^;&|` + "`" + `$()<>]*$`
	}
	return `^<command>\s+<read-only-subcommand>(\s|$)[^;&|` + "`" + `$()<>]*$`
}

func anchoredCommandName(pattern string) (string, bool) {
	pattern = trimLeadingRegexWhitespace(pattern)
	for _, cmd := range broadPatternCommands() {
		if strings.HasPrefix(pattern, "^"+cmd) {
			return cmd, true
		}
	}
	return "", false
}

func duplicateRuleNameWarnings(p policy.Pipeline) []VerifyDiagnostic {
	type seenRule struct {
		source policy.Source
		name   string
	}
	seen := map[string]seenRule{}
	var warnings []VerifyDiagnostic
	visit := func(rules []policy.PermissionRuleSpec) {
		for _, rule := range rules {
			name := strings.TrimSpace(rule.Name)
			if name == "" {
				continue
			}
			if first, ok := seen[name]; ok {
				warnings = append(warnings, VerifyDiagnostic{
					Kind:    "duplicate_rule_name",
					Title:   "Duplicate rule name",
					Message: "duplicate permission rule name: " + name,
					First:   sourceFromPolicy(first.source, first.name),
					Second:  sourceFromPolicy(rule.Source, rule.Name),
				})
				continue
			}
			seen[name] = seenRule{source: rule.Source, name: name}
		}
	}
	visit(p.Permission.Deny)
	visit(p.Permission.Ask)
	visit(p.Permission.Allow)
	return warnings
}

func diagnosticFromTestFailure(f doctoring.TestFailure) VerifyDiagnostic {
	d := VerifyDiagnostic{
		Kind:     "e2e_test_failed",
		Title:    "E2E test failed",
		Source:   sourceFromPolicy(f.Source, ""),
		Input:    f.Example,
		Expected: f.Expected,
		Actual:   f.Got,
		Reason:   f.Reason,
		Decisions: &VerifyDecisions{
			Policy:         nonEmpty(f.Policy, "abstain"),
			ClaudeSettings: nonEmpty(f.Claude, "abstain"),
			Final:          nonEmpty(f.Final, f.Got),
		},
	}
	if f.MatchedRule != nil {
		d.MatchedRule = sourceFromPolicy(*f.MatchedRule.Source, f.MatchedRule.Name)
		d.MatchedMessage = f.MatchedRule.Message
	}
	return d
}

func diagnosticsFromError(err error) []VerifyDiagnostic {
	var validation *policy.ValidationError
	if errors.As(err, &validation) {
		diagnostics := make([]VerifyDiagnostic, 0, len(validation.Issues))
		for _, issue := range validation.Issues {
			diagnostics = append(diagnostics, diagnosticFromIssue(issue))
		}
		return diagnostics
	}
	parts := strings.Split(err.Error(), "; ")
	diagnostics := make([]VerifyDiagnostic, 0, len(parts))
	for _, part := range parts {
		diagnostics = append(diagnostics, diagnosticFromIssue(part))
	}
	return diagnostics
}

func diagnosticFromIssue(issue string) VerifyDiagnostic {
	d := VerifyDiagnostic{Kind: "validation_error", Title: "Validation error", Message: issue}
	if src, rest, ok := splitIssueSource(issue); ok {
		d.Source = sourceFromScope(src, rest, "")
	}
	if semantic := semanticUnsupportedFieldDiagnostic(issue); semantic.Kind != "" {
		return semantic
	}
	if semantic := semanticUnsupportedTypeDiagnostic(issue); semantic.Kind != "" {
		return semantic
	}
	if semantic := semanticUnavailableDiagnostic(issue); semantic.Kind != "" {
		return semantic
	}
	return d
}

var unsupportedFieldRe = regexp.MustCompile(`^(?:(.+) )?(permission\.(deny|ask|allow)\[(\d+)\]\.command\.semantic\.([A-Za-z0-9_]+)) is not supported for command ([^\. ]+)\. Supported semantic fields for [^:]+: ([^\.]+)\.`)
var unsupportedTypeRe = regexp.MustCompile(`^(?:(.+) )?(permission\.(deny|ask|allow)\[(\d+)\]\.command\.semantic\.([A-Za-z0-9_]+)) must be ([^,]+), got ([^\.]+)\.(?: Command: ([^\.]+)\.)?`)
var semanticUnavailableRe = regexp.MustCompile(`^(?:(.+) )?(permission\.(deny|ask|allow)\[(\d+)\]\.command\.semantic) is not available for command ([^\. ]+)\.`)

func semanticUnsupportedFieldDiagnostic(issue string) VerifyDiagnostic {
	m := unsupportedFieldRe.FindStringSubmatch(issue)
	if len(m) == 0 {
		return VerifyDiagnostic{}
	}
	command := m[6]
	return VerifyDiagnostic{
		Kind:            "unsupported_semantic_field",
		Title:           "Unsupported semantic field",
		Source:          sourceFromScope(m[1], "permission."+m[3]+"["+m[4]+"]", ""),
		Message:         "unsupported semantic field",
		Command:         command,
		Field:           "command.semantic." + m[5],
		SupportedFields: semanticpkg.FieldNames(command),
		Hint:            "cc-bash-guard help semantic " + command,
	}
}

func semanticUnsupportedTypeDiagnostic(issue string) VerifyDiagnostic {
	m := unsupportedTypeRe.FindStringSubmatch(issue)
	if len(m) == 0 {
		return VerifyDiagnostic{}
	}
	command := m[8]
	if command == "" {
		command = commandFromSemanticIssue(issue)
	}
	return VerifyDiagnostic{
		Kind:            "invalid_semantic_field_type",
		Title:           "Invalid semantic field type",
		Source:          sourceFromScope(m[1], "permission."+m[3]+"["+m[4]+"]", ""),
		Message:         "invalid semantic field type",
		Command:         command,
		Field:           m[2],
		ExpectedType:    m[6],
		ActualType:      m[7],
		SupportedFields: semanticpkg.FieldNames(command),
		Hint:            "cc-bash-guard help semantic " + command,
	}
}

func semanticUnavailableDiagnostic(issue string) VerifyDiagnostic {
	m := semanticUnavailableRe.FindStringSubmatch(issue)
	if len(m) == 0 {
		return VerifyDiagnostic{}
	}
	command := m[5]
	return VerifyDiagnostic{
		Kind:    "semantic_schema_unavailable",
		Title:   "Semantic schema unavailable",
		Source:  sourceFromScope(m[1], "permission."+m[3]+"["+m[4]+"]", ""),
		Message: "semantic schema unavailable",
		Command: command,
		Field:   "command.semantic",
		Hint:    "Use patterns for commands without semantic support, or add a semantic parser.",
	}
}

func commandFromSemanticIssue(issue string) string {
	for _, command := range semanticpkg.SupportedCommands() {
		if strings.Contains(issue, " for command "+command) {
			return command
		}
	}
	return ""
}

func splitIssueSource(issue string) (string, string, bool) {
	idx := strings.Index(issue, " permission.")
	if idx < 0 {
		idx = strings.Index(issue, " test[")
	}
	if idx < 0 {
		return "", issue, false
	}
	return issue[:idx], issue[idx+1:], true
}

func sourceFromPolicy(src policy.Source, name string) *VerifySource {
	if src == (policy.Source{}) && name == "" {
		return nil
	}
	scope := src.Section
	if scope != "" && !strings.Contains(scope, "[") {
		scope += "[" + itoa(src.Index) + "]"
	}
	return sourceFromScope(src.Path, scope, name)
}

var scopeRe = regexp.MustCompile(`^(permission)\.(deny|ask|allow)\[(\d+)\]|^(test)\[(\d+)\]`)

func sourceFromScope(file string, scope string, name string) *VerifySource {
	source := &VerifySource{File: file, Name: name}
	if scope == "" {
		return source
	}
	m := scopeRe.FindStringSubmatch(scope)
	if len(m) == 0 {
		source.Section = scope
		return source
	}
	if m[1] == "permission" {
		source.Section = "permission"
		source.Bucket = m[2]
		source.Index = atoi(m[3])
		return source
	}
	source.Section = "test"
	source.Index = atoi(m[5])
	return source
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func nonEmpty(v string, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
