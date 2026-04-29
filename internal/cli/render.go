package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/tasuku43/cc-bash-guard/internal/app"
	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
)

type colorScheme struct {
	enabled bool
}

func (c colorScheme) wrap(code string, s string) string {
	if !c.enabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (c colorScheme) green(s string) string  { return c.wrap("32", s) }
func (c colorScheme) red(s string) string    { return c.wrap("31", s) }
func (c colorScheme) yellow(s string) string { return c.wrap("33", s) }
func (c colorScheme) cyan(s string) string   { return c.wrap("36", s) }
func (c colorScheme) bold(s string) string   { return c.wrap("1", s) }
func (c colorScheme) dim(s string) string    { return c.wrap("2", s) }

func colorFor(w io.Writer, mode string) colorScheme {
	switch mode {
	case "always":
		return colorScheme{enabled: os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"}
	case "never":
		return colorScheme{}
	default:
		return colorScheme{enabled: os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && isTerminal(w)}
	}
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func writeVerifyText(w io.Writer, result app.VerifyResult, color colorScheme) {
	if result.Verified {
		fmt.Fprintf(w, "%s verify\n", color.green(color.bold("PASS")))
		artifact := "verified"
		if result.ArtifactBuilt {
			artifact = "updated"
		}
		writeVerifySummary(w, result, artifact)
		writeVerifyWarnings(w, result, color)
		return
	}
	fmt.Fprintf(w, "%s verify\n", color.red(color.bold("FAIL")))
	fmt.Fprintf(w, "  failures: %s\n", color.red(fmtInt(result.Summary.Failures)))
	fmt.Fprintf(w, "  warnings: %s\n", warningCountText(color, result.Summary.Warnings))
	fmt.Fprintln(w)
	for i, failure := range result.Diagnostics {
		writeVerifyDiagnostic(w, color, "Failure", i+1, failure)
	}
	writeVerifyWarnings(w, result, color)
	fmt.Fprintln(w, color.bold("Next:"))
	fmt.Fprintln(w, "  Fix the failures above and run:")
	fmt.Fprintln(w, "    cc-bash-guard verify")
}

func writeVerifySummary(w io.Writer, result app.VerifyResult, artifactStatus string) {
	fmt.Fprintf(w, "  config files: %d\n", result.Summary.ConfigFiles)
	fmt.Fprintf(w, "  permission rules: %d\n", result.Summary.PermissionRules)
	fmt.Fprintf(w, "  tests: %d\n", result.Summary.Tests)
	fmt.Fprintf(w, "  warnings: %s\n", warningCountText(colorScheme{}, result.Summary.Warnings))
	fmt.Fprintf(w, "  artifact: %s\n", artifactStatus)
}

func writeVerifyWarnings(w io.Writer, result app.VerifyResult, color colorScheme) {
	if len(result.Warnings) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s warnings: %d\n\n", color.yellow(color.bold("WARN")), len(result.Warnings))
	for i, warning := range result.Warnings {
		writeVerifyDiagnostic(w, color, "Warning", i+1, warning)
	}
}

func warningCountText(color colorScheme, count int) string {
	if count == 0 {
		return fmtInt(count)
	}
	return color.yellow(fmtInt(count))
}

func writeVerifyDiagnostic(w io.Writer, color colorScheme, label string, index int, d app.VerifyDiagnostic) {
	title := d.Title
	if title == "" {
		title = strings.ReplaceAll(d.Kind, "_", " ")
	}
	fmt.Fprintf(w, "%s %d: %s\n", label, index, color.bold(title))
	if d.Source != nil {
		fmt.Fprintf(w, "  source: %s\n", color.cyan(formatVerifySource(*d.Source)))
	}
	if d.Input != "" {
		fmt.Fprintf(w, "  input: %s\n", d.Input)
	}
	if d.Pattern != "" {
		fmt.Fprintf(w, "  pattern: %s\n", d.Pattern)
	}
	if d.Expected != "" {
		fmt.Fprintf(w, "  expected: %s\n", decisionText(color, d.Expected))
	}
	if d.Actual != "" {
		fmt.Fprintf(w, "  actual: %s\n", decisionText(color, d.Actual))
	}
	if d.Reason != "" {
		fmt.Fprintf(w, "  reason: %s\n", d.Reason)
	}
	if d.Command != "" {
		fmt.Fprintf(w, "  command: %s\n", d.Command)
	}
	if d.Field != "" {
		fmt.Fprintf(w, "  field: %s\n", d.Field)
	}
	if d.ExpectedType != "" || d.ActualType != "" {
		fmt.Fprintf(w, "  expected: %s\n", d.ExpectedType)
		fmt.Fprintf(w, "  actual: %s\n", d.ActualType)
	}
	if d.Message != "" && d.Input == "" && d.Field == "" {
		fmt.Fprintf(w, "  message: %s\n", d.Message)
	}
	if d.Decisions != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  decisions:")
		fmt.Fprintf(w, "    cc-bash-guard: %s\n", decisionText(color, d.Decisions.Policy))
		fmt.Fprintf(w, "    Claude settings: %s\n", decisionText(color, d.Decisions.ClaudeSettings))
		fmt.Fprintf(w, "    final: %s\n", decisionText(color, d.Decisions.Final))
	}
	if d.MatchedRule != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  matched rule:")
		fmt.Fprintf(w, "    source: %s\n", color.cyan(formatVerifySource(*d.MatchedRule)))
		if d.MatchedRule.Name != "" {
			fmt.Fprintf(w, "    name: %s\n", d.MatchedRule.Name)
		}
		if d.MatchedMessage != "" {
			fmt.Fprintf(w, "    message: %s\n", d.MatchedMessage)
		}
	}
	if len(d.SupportedFields) > 0 {
		fmt.Fprintln(w)
		if d.Command != "" {
			fmt.Fprintf(w, "  Supported fields for %s:\n", d.Command)
		} else {
			fmt.Fprintln(w, "  supported fields:")
		}
		fmt.Fprintf(w, "    %s\n", strings.Join(d.SupportedFields, ", "))
	}
	if d.First != nil || d.Second != nil {
		if d.First != nil {
			fmt.Fprintf(w, "  first: %s\n", color.cyan(formatVerifySource(*d.First)))
		}
		if d.Second != nil {
			fmt.Fprintf(w, "  second: %s\n", color.cyan(formatVerifySource(*d.Second)))
		}
	}
	if d.Hint != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Hint:")
		fmt.Fprintf(w, "    %s\n", d.Hint)
	}
	if d.SaferAlternative != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Safer alternative:")
		fmt.Fprintf(w, "    %s\n", d.SaferAlternative)
	}
	fmt.Fprintln(w)
}

func decisionText(color colorScheme, decision string) string {
	switch decision {
	case "allow":
		return color.green(decision)
	case "deny":
		return color.red(decision)
	case "ask":
		return color.yellow(decision)
	default:
		return color.dim(decision)
	}
}

func formatVerifySource(src app.VerifySource) string {
	var b strings.Builder
	if src.File != "" {
		b.WriteString(src.File)
		if src.Section != "" || src.Bucket != "" {
			b.WriteByte(' ')
		}
	}
	switch {
	case src.Section == "permission" && src.Bucket != "":
		b.WriteString("permission.")
		b.WriteString(src.Bucket)
		b.WriteByte('[')
		b.WriteString(fmtInt(src.Index))
		b.WriteByte(']')
	case src.Section == "test":
		b.WriteString("test[")
		b.WriteString(fmtInt(src.Index))
		b.WriteByte(']')
	case src.Section != "":
		b.WriteString(src.Section)
	}
	if src.Name != "" {
		b.WriteString(" \"")
		b.WriteString(src.Name)
		b.WriteByte('"')
	}
	return b.String()
}

func fmtInt(v int) string {
	return fmt.Sprintf("%d", v)
}

func writeVersionText(w io.Writer, result app.VersionResult) {
	fmt.Fprintf(w, "cc-bash-guard %s\n", result.Info.Version)
	fmt.Fprintf(w, "module: %s\n", result.Info.Module)
	if result.Info.GoVersion != "" {
		fmt.Fprintf(w, "go: %s\n", result.Info.GoVersion)
	}
	if result.Info.VCSRevision != "" {
		fmt.Fprintf(w, "vcs.revision: %s\n", result.Info.VCSRevision)
	}
	if result.Info.VCSTime != "" {
		fmt.Fprintf(w, "vcs.time: %s\n", result.Info.VCSTime)
	}
	if result.Info.BuildDate != "" {
		fmt.Fprintf(w, "build.date: %s\n", result.Info.BuildDate)
	}
	if result.Info.VCSModified != "" {
		fmt.Fprintf(w, "vcs.modified: %s\n", result.Info.VCSModified)
	}
}

func writeSuggestedYAML(w io.Writer, spec app.SuggestedPolicySpec) {
	writeLine(w, "permission:")
	switch {
	case len(spec.Permission.Deny) > 0:
		writeSuggestedRules(w, "deny", spec.Permission.Deny)
	case len(spec.Permission.Ask) > 0:
		writeSuggestedRules(w, "ask", spec.Permission.Ask)
	case len(spec.Permission.Allow) > 0:
		writeSuggestedRules(w, "allow", spec.Permission.Allow)
	}
}

func writeSuggestedRules(w io.Writer, bucket string, rules []policy.PermissionRuleSpec) {
	writeLine(w, "  "+bucket+":")
	for _, rule := range rules {
		writeLine(w, "    - name: "+yamlScalar(rule.Name))
		if !policy.IsZeroPermissionCommandSpec(rule.Command) {
			writeLine(w, "      command:")
			writeLine(w, "        name: "+yamlScalar(rule.Command.Name))
			if rule.Command.Semantic != nil {
				writeLine(w, "        semantic:")
				for _, field := range suggestedSemanticFields(*rule.Command.Semantic) {
					writeLine(w, "          "+field.key+": "+field.value)
				}
			}
		}
		if len(rule.Patterns) > 0 {
			writeLine(w, "      patterns:")
			for _, pattern := range rule.Patterns {
				writeLine(w, "        - "+yamlScalar(pattern))
			}
		}
		if rule.Message != "" {
			writeLine(w, "      message: "+yamlScalar(rule.Message))
		}
		writeSuggestedRuleTests(w, rule.Test)
	}
}

type suggestedField struct {
	key   string
	value string
}

func suggestedSemanticFields(semantic policy.SemanticMatchSpec) []suggestedField {
	var fields []suggestedField
	addSuggestedString := func(key, value string) {
		if strings.TrimSpace(value) != "" {
			fields = append(fields, suggestedField{key: key, value: yamlScalar(value)})
		}
	}
	addSuggestedBool := func(key string, value *bool) {
		if value != nil {
			fields = append(fields, suggestedField{key: key, value: fmt.Sprintf("%t", *value)})
		}
	}
	addSuggestedString("verb", semantic.Verb)
	addSuggestedString("service", semantic.Service)
	addSuggestedString("operation", semantic.Operation)
	addSuggestedString("resource_type", semantic.ResourceType)
	addSuggestedString("resource_name", semantic.ResourceName)
	addSuggestedString("namespace", semantic.Namespace)
	addSuggestedString("area", semantic.Area)
	addSuggestedString("environment", semantic.Environment)
	addSuggestedString("kube_context", semantic.KubeContext)
	addSuggestedString("app_name", semantic.AppName)
	addSuggestedString("project", semantic.Project)
	addSuggestedString("subcommand", semantic.Subcommand)
	addSuggestedString("workspace_subcommand", semantic.WorkspaceSubcommand)
	addSuggestedString("state_subcommand", semantic.StateSubcommand)
	addSuggestedString("method", semantic.Method)
	addSuggestedString("container", semantic.Container)
	addSuggestedString("image", semantic.Image)
	addSuggestedBool("force", semantic.Force)
	addSuggestedBool("force_with_lease", semantic.ForceWithLease)
	addSuggestedBool("force_if_includes", semantic.ForceIfIncludes)
	addSuggestedBool("hard", semantic.Hard)
	addSuggestedBool("recursive", semantic.Recursive)
	addSuggestedBool("include_ignored", semantic.IncludeIgnored)
	addSuggestedBool("admin", semantic.Admin)
	addSuggestedBool("interactive", semantic.Interactive)
	addSuggestedBool("read_only", semantic.ReadOnly)
	addSuggestedBool("mutating", semantic.Mutating)
	addSuggestedBool("destructive", semantic.Destructive)
	addSuggestedBool("privileged", semantic.Privileged)
	addSuggestedBool("destroy", semantic.Destroy)
	addSuggestedBool("auto_approve", semantic.AutoApprove)
	sort.SliceStable(fields, func(i, j int) bool {
		return suggestedFieldOrder(fields[i].key) < suggestedFieldOrder(fields[j].key)
	})
	return fields
}

func suggestedFieldOrder(key string) int {
	order := map[string]int{
		"verb": 0, "service": 1, "operation": 2, "area": 3, "resource_type": 4, "resource_name": 5,
		"namespace": 6, "environment": 7, "kube_context": 8, "app_name": 9, "project": 10,
		"subcommand": 11, "workspace_subcommand": 12, "state_subcommand": 13, "method": 14, "container": 15, "image": 16,
		"force": 20, "force_with_lease": 21, "force_if_includes": 22, "hard": 23, "recursive": 24,
		"include_ignored": 25, "admin": 26, "interactive": 27, "read_only": 28, "mutating": 29, "destructive": 30,
		"privileged": 31, "destroy": 32, "auto_approve": 33,
	}
	if v, ok := order[key]; ok {
		return v
	}
	return 100
}

func writeSuggestedRuleTests(w io.Writer, test policy.PermissionTestSpec) {
	writeLine(w, "      test:")
	writeSuggestedTestBucket(w, "allow", test.Allow)
	writeSuggestedTestBucket(w, "ask", test.Ask)
	writeSuggestedTestBucket(w, "deny", test.Deny)
	writeSuggestedTestBucket(w, "abstain", test.Abstain)
}

func writeSuggestedTestBucket(w io.Writer, bucket string, commands []string) {
	if len(commands) == 0 {
		return
	}
	writeLine(w, "        "+bucket+":")
	for _, command := range commands {
		writeLine(w, "          - "+yamlScalar(command))
	}
}

func yamlScalar(s string) string {
	if s == "" {
		return "''"
	}
	if isPlainYAMLScalar(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func isPlainYAMLScalar(s string) bool {
	for _, r := range s {
		if !(r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '@' || r == '=' || r == '+' || r == ',' || r == ' ' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return strings.TrimSpace(s) == s && !strings.Contains(s, ": ")
}

func writeLine(w io.Writer, line string) {
	fmt.Fprintln(w, line)
}
