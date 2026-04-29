package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/tasuku43/cc-bash-guard/internal/app"
	"github.com/tasuku43/cc-bash-guard/internal/app/doctoring"
	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
)

func runHook(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "hook")
		return exitAllow
	}
	useRTK := false
	for _, arg := range args {
		switch arg {
		case "--rtk":
			useRTK = true
		case "--auto-verify":
			writeErr(streams.Stderr, "--auto-verify is no longer supported; run cc-bash-guard verify explicitly after policy or settings changes")
			return exitError
		default:
			writeCommandHelp(streams.Stderr, "hook")
			return exitError
		}
	}

	raw, err := io.ReadAll(streams.Stdin)
	if err != nil {
		return writeJSON(streams.Stdout, app.HookResult{
			Payload: map[string]any{
				"hookSpecificOutput": map[string]any{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "deny",
					"permissionDecisionReason": "cc-bash-guard claude runtime_error: " + err.Error(),
				},
			},
		}.Payload)
	}

	result := app.RunHook(raw, app.HookOptions{UseRTK: useRTK}, env)
	return writeJSON(streams.Stdout, result.Payload)
}

func runExplain(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "explain")
		return exitAllow
	}
	format := "text"
	whyNot := ""
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format":
			if i+1 >= len(args) {
				writeCommandHelp(streams.Stderr, "explain")
				return exitError
			}
			format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
		case arg == "--why-not":
			if i+1 >= len(args) {
				writeCommandHelp(streams.Stderr, "explain")
				return exitError
			}
			whyNot = args[i+1]
			i++
		case strings.HasPrefix(arg, "--why-not="):
			whyNot = strings.TrimPrefix(arg, "--why-not=")
		default:
			rest = append(rest, arg)
		}
	}
	if format != "text" && format != "json" {
		writeErr(streams.Stderr, "unknown format: "+format)
		writeCommandHelp(streams.Stderr, "explain")
		return exitError
	}
	if whyNot != "" && whyNot != "allow" && whyNot != "ask" && whyNot != "deny" {
		writeErr(streams.Stderr, "why-not must be one of allow, ask, deny")
		writeCommandHelp(streams.Stderr, "explain")
		return exitError
	}
	if len(rest) == 0 {
		writeCommandHelp(streams.Stderr, "explain")
		return exitError
	}
	command := strings.Join(rest, " ")
	if whyNot != "" {
		result, err := app.RunExplainWhyNot(command, whyNot, env)
		if format == "json" {
			if encErr := writeIndentedJSON(streams.Stdout, result); encErr != nil {
				writeErr(streams.Stderr, encErr.Error())
				return exitError
			}
		} else {
			writeExplainWhyNotText(streams.Stdout, result)
		}
		if err != nil || hasWhyNotParseError(result) {
			return exitError
		}
		return exitAllow
	}
	result, err := app.RunExplain(command, env)
	if format == "json" {
		if encErr := writeIndentedJSON(streams.Stdout, result); encErr != nil {
			writeErr(streams.Stderr, encErr.Error())
			return exitError
		}
	} else {
		writeExplainText(streams.Stdout, result)
	}
	if err != nil || app.ExplainHasParseError(result) {
		return exitError
	}
	return exitAllow
}

func runSuggest(args []string, streams Streams) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "suggest")
		return exitAllow
	}
	format := "yaml"
	var opts app.SuggestOptions
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format":
			if i+1 >= len(args) {
				writeCommandHelp(streams.Stderr, "suggest")
				return exitError
			}
			format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
		case arg == "--decision":
			if i+1 >= len(args) {
				writeCommandHelp(streams.Stderr, "suggest")
				return exitError
			}
			opts.Decision = args[i+1]
			i++
		case strings.HasPrefix(arg, "--decision="):
			opts.Decision = strings.TrimPrefix(arg, "--decision=")
		default:
			rest = append(rest, arg)
		}
	}
	if format != "yaml" && format != "json" {
		writeErr(streams.Stderr, "unknown format: "+format)
		writeCommandHelp(streams.Stderr, "suggest")
		return exitError
	}
	if len(rest) == 0 {
		writeCommandHelp(streams.Stderr, "suggest")
		return exitError
	}
	command := strings.Join(rest, " ")
	result, err := app.RunSuggest(command, opts)
	if err != nil {
		writeErr(streams.Stderr, err.Error())
		writeCommandHelp(streams.Stderr, "suggest")
		return exitError
	}
	if format == "json" {
		if err := writeIndentedJSON(streams.Stdout, result); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
		return exitAllow
	}
	writeSuggestedYAML(streams.Stdout, result.Policy)
	return exitAllow
}

func runDoctor(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "doctor")
		return exitAllow
	}
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) != 0 {
		writeCommandHelp(streams.Stderr, "doctor")
		return exitError
	}

	result := app.RunDoctor(env)
	if format == "json" {
		if err := writeIndentedJSON(streams.Stdout, result.Report); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
	} else {
		for _, check := range result.Report.Checks {
			writeDoctorCheck(streams.Stdout, check)
		}
	}

	if doctoring.HasFailures(result.Report) {
		return exitError
	}
	return exitAllow
}

func runVerify(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "verify")
		return exitAllow
	}
	format, colorMode, allFailures, rest, err := parseVerifyFlags(args)
	if err != nil || len(rest) != 0 {
		writeCommandHelp(streams.Stderr, "verify")
		return exitError
	}

	result := app.RunVerifyWithOptions(env, app.VerifyOptions{AllFailures: allFailures})
	if format == "json" {
		payload := map[string]any{
			"ok":             result.Verified,
			"tool":           result.Tool,
			"build_info":     result.BuildInfo,
			"summary":        result.Summary,
			"failures":       result.Diagnostics,
			"warnings":       result.Warnings,
			"artifact_built": result.ArtifactBuilt,
			"artifact_cache": result.ArtifactCache,
			"report":         result.Report,
		}
		if err := writeIndentedJSON(streams.Stdout, payload); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
	} else {
		writeVerifyText(streams.Stdout, result, colorFor(streams.Stdout, colorMode))
	}

	if !result.Verified {
		return exitError
	}
	return exitAllow
}

func runInit(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "init")
		return exitAllow
	}
	var opts app.InitOptions
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--list-profiles":
			if len(args) != 1 {
				writeCommandHelp(streams.Stderr, "init")
				return exitError
			}
			for _, profile := range app.InitProfiles() {
				writeLine(streams.Stdout, profile.Name+"\t"+profile.Description)
			}
			return exitAllow
		case arg == "--profile":
			if i+1 >= len(args) {
				writeCommandHelp(streams.Stderr, "init")
				return exitError
			}
			opts.Profile = args[i+1]
			i++
		case strings.HasPrefix(arg, "--profile="):
			opts.Profile = strings.TrimPrefix(arg, "--profile=")
		default:
			writeCommandHelp(streams.Stderr, "init")
			return exitError
		}
	}
	if opts.Profile == "" {
		for _, arg := range args {
			if arg == "--profile" || strings.HasPrefix(arg, "--profile=") {
				writeCommandHelp(streams.Stderr, "init")
				return exitError
			}
		}
	}

	result, err := app.RunInitWithOptions(env, opts)
	if err != nil {
		writeErr(streams.Stderr, err.Error())
		return exitError
	}

	if result.Created {
		writeLine(streams.Stdout, "created "+result.ConfigPath)
	} else {
		writeLine(streams.Stdout, "exists "+result.ConfigPath)
		if result.Profile != "" {
			writeLine(streams.Stdout, "profile not applied because the config file already exists")
		}
	}
	if result.Profile != "" && result.Created {
		writeLine(streams.Stdout, "profile: "+result.Profile)
	}
	writeLine(streams.Stdout, "user config: "+result.ConfigPath)
	if result.ClaudeSettingsDetected {
		writeLine(streams.Stdout, "detected Claude Code settings: "+result.ClaudeSettingsPath)
	} else {
		writeLine(streams.Stdout, "Claude Code settings not found: "+result.ClaudeSettingsPath)
	}
	writeLine(streams.Stdout, "hook snippet:")
	writeLine(streams.Stdout, result.HookSnippet)
	writeLine(streams.Stdout, "next: run cc-bash-guard verify")
	writeLine(streams.Stdout, "safety: cc-bash-guard is a permission layer, not a sandbox")
	writeLine(streams.Stdout, "warning: avoid broad permission.allow rules; prefer semantic allow rules and use permission.ask for broad command namespaces")
	return exitAllow
}

func runVersion(args []string, streams Streams) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "version")
		return exitAllow
	}
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) != 0 {
		writeCommandHelp(streams.Stderr, "version")
		return exitError
	}

	result := app.RunVersion()
	if format == "json" {
		if err := writeIndentedJSON(streams.Stdout, result.Info); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
		return exitAllow
	}

	writeVersionText(streams.Stdout, result)
	return exitAllow
}

func runSemanticSchema(args []string, streams Streams) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "semantic-schema")
		return exitAllow
	}
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) > 1 {
		writeCommandHelp(streams.Stderr, "semantic-schema")
		return exitError
	}
	if len(rest) == 1 {
		schema, ok := semanticpkg.Lookup(rest[0])
		if !ok {
			writeErr(streams.Stderr, "unknown semantic command "+rest[0]+". Supported commands: "+strings.Join(semanticpkg.SupportedCommands(), ", "))
			return exitError
		}
		if format == "json" {
			if err := writeIndentedJSON(streams.Stdout, schema); err != nil {
				writeErr(streams.Stderr, err.Error())
				return exitError
			}
			return exitAllow
		}
		if err := writeSemanticHelp(streams.Stdout, rest); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
		return exitAllow
	}
	if format == "json" {
		payload := map[string]any{
			"schemas":            semanticpkg.AllSchemas(),
			"schemas_by_command": semanticpkg.SchemasByCommand(),
		}
		if err := writeIndentedJSON(streams.Stdout, payload); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
		return exitAllow
	}
	if err := writeSemanticHelp(streams.Stdout, nil); err != nil {
		writeErr(streams.Stderr, err.Error())
		return exitError
	}
	return exitAllow
}

func writeJSON(w io.Writer, payload any) int {
	_ = json.NewEncoder(w).Encode(payload)
	return exitAllow
}

func writeIndentedJSON(w io.Writer, payload any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func writeDoctorCheck(w io.Writer, check doctoring.Check) {
	status := strings.ToUpper(string(check.Status))
	if status == "PASS" {
		status = "OK"
	}
	writeLine(w, "["+status+"] "+check.ID+": "+check.Message)
}

func writeExplainText(w io.Writer, result app.ExplainResult) {
	writeLine(w, "Command:")
	writeLine(w, "  "+result.Command)
	writeLine(w, "")
	writeLine(w, "Parsed:")
	writeLine(w, "  shape: "+result.Parsed.Shape)
	if len(result.Parsed.ShapeFlags) > 0 {
		writeLine(w, "  shape_flags: "+strings.Join(result.Parsed.ShapeFlags, ", "))
	}
	if len(result.Parsed.Diagnostics) > 0 {
		writeLine(w, "  diagnostics:")
		for _, diagnostic := range result.Parsed.Diagnostics {
			writeLine(w, "    - "+diagnostic)
		}
	}
	if result.Parsed.EvaluatedInner != nil {
		writeLine(w, "  evaluated inner command:")
		writeExplainSegment(w, *result.Parsed.EvaluatedInner, "    ")
		writeLine(w, "  note: evaluation-only normalization; command string is not rewritten or executed")
	} else {
		writeLine(w, "  segments:")
		for _, segment := range result.Parsed.Segments {
			writeLine(w, "    - command.name: "+segment.CommandName)
			writeExplainSegmentFields(w, segment, "      ")
		}
	}
	writeLine(w, "")
	writeLine(w, "cc-bash-guard policy:")
	writeLine(w, "  outcome: "+result.Policy.Outcome)
	writeMatchedRule(w, result.Policy.MatchedRule)
	writeLine(w, "")
	writeLine(w, "Claude settings:")
	writeLine(w, "  outcome: "+result.ClaudeSettings.Outcome)
	if result.ClaudeSettings.Matched == nil {
		writeLine(w, "  matched: none")
	} else {
		writeLine(w, fmt.Sprintf("  matched: %+v", result.ClaudeSettings.Matched))
	}
	writeLine(w, "")
	writeLine(w, "Final decision:")
	writeLine(w, "  outcome: "+result.Final.Outcome)
	writeLine(w, "  reason: "+result.Final.Reason)
}

func writeExplainWhyNotText(w io.Writer, result app.ExplainWhyNotResult) {
	writeLine(w, "Command:")
	writeLine(w, "  "+result.Command)
	writeLine(w, "")
	writeLine(w, "Why not:")
	writeLine(w, "  requested_outcome: "+result.RequestedOutcome)
	writeLine(w, "")
	writeLine(w, "Actual:")
	writeLine(w, "  policy: "+result.Actual.Policy)
	writeLine(w, "  claude_settings: "+result.Actual.ClaudeSettings)
	writeLine(w, "  final: "+result.Actual.Final)
	writeLine(w, "")
	writeLine(w, "Matched rule:")
	writeMatchedRule(w, result.MatchedRule)
	writeLine(w, "")
	writeLine(w, "Parsed:")
	writeLine(w, "  shape: "+result.Parsed.Shape)
	if len(result.Parsed.ShapeFlags) > 0 {
		writeLine(w, "  shape_flags: "+strings.Join(result.Parsed.ShapeFlags, ", "))
	}
	if len(result.Parsed.Diagnostics) > 0 {
		writeLine(w, "  diagnostics:")
		for _, diagnostic := range result.Parsed.Diagnostics {
			writeLine(w, "    - "+diagnostic)
		}
	}
	if result.Parsed.EvaluatedInner != nil {
		writeLine(w, "  evaluated inner command:")
		writeExplainSegment(w, *result.Parsed.EvaluatedInner, "    ")
	} else {
		writeLine(w, "  segments:")
		for _, segment := range result.Parsed.Segments {
			writeLine(w, "    - command.name: "+segment.CommandName)
			writeExplainSegmentFields(w, segment, "      ")
		}
	}
	writeLine(w, "")
	writeLine(w, "Reasons:")
	for _, reason := range result.Reasons {
		writeLine(w, "  - "+reason.Kind+": "+reason.Message)
	}
	if len(result.Suggestions) > 0 {
		writeLine(w, "")
		writeLine(w, "Suggestions:")
		for _, suggestion := range result.Suggestions {
			writeLine(w, "  - "+suggestion.Kind+": "+suggestion.Message)
		}
	}
}

func hasWhyNotParseError(result app.ExplainWhyNotResult) bool {
	for _, diagnostic := range result.Parsed.Diagnostics {
		if strings.TrimSpace(diagnostic) != "" {
			return true
		}
	}
	return false
}

func writeExplainSegment(w io.Writer, segment app.ExplainSegment, prefix string) {
	writeLine(w, prefix+"command.name: "+segment.CommandName)
	writeExplainSegmentFields(w, segment, prefix)
}

func writeExplainSegmentFields(w io.Writer, segment app.ExplainSegment, prefix string) {
	if segment.ProgramToken != "" {
		writeLine(w, prefix+"program_token: "+segment.ProgramToken)
	}
	writeLine(w, prefix+"parser: "+segment.Parser)
	if len(segment.Semantic) > 0 {
		writeLine(w, prefix+"semantic:")
		for _, key := range app.SortedSemanticKeys(segment.Semantic) {
			writeLine(w, fmt.Sprintf("%s  %s: %v", prefix, key, segment.Semantic[key]))
		}
	}
}

func writeMatchedRule(w io.Writer, matched *app.ExplainRuleMatch) {
	if matched == nil {
		writeLine(w, "  matched: none")
		return
	}
	writeLine(w, "  matched rule:")
	if matched.Name != "" {
		writeLine(w, "    name: "+matched.Name)
	}
	if matched.Source != "" {
		writeLine(w, "    source: "+matched.Source)
	}
	if matched.Bucket != "" {
		writeLine(w, "    bucket: "+matched.Bucket)
	}
	writeLine(w, fmt.Sprintf("    index: %d", matched.Index))
	if matched.Message != "" {
		writeLine(w, "    message: "+matched.Message)
	}
}
