package cli

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/app"
	"github.com/tasuku43/cc-bash-proxy/internal/doctor"
)

func runHook(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "hook")
		return exitAllow
	}
	useRTK := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "--rtk":
		useRTK = true
	default:
		writeCommandHelp(streams.Stderr, "hook")
		return exitError
	}

	raw, err := io.ReadAll(streams.Stdin)
	if err != nil {
		return writeJSON(streams.Stdout, app.HookResult{
			Payload: map[string]any{
				"hookSpecificOutput": map[string]any{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "deny",
					"permissionDecisionReason": "cc-bash-proxy claude runtime_error: " + err.Error(),
				},
			},
		}.Payload)
	}

	result := app.RunHook(raw, useRTK, env)
	return writeJSON(streams.Stdout, result.Payload)
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

	if doctor.HasFailures(result.Report) {
		return exitError
	}
	return exitAllow
}

func runVerify(args []string, streams Streams, env Env) int {
	if wantsHelp(args) {
		writeCommandHelp(streams.Stdout, "verify")
		return exitAllow
	}
	format, rest, err := parseCommonFlags(args)
	if err != nil || len(rest) != 0 {
		writeCommandHelp(streams.Stderr, "verify")
		return exitError
	}

	result := app.RunVerify(env)
	if format == "json" {
		payload := map[string]any{
			"verified":       result.Verified,
			"tool":           result.Tool,
			"build_info":     result.BuildInfo,
			"report":         result.Report,
			"artifact_built": result.ArtifactBuilt,
			"artifact_cache": result.ArtifactCache,
		}
		if len(result.Failures) > 0 {
			payload["failures"] = result.Failures
		}
		if err := writeIndentedJSON(streams.Stdout, payload); err != nil {
			writeErr(streams.Stderr, err.Error())
			return exitError
		}
	} else {
		writeVerifyText(streams.Stdout, result)
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
	if len(args) != 0 {
		writeCommandHelp(streams.Stderr, "init")
		return exitError
	}

	result, err := app.RunInit(env)
	if err != nil {
		writeErr(streams.Stderr, err.Error())
		return exitError
	}

	if result.Created {
		writeLine(streams.Stdout, "created "+result.ConfigPath)
	} else {
		writeLine(streams.Stdout, "exists "+result.ConfigPath)
	}
	writeLine(streams.Stdout, "user config: "+result.ConfigPath)
	if result.ClaudeSettingsDetected {
		writeLine(streams.Stdout, "detected Claude Code settings: "+result.ClaudeSettingsPath)
	} else {
		writeLine(streams.Stdout, "Claude Code settings not found: "+result.ClaudeSettingsPath)
	}
	writeLine(streams.Stdout, "hook snippet:")
	writeLine(streams.Stdout, result.HookSnippet)
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

func writeJSON(w io.Writer, payload any) int {
	_ = json.NewEncoder(w).Encode(payload)
	return exitAllow
}

func writeIndentedJSON(w io.Writer, payload any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func writeDoctorCheck(w io.Writer, check doctor.Check) {
	writeLine(w, "["+strings.ToUpper(string(check.Status))+"] "+check.ID+": "+check.Message)
}
