package app

import (
	"fmt"
	"strings"

	"github.com/tasuku43/cc-bash-guard/internal/adapter/claude"
	"github.com/tasuku43/cc-bash-guard/internal/adapter/hookinput"
	commandpkg "github.com/tasuku43/cc-bash-guard/internal/domain/command"
	"github.com/tasuku43/cc-bash-guard/internal/domain/invocation"
	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
	"github.com/tasuku43/cc-bash-guard/internal/infra"
)

func RunHook(raw []byte, opts HookOptions, env Env) HookResult {
	req, err := hookinput.Normalize(raw)
	if err != nil {
		return HookResult{Payload: hookErrorPayload(claude.Tool, "invalid_input", err.Error())}
	}

	if isSelfCommand(req.Command) {
		return HookResult{Payload: hookPayload(selfCommandDecision(req.Command), req)}
	}

	_, decision, err := EvaluateForCommand(req.Command, env)
	if err != nil {
		if isRecoverableArtifactDrift(err) {
			return HookResult{Payload: hookPayload(artifactDriftDecision(req.Command, err), req)}
		}
		return HookResult{Payload: hookErrorPayload(claude.Tool, "invalid_config", err.Error())}
	}
	if opts.UseRTK && decision.Outcome != "deny" {
		decision = applyRTKRewrite(decision)
	}

	return HookResult{Payload: hookPayload(decision, req)}
}

func evaluateDecision(req hookinput.ExecRequest, env Env) (policy.Decision, error) {
	_, decision, err := EvaluateForCommand(req.Command, env)
	return decision, err
}

func isSelfCommand(command string) bool {
	if invocation.Classify(command) == invocation.CommandClassUnsafeCompound {
		return false
	}
	parsed := commandpkg.NewInvocation(command)
	return parsed.Program == "cc-bash-guard"
}

func selfCommandDecision(command string) policy.Decision {
	return policy.Decision{
		Command:  command,
		Outcome:  "allow",
		Explicit: true,
		Reason:   "cc-bash-guard self command bypasses hook policy",
		Message:  "cc-bash-guard self command bypasses hook policy",
		Trace: []policy.TraceStep{{
			Action: "bypass",
			Name:   "self-command",
			Effect: "allow",
			Reason: "cc-bash-guard self command bypasses hook policy",
		}},
	}
}

func shouldAttemptImplicitVerify(errs []error) bool {
	if len(errs) == 0 {
		return false
	}
	for _, msg := range policy.ErrorStrings(errs) {
		if strings.Contains(msg, "verified artifact not found") || strings.Contains(msg, "changed since last verify") {
			return true
		}
	}
	return false
}

func isRecoverableArtifactDrift(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if strings.Contains(msg, "incompatible") || strings.Contains(msg, "evaluation semantics version") {
		return false
	}
	return strings.Contains(msg, "verified artifact missing or stale")
}

func artifactDriftDecision(command string, err error) policy.Decision {
	reason := "cc-bash-guard warning: verified artifact is missing or stale; continuing with Claude Code confirmation. Run cc-bash-guard verify."
	if err != nil {
		reason = reason + " Details: " + err.Error()
	}
	return policy.Decision{
		Command:  command,
		Outcome:  "ask",
		Explicit: true,
		Reason:   reason,
		Message:  reason,
		Trace: []policy.TraceStep{{
			Action:  "permission",
			Name:    "verified_artifact_drift",
			Effect:  "ask",
			Reason:  reason,
			Message: reason,
		}},
	}
}

func hookPayload(decision policy.Decision, req hookinput.ExecRequest) map[string]any {
	switch decision.Outcome {
	case "allow", "ask":
		hookOutput := map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecisionReason": permissionDecisionReason(decision, "cc-bash-guard permission evaluated"),
		}
		// updatedInput is reserved for hook --rtk after a non-deny decision.
		// Policy evaluation and the default hook never rewrite commands.
		if decision.Command != req.Command {
			hookOutput["updatedInput"] = updatedInput(req, decision.Command)
		}
		if decision.Outcome == "allow" {
			hookOutput["permissionDecision"] = "allow"
		} else {
			hookOutput["permissionDecision"] = "ask"
		}
		if message, ok := buildArtifactWarningSystemMessage(decision); ok {
			hookOutput["additionalContext"] = message
		}
		payload := map[string]any{
			"hookSpecificOutput": hookOutput,
			"cc-bash-guard": map[string]any{
				"outcome":  decision.Outcome,
				"explicit": decision.Explicit,
				"reason":   decision.Reason,
				"trace":    decision.Trace,
			},
		}
		if message, ok := buildRewriteSystemMessage(decision); ok {
			payload["systemMessage"] = message
		}
		if message, ok := buildArtifactWarningSystemMessage(decision); ok {
			payload["systemMessage"] = message
		}
		return payload
	case "deny":
		reason := permissionDecisionReason(decision, "cc-bash-guard denied by policy")
		return map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
			"cc-bash-guard": map[string]any{
				"outcome":  "deny",
				"explicit": decision.Explicit,
				"reason":   decision.Reason,
				"trace":    decision.Trace,
			},
		}
	default:
		return hookErrorPayload(claude.Tool, "runtime_error", "unsupported decision outcome")
	}
}

func buildArtifactWarningSystemMessage(decision policy.Decision) (string, bool) {
	for _, step := range decision.Trace {
		if step.Name != "verified_artifact_drift" {
			continue
		}
		message := strings.TrimSpace(step.Message)
		if message == "" {
			message = strings.TrimSpace(step.Reason)
		}
		if message == "" {
			message = "cc-bash-guard warning: verified artifact is missing or stale; continuing with Claude Code confirmation. Run cc-bash-guard verify."
		}
		return message, true
	}
	return "", false
}

func updatedInput(req hookinput.ExecRequest, command string) map[string]any {
	if req.OriginalToolInput == nil {
		return map[string]any{"command": command}
	}
	out := make(map[string]any, len(req.OriginalToolInput))
	for key, value := range req.OriginalToolInput {
		out[key] = value
	}
	out["command"] = command
	return out
}

func permissionDecisionReason(decision policy.Decision, fallback string) string {
	if reason := strings.TrimSpace(decision.Message); reason != "" {
		return reason
	}
	return fallback
}

func hookErrorPayload(tool string, code string, message string) map[string]any {
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": "cc-bash-guard " + tool + " " + code + ": " + message,
		},
	}
}

func applyRTKRewrite(decision policy.Decision) policy.Decision {
	// RTK integration only. RunHook calls this only after a non-deny permission
	// decision; deny must never invoke RTK. The returned command comes from the
	// external rtk binary, not cc-bash-guard policy evaluation.
	rewritten, ok := infra.RewriteRTK(decision.Command)
	if !ok || rewritten == decision.Command {
		return decision
	}
	decision.Trace = append(decision.Trace, policy.TraceStep{
		Action: "rewrite",
		Name:   "rtk",
		From:   decision.Command,
		To:     rewritten,
	})
	decision.Command = rewritten
	return decision
}

func buildRewriteSystemMessage(decision policy.Decision) (string, bool) {
	// RTK integration only. Policy evaluation and the default hook do not
	// produce rewrite trace steps or updatedInput.
	ruleIDs := make([]string, 0, len(decision.Trace))
	for _, step := range decision.Trace {
		if step.Action != "rewrite" {
			continue
		}
		ruleIDs = append(ruleIDs, step.Name)
	}
	if len(ruleIDs) == 0 {
		return "", false
	}
	return fmt.Sprintf("cc-bash-guard: rewrote [%s] -> %s", strings.Join(ruleIDs, " -> "), decision.Command), true
}
