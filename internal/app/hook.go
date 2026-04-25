package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/adapter/claude"
	"github.com/tasuku43/cc-bash-proxy/internal/adapter/hookinput"
	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
	"github.com/tasuku43/cc-bash-proxy/internal/infra"
	"github.com/tasuku43/cc-bash-proxy/internal/infra/buildinfo"
	configrepo "github.com/tasuku43/cc-bash-proxy/internal/infra/config"
)

func RunHook(raw []byte, useRTK bool, autoVerify bool, env Env) HookResult {
	req, err := hookinput.Normalize(raw)
	if err != nil {
		return HookResult{Payload: hookErrorPayload(claude.Tool, "invalid_input", err.Error())}
	}

	decision, mergeMode, err := evaluateDecision(req, env, autoVerify)
	if err != nil {
		return HookResult{Payload: hookErrorPayload(claude.Tool, "invalid_config", err.Error())}
	}
	decision = claude.ApplyPermissionBridgeWithMode(claude.Tool, decision, env.Cwd, env.Home, mergeMode)
	if useRTK && decision.Outcome != "deny" {
		decision = applyRTKRewrite(decision)
	}

	return HookResult{Payload: hookPayload(decision, req.Command)}
}

func evaluateDecision(req hookinput.ExecRequest, env Env, autoVerify bool) (policy.Decision, string, error) {
	loaded := configrepo.LoadEffectiveForHookTool(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, claude.Tool)
	if len(loaded.Errors) > 0 {
		if shouldAttemptImplicitVerify(loaded.Errors) {
			if !autoVerify {
				return policy.Decision{}, "", errors.New("verified artifact missing or stale; run cc-bash-proxy verify")
			}
			if err := ensureVerifiedArtifacts(env, claude.Tool); err == nil {
				loaded = configrepo.LoadEffectiveForHookTool(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, claude.Tool)
			}
		}
		if len(loaded.Errors) > 0 {
			return policy.Decision{}, "", errors.New(strings.Join(policy.ErrorStrings(loaded.Errors), "; "))
		}
	}

	decision, err := policy.Evaluate(loaded.Pipeline, req.Command)
	return decision, loaded.Pipeline.ClaudePermissionMergeMode, err
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

func ensureVerifiedArtifacts(env Env, tool string) error {
	info := buildinfo.Read()
	_, err := configrepo.VerifyEffectiveToAllCaches(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, tool, info.Version)
	return err
}

func hookPayload(decision policy.Decision, originalCommand string) map[string]any {
	switch decision.Outcome {
	case "allow", "ask":
		hookOutput := map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecisionReason": "cc-bash-proxy permission evaluated",
		}
		if decision.Command != originalCommand {
			hookOutput["updatedInput"] = map[string]any{"command": decision.Command}
		}
		if decision.Outcome == "allow" {
			hookOutput["permissionDecision"] = "allow"
		}
		payload := map[string]any{
			"hookSpecificOutput": hookOutput,
			"cc-bash-proxy": map[string]any{
				"outcome":  decision.Outcome,
				"explicit": decision.Explicit,
				"reason":   decision.Reason,
				"trace":    decision.Trace,
			},
		}
		if message, ok := buildRewriteSystemMessage(decision); ok {
			payload["systemMessage"] = message
		}
		return payload
	case "deny":
		reason := decision.Message
		if strings.TrimSpace(reason) == "" {
			reason = "cc-bash-proxy denied by policy"
		}
		return map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
			"cc-bash-proxy": map[string]any{
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

func hookErrorPayload(tool string, code string, message string) map[string]any {
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": "cc-bash-proxy " + tool + " " + code + ": " + message,
		},
	}
}

func applyRTKRewrite(decision policy.Decision) policy.Decision {
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
	return fmt.Sprintf("cc-bash-proxy: rewrote [%s] -> %s", strings.Join(ruleIDs, " -> "), decision.Command), true
}
