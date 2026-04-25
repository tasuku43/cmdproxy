package claude

import (
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
)

const Tool = "claude"

const (
	MergeModeMigrationCompat          = "migration_compat"
	MergeModeStrict                   = "strict"
	MergeModeCCBashProxyAuthoritative = "cc_bash_proxy_authoritative"
)

func Supported(tool string) bool {
	switch strings.TrimSpace(tool) {
	case Tool:
		return true
	default:
		return false
	}
}

func ApplyPermissionBridge(tool string, decision policy.Decision, cwd string, home string) policy.Decision {
	return ApplyPermissionBridgeWithMode(tool, decision, cwd, home, "")
}

func ApplyPermissionBridgeWithMode(tool string, decision policy.Decision, cwd string, home string, mode string) policy.Decision {
	switch strings.TrimSpace(tool) {
	case Tool:
		return applyPermissionBridge(decision, cwd, home, mode)
	default:
		return decision
	}
}

func applyPermissionBridge(decision policy.Decision, cwd string, home string, mode string) policy.Decision {
	verdict := CheckCommand(decision.Command, cwd, home)
	mergeMode := normalizeMergeMode(mode)
	decision.Trace = append(decision.Trace, policy.TraceStep{
		Action:  "permission",
		Name:    "claude_permission_merge_mode",
		Effect:  mergeMode,
		Message: "Claude permission merge mode: " + mergeMode,
	})
	switch mergeMode {
	case MergeModeStrict:
		return applyStrictPermissionBridge(decision, verdict)
	case MergeModeCCBashProxyAuthoritative:
		return applyAuthoritativePermissionBridge(decision, verdict)
	case MergeModeMigrationCompat:
		return applyMigrationCompatPermissionBridge(decision, verdict)
	default:
		return applyStrictPermissionBridge(decision, verdict)
	}
}

func normalizeMergeMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case MergeModeMigrationCompat:
		return MergeModeMigrationCompat
	case MergeModeStrict:
		return MergeModeStrict
	case MergeModeCCBashProxyAuthoritative:
		return MergeModeCCBashProxyAuthoritative
	default:
		return MergeModeStrict
	}
}

func applyMigrationCompatPermissionBridge(decision policy.Decision, verdict PermissionVerdict) policy.Decision {
	switch verdict {
	case PermissionDeny:
		decision.Trace = append(decision.Trace, policy.TraceStep{
			Action:  "permission",
			Name:    "claude_settings",
			Effect:  "deny",
			Message: "Claude settings deny matched during migration",
		})
		if strings.TrimSpace(decision.Message) == "" {
			decision.Message = "blocked by Claude settings migration rule"
		}
		decision.Outcome = "deny"
	case PermissionAllow:
		if decision.Outcome == "deny" {
			return decision
		}
		decision.Trace = append(decision.Trace, policy.TraceStep{
			Action:  "permission",
			Name:    "claude_settings",
			Effect:  "allow",
			Message: "Claude settings allow matched during migration",
		})
		decision.Outcome = "allow"
	case PermissionAsk:
		if decision.Outcome == "deny" {
			return decision
		}
		decision.Trace = append(decision.Trace, policy.TraceStep{
			Action:  "permission",
			Name:    "claude_settings",
			Effect:  "ask",
			Message: "Claude settings explicitly require confirmation during migration",
		})
		decision.Outcome = "ask"
	case PermissionDefault:
		decision.Trace = append(decision.Trace, policy.TraceStep{
			Action:  "permission",
			Name:    "claude_settings",
			Effect:  "abstain",
			Message: "Claude settings did not define a matching permission during migration",
		})
		if decision.Outcome == "" {
			decision.Trace = append(decision.Trace, policy.TraceStep{
				Action:  "permission",
				Name:    "default",
				Effect:  "ask",
				Message: "no explicit permission source matched; falling back to ask",
			})
			decision.Outcome = "ask"
		}
	}
	return decision
}

func applyStrictPermissionBridge(decision policy.Decision, verdict PermissionVerdict) policy.Decision {
	switch verdict {
	case PermissionDeny:
		return applyClaudeDeny(decision, "Claude settings deny matched in strict merge mode")
	case PermissionAsk:
		if decision.Outcome == "deny" {
			return decision
		}
		return applyClaudeAsk(decision, "Claude settings explicitly require confirmation in strict merge mode")
	case PermissionAllow:
		if decision.Outcome == "deny" || decision.Outcome == "ask" {
			decision.Trace = append(decision.Trace, policy.TraceStep{
				Action:  "permission",
				Name:    "claude_settings",
				Effect:  "allow",
				Message: "Claude settings allow ignored by strict merge mode",
			})
			return decision
		}
		return applyClaudeAllow(decision, "Claude settings allow matched in strict merge mode")
	case PermissionDefault:
		return applyClaudeDefault(decision, "Claude settings did not define a matching permission in strict merge mode")
	default:
		return decision
	}
}

func applyAuthoritativePermissionBridge(decision policy.Decision, verdict PermissionVerdict) policy.Decision {
	switch verdict {
	case PermissionDeny:
		return applyClaudeDeny(decision, "Claude settings deny matched in cc_bash_proxy_authoritative merge mode")
	case PermissionAsk, PermissionAllow:
		decision.Trace = append(decision.Trace, policy.TraceStep{
			Action:  "permission",
			Name:    "claude_settings",
			Effect:  string(verdict),
			Message: "Claude settings allow/ask ignored in cc_bash_proxy_authoritative merge mode",
		})
		return decision
	case PermissionDefault:
		return applyClaudeDefault(decision, "Claude settings did not define a matching permission in cc_bash_proxy_authoritative merge mode")
	default:
		return decision
	}
}

func applyClaudeDeny(decision policy.Decision, message string) policy.Decision {
	decision.Trace = append(decision.Trace, policy.TraceStep{
		Action:  "permission",
		Name:    "claude_settings",
		Effect:  "deny",
		Message: message,
	})
	if strings.TrimSpace(decision.Message) == "" {
		decision.Message = "blocked by Claude settings"
	}
	decision.Outcome = "deny"
	return decision
}

func applyClaudeAsk(decision policy.Decision, message string) policy.Decision {
	decision.Trace = append(decision.Trace, policy.TraceStep{
		Action:  "permission",
		Name:    "claude_settings",
		Effect:  "ask",
		Message: message,
	})
	decision.Outcome = "ask"
	return decision
}

func applyClaudeAllow(decision policy.Decision, message string) policy.Decision {
	decision.Trace = append(decision.Trace, policy.TraceStep{
		Action:  "permission",
		Name:    "claude_settings",
		Effect:  "allow",
		Message: message,
	})
	decision.Outcome = "allow"
	return decision
}

func applyClaudeDefault(decision policy.Decision, message string) policy.Decision {
	decision.Trace = append(decision.Trace, policy.TraceStep{
		Action:  "permission",
		Name:    "claude_settings",
		Effect:  "abstain",
		Message: message,
	})
	if decision.Outcome == "" {
		decision.Trace = append(decision.Trace, policy.TraceStep{
			Action:  "permission",
			Name:    "default",
			Effect:  "ask",
			Message: "no explicit permission source matched; falling back to ask",
		})
		decision.Outcome = "ask"
	}
	return decision
}
