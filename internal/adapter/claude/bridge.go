package claude

import (
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
)

const Tool = "claude"

func Supported(tool string) bool {
	switch strings.TrimSpace(tool) {
	case Tool:
		return true
	default:
		return false
	}
}

func ApplyPermissionBridge(tool string, decision policy.Decision, cwd string, home string) policy.Decision {
	switch strings.TrimSpace(tool) {
	case Tool:
		return applyPermissionBridge(decision, cwd, home)
	default:
		return decision
	}
}

func applyPermissionBridge(decision policy.Decision, cwd string, home string) policy.Decision {
	verdict := CheckCommand(decision.Command, cwd, home)
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
