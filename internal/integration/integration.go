package integration

import (
	"strings"

	"github.com/tasuku43/cmdproxy/internal/claude"
	"github.com/tasuku43/cmdproxy/internal/domain/policy"
)

const ToolClaude = "claude"

func Supported(tool string) bool {
	switch strings.TrimSpace(tool) {
	case ToolClaude:
		return true
	default:
		return false
	}
}

func SettingsPaths(tool string, cwd string, home string) []string {
	switch strings.TrimSpace(tool) {
	case ToolClaude:
		return claude.SettingsPaths(cwd, home)
	default:
		return nil
	}
}

func ProjectRoot(tool string, cwd string) string {
	switch strings.TrimSpace(tool) {
	case ToolClaude:
		return claude.ProjectRoot(cwd)
	default:
		return ""
	}
}

func ApplyPermissionBridge(tool string, decision policy.Decision, cwd string, home string) policy.Decision {
	switch strings.TrimSpace(tool) {
	case ToolClaude:
		return applyClaudePermissionBridge(decision, cwd, home)
	default:
		return decision
	}
}

func applyClaudePermissionBridge(decision policy.Decision, cwd string, home string) policy.Decision {
	verdict := claude.CheckCommand(decision.Command, cwd, home)
	switch verdict {
	case claude.PermissionDeny:
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
	case claude.PermissionAllow:
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
	case claude.PermissionAsk, claude.PermissionDefault:
		if decision.Outcome != "allow" && decision.Outcome != "deny" {
			decision.Trace = append(decision.Trace, policy.TraceStep{
				Action:  "permission",
				Name:    "claude_settings",
				Effect:  "ask",
				Message: "Claude settings require confirmation during migration",
			})
			decision.Outcome = "ask"
		}
	}
	return decision
}
