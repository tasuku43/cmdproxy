package app

import (
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/buildinfo"
	"github.com/tasuku43/cc-bash-proxy/internal/config"
	"github.com/tasuku43/cc-bash-proxy/internal/doctor"
	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
	"github.com/tasuku43/cc-bash-proxy/internal/integration"
)

func RunVerify(env Env) VerifyResult {
	tool := integration.ToolClaude
	loaded := config.LoadEffectiveForTool(env.Cwd, env.Home, env.XDGConfigHome, tool)
	report := doctor.Run(loaded, tool, env.Cwd, env.Home)
	info := buildinfo.Read()
	ok, reasons := VerifyStatus(report, info, tool)
	artifactBuilt := false
	if ok {
		rules, err := config.VerifyEffectiveToAllCaches(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, tool, info.Version)
		if err != nil {
			ok = false
			reasons = append(reasons, err.Error())
		} else if len(rules.Rewrite) > 0 || !policy.IsZeroPermissionSpec(rules.Permission) || len(rules.Test) > 0 {
			artifactBuilt = true
		}
	}

	return VerifyResult{
		Tool:          tool,
		BuildInfo:     info,
		Report:        report,
		Verified:      ok,
		ArtifactBuilt: artifactBuilt,
		ArtifactCache: config.HookCacheDirs(env.Home, env.XDGCacheHome),
		Failures:      reasons,
	}
}

func VerifyStatus(report doctor.Report, info buildinfo.Info, tool string) (bool, []string) {
	var reasons []string

	for _, check := range report.Checks {
		if check.Status == doctor.StatusFail {
			reasons = append(reasons, check.ID+": "+check.Message)
			continue
		}
		if tool == integration.ToolClaude && check.ID == "install.claude-registered" && check.Status == doctor.StatusWarn && strings.Contains(check.Message, "settings found but") {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
		if tool == integration.ToolClaude && check.ID == "install.claude-hook-path" && check.Status == doctor.StatusWarn {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
		if tool == integration.ToolClaude && (check.ID == "install.claude-hook-target" || check.ID == "install.claude-hook-binary-match") && check.Status == doctor.StatusWarn {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
	}
	if info.VCSRevision == "" {
		reasons = append(reasons, "build metadata missing: prefer a binary built with embedded VCS info")
	}

	return len(reasons) == 0, reasons
}
