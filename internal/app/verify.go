package app

import (
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/adapter/claude"
	"github.com/tasuku43/cc-bash-proxy/internal/app/doctoring"
	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
	"github.com/tasuku43/cc-bash-proxy/internal/infra/buildinfo"
	configrepo "github.com/tasuku43/cc-bash-proxy/internal/infra/config"
)

func RunVerify(env Env) VerifyResult {
	tool := claude.Tool
	loaded := configrepo.LoadEffectiveForTool(env.Cwd, env.Home, env.XDGConfigHome, tool)
	report := doctoring.Run(loaded, tool, env.Cwd, env.Home)
	info := buildinfo.Read()
	ok, reasons := VerifyStatus(report, info, tool)
	artifactBuilt := false
	if ok {
		rules, err := configrepo.VerifyEffectiveToAllCaches(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, tool, info.Version)
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
		ArtifactCache: configrepo.HookCacheDirs(env.Home, env.XDGCacheHome),
		Failures:      reasons,
	}
}

func VerifyStatus(report doctoring.Report, info buildinfo.Info, tool string) (bool, []string) {
	var reasons []string

	for _, check := range report.Checks {
		if check.Status == doctoring.StatusFail {
			reasons = append(reasons, check.ID+": "+check.Message)
			continue
		}
		if tool == claude.Tool && check.ID == "install.claude-registered" && check.Status == doctoring.StatusWarn && strings.Contains(check.Message, "settings found but") {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
		if tool == claude.Tool && check.ID == "install.claude-hook-path" && check.Status == doctoring.StatusWarn {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
		if tool == claude.Tool && (check.ID == "install.claude-hook-target" || check.ID == "install.claude-hook-binary-match") && check.Status == doctoring.StatusWarn {
			reasons = append(reasons, check.ID+": "+check.Message)
		}
	}
	if info.VCSRevision == "" {
		reasons = append(reasons, "build metadata missing: prefer a binary built with embedded VCS info")
	}

	return len(reasons) == 0, reasons
}
