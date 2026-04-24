package app

import (
	"github.com/tasuku43/cc-bash-proxy/internal/adapter/claude"
	"github.com/tasuku43/cc-bash-proxy/internal/app/doctoring"
	configrepo "github.com/tasuku43/cc-bash-proxy/internal/infra/config"
)

func RunDoctor(env Env) DoctorResult {
	inputs := configrepo.ResolveEffectiveInputs(env.Cwd, env.Home, env.XDGConfigHome, claude.Tool)
	loaded := configrepo.LoadEffectiveForTool(env.Cwd, env.Home, env.XDGConfigHome, claude.Tool)
	report := doctoring.Run(loaded, claude.Tool, env.Cwd, env.Home)
	report.Tool = claude.Tool
	report.ConfigSources = inputs.ConfigSources
	report.SettingsPaths = inputs.SettingsPaths
	report.EffectiveFingerprint = inputs.Fingerprint
	report.VerifiedArtifactExists = configrepo.VerifiedEffectiveArtifactExists(env.Cwd, env.Home, env.XDGConfigHome, env.XDGCacheHome, claude.Tool)
	return DoctorResult{
		Report: report,
	}
}
