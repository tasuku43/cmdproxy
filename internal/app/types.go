package app

import (
	"github.com/tasuku43/cc-bash-proxy/internal/buildinfo"
	"github.com/tasuku43/cc-bash-proxy/internal/doctor"
)

type Env struct {
	Cwd           string
	Home          string
	XDGConfigHome string
	XDGCacheHome  string
}

type HookResult struct {
	Payload map[string]any
}

type DoctorResult struct {
	Report doctor.Report
}

type VerifyResult struct {
	Tool          string
	BuildInfo     buildinfo.Info
	Report        doctor.Report
	Verified      bool
	ArtifactBuilt bool
	ArtifactCache []string
	Failures      []string
}

type InitResult struct {
	ConfigPath             string
	Created                bool
	ClaudeSettingsPath     string
	ClaudeSettingsDetected bool
	HookSnippet            string
}

type VersionResult struct {
	Info buildinfo.Info
}
