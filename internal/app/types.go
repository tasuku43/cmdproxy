package app

import (
	"github.com/tasuku43/cc-bash-guard/internal/app/doctoring"
	"github.com/tasuku43/cc-bash-guard/internal/infra/buildinfo"
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

type HookOptions struct {
	AutoVerify bool
	// UseRTK optionally delegates to external RTK after a non-deny permission
	// decision. It is the only path that may emit updatedInput, and it is a
	// bridge to RTK rather than cc-bash-guard policy rewriting.
	UseRTK bool
}

type DoctorResult struct {
	Report doctoring.Report
}

type VerifyResult struct {
	Tool            string
	BuildInfo       buildinfo.Info
	Report          doctoring.Report
	Verified        bool
	ArtifactBuilt   bool
	ArtifactCache   []string
	PermissionRules int
	Tests           int
	ConfigFiles     int
	Failures        []string
	Diagnostics     []VerifyDiagnostic
	Warnings        []VerifyDiagnostic
	Summary         VerifySummary
}

type VerifySummary struct {
	ConfigFiles     int `json:"config_files"`
	PermissionRules int `json:"permission_rules"`
	Tests           int `json:"tests"`
	Failures        int `json:"failures"`
	Warnings        int `json:"warnings"`
}

type VerifySource struct {
	File    string `json:"file,omitempty"`
	Section string `json:"section,omitempty"`
	Bucket  string `json:"bucket,omitempty"`
	Index   int    `json:"index,omitempty"`
	Name    string `json:"name,omitempty"`
}

type VerifyDecisions struct {
	Policy         string `json:"policy,omitempty"`
	ClaudeSettings string `json:"claude_settings,omitempty"`
	Final          string `json:"final,omitempty"`
}

type VerifyDiagnostic struct {
	Kind             string           `json:"kind"`
	Title            string           `json:"title,omitempty"`
	Source           *VerifySource    `json:"source,omitempty"`
	Message          string           `json:"message,omitempty"`
	Input            string           `json:"input,omitempty"`
	Pattern          string           `json:"pattern,omitempty"`
	Expected         string           `json:"expected,omitempty"`
	Actual           string           `json:"actual,omitempty"`
	Reason           string           `json:"reason,omitempty"`
	Decisions        *VerifyDecisions `json:"decisions,omitempty"`
	MatchedRule      *VerifySource    `json:"matched_rule,omitempty"`
	MatchedMessage   string           `json:"matched_message,omitempty"`
	Command          string           `json:"command,omitempty"`
	Field            string           `json:"field,omitempty"`
	ExpectedType     string           `json:"expected_type,omitempty"`
	ActualType       string           `json:"actual_type,omitempty"`
	SupportedFields  []string         `json:"supported_fields,omitempty"`
	Hint             string           `json:"hint,omitempty"`
	SaferAlternative string           `json:"safer_alternative,omitempty"`
	First            *VerifySource    `json:"first,omitempty"`
	Second           *VerifySource    `json:"second,omitempty"`
}

type VerifyOptions struct {
	AllFailures bool
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
