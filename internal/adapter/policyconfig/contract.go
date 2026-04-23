package policyconfig

import (
	"fmt"
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/policy"
)

type Contract interface {
	Name() string
	Command() string
}

type Registry interface {
	Lookup(command string) (Contract, bool)
}

type FlagToEnvValidator interface {
	ValidateFlagToEnv(spec policy.MoveFlagToEnvSpec, strict bool) error
}

type EnvToFlagValidator interface {
	ValidateEnvToFlag(spec policy.MoveEnvToFlagSpec, strict bool) error
}

type UnwrapWrapperValidator interface {
	ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error
}

type UnwrapShellValidator interface {
	ValidateUnwrapShell() error
}

type mapRegistry struct {
	contracts map[string]Contract
}

func DefaultRegistry() Registry {
	return mapRegistry{
		contracts: map[string]Contract{
			"aws":       awsContract{},
			"git":       gitContract{},
			"gh":        ghContract{},
			"docker":    dockerContract{},
			"kubectl":   kubectlContract{},
			"npm":       npmContract{name: "npm"},
			"pnpm":      npmContract{name: "pnpm"},
			"yarn":      npmContract{name: "yarn"},
			"terraform": terraformContract{},
			"go":        goContract{},
			"shell":     shellContract{},
			"wrapper":   wrapperContract{},
		},
	}
}

func (r mapRegistry) Lookup(command string) (Contract, bool) {
	ctr, ok := r.contracts[strings.TrimSpace(command)]
	return ctr, ok
}

func ValidateRewrites(steps []policy.RewriteStepSpec) []string {
	var issues []string
	reg := DefaultRegistry()
	for i, step := range steps {
		prefix := fmt.Sprintf("rewrite[%d]", i)
		issues = append(issues, validateRewriteStep(prefix, step, reg)...)
	}
	return issues
}

func validateRewriteStep(prefix string, step policy.RewriteStepSpec, reg Registry) []string {
	if policy.IsZeroUnwrapWrapperSpec(step.UnwrapWrapper) &&
		policy.IsZeroMoveFlagToEnvSpec(step.MoveFlagToEnv) &&
		policy.IsZeroMoveEnvToFlagSpec(step.MoveEnvToFlag) &&
		!step.UnwrapShellDashC &&
		!step.StripCommandPath {
		return nil
	}
	if step.StripCommandPath {
		return nil
	}

	command := strings.TrimSpace(step.Match.Command)
	if command == "" {
		switch {
		case step.UnwrapShellDashC:
			command = "shell"
		case !policy.IsZeroUnwrapWrapperSpec(step.UnwrapWrapper):
			command = "wrapper"
		}
	}

	if command == "" {
		return []string{prefix + " requires match.command for contract-validated rewrite primitives"}
	}

	ctr, ok := reg.Lookup(command)
	if !ok {
		return []string{fmt.Sprintf("%s.match.command %q is not supported by built-in rewrite contracts", prefix, command)}
	}
	return validateRewrite(prefix, ctr, step)
}

func validateRewrite(prefix string, ctr Contract, rewrite policy.RewriteStepSpec) []string {
	var issues []string
	strict := policy.RewriteStrict(rewrite)
	switch {
	case rewrite.UnwrapShellDashC:
		v, ok := ctr.(UnwrapShellValidator)
		if !ok {
			return []string{fmt.Sprintf("%s is not supported for command %q", "unwrap_shell_dash_c", ctr.Command())}
		}
		if err := v.ValidateUnwrapShell(); err != nil {
			issues = append(issues, prefix+".unwrap_shell_dash_c "+err.Error())
		}
	case !policy.IsZeroUnwrapWrapperSpec(rewrite.UnwrapWrapper):
		v, ok := ctr.(UnwrapWrapperValidator)
		if !ok {
			return []string{fmt.Sprintf("%s is not supported for command %q", "unwrap_wrapper", ctr.Command())}
		}
		if err := v.ValidateUnwrapWrapper(rewrite.UnwrapWrapper); err != nil {
			issues = append(issues, prefix+".unwrap_wrapper "+err.Error())
		}
	case !policy.IsZeroMoveFlagToEnvSpec(rewrite.MoveFlagToEnv):
		v, ok := ctr.(FlagToEnvValidator)
		if !ok {
			return []string{fmt.Sprintf("%s is not supported for command %q", "move_flag_to_env", ctr.Command())}
		}
		if err := v.ValidateFlagToEnv(rewrite.MoveFlagToEnv, strict); err != nil {
			issues = append(issues, prefix+".move_flag_to_env "+err.Error())
		}
	case !policy.IsZeroMoveEnvToFlagSpec(rewrite.MoveEnvToFlag):
		v, ok := ctr.(EnvToFlagValidator)
		if !ok {
			return []string{fmt.Sprintf("%s is not supported for command %q", "move_env_to_flag", ctr.Command())}
		}
		if err := v.ValidateEnvToFlag(rewrite.MoveEnvToFlag, strict); err != nil {
			issues = append(issues, prefix+".move_env_to_flag "+err.Error())
		}
	}
	return issues
}

type awsContract struct{}

func (awsContract) Name() string    { return "aws" }
func (awsContract) Command() string { return "aws" }

func (awsContract) ValidateFlagToEnv(spec policy.MoveFlagToEnvSpec, strict bool) error {
	if spec.Flag == "--profile" && spec.Env == "AWS_PROFILE" {
		return nil
	}
	if spec.Flag == "--region" && spec.Env == "AWS_DEFAULT_REGION" {
		return nil
	}
	return fmt.Errorf("only --profile <-> AWS_PROFILE and --region <-> AWS_DEFAULT_REGION are supported")
}

func (awsContract) ValidateEnvToFlag(spec policy.MoveEnvToFlagSpec, strict bool) error {
	if spec.Env == "AWS_PROFILE" && spec.Flag == "--profile" {
		return nil
	}
	if spec.Env == "AWS_DEFAULT_REGION" && spec.Flag == "--region" {
		return nil
	}
	return fmt.Errorf("only AWS_PROFILE <-> --profile and AWS_DEFAULT_REGION <-> --region are supported")
}

func (awsContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func (awsContract) ValidateUnwrapShell() error { return nil }

type gitContract struct{}

func (gitContract) Name() string    { return "git" }
func (gitContract) Command() string { return "git" }

func (gitContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func (gitContract) ValidateUnwrapShell() error { return nil }

type ghContract struct{}

func (ghContract) Name() string    { return "gh" }
func (ghContract) Command() string { return "gh" }

func (ghContract) ValidateFlagToEnv(spec policy.MoveFlagToEnvSpec, strict bool) error {
	if spec.Flag == "--repo" && spec.Env == "GH_REPO" {
		return nil
	}
	return fmt.Errorf("only --repo <-> GH_REPO is supported")
}

func (ghContract) ValidateEnvToFlag(spec policy.MoveEnvToFlagSpec, strict bool) error {
	if spec.Env == "GH_REPO" && spec.Flag == "--repo" {
		return nil
	}
	return fmt.Errorf("only GH_REPO <-> --repo is supported")
}

func (ghContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func (ghContract) ValidateUnwrapShell() error { return nil }

type dockerContract struct{}

func (dockerContract) Name() string    { return "docker" }
func (dockerContract) Command() string { return "docker" }

func (dockerContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func (dockerContract) ValidateUnwrapShell() error { return nil }

type kubectlContract struct{}

func (kubectlContract) Name() string    { return "kubectl" }
func (kubectlContract) Command() string { return "kubectl" }

func (kubectlContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func (kubectlContract) ValidateUnwrapShell() error { return nil }

func (kubectlContract) ValidateFlagToEnv(spec policy.MoveFlagToEnvSpec, strict bool) error {
	if !strict && spec.Flag == "--kubeconfig" && spec.Env == "KUBECONFIG" {
		return nil
	}
	if strict {
		return fmt.Errorf("no strict flag-to-env mappings are supported")
	}
	return fmt.Errorf("only relaxed --kubeconfig <-> KUBECONFIG is supported")
}

func (kubectlContract) ValidateEnvToFlag(spec policy.MoveEnvToFlagSpec, strict bool) error {
	if !strict && spec.Env == "KUBECONFIG" && spec.Flag == "--kubeconfig" {
		return nil
	}
	if strict {
		return fmt.Errorf("no strict env-to-flag mappings are supported")
	}
	return fmt.Errorf("only relaxed KUBECONFIG <-> --kubeconfig is supported")
}

type npmContract struct {
	name string
}

func (c npmContract) Name() string    { return c.name }
func (c npmContract) Command() string { return c.name }

func (c npmContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func (c npmContract) ValidateUnwrapShell() error { return nil }

type terraformContract struct{}

func (terraformContract) Name() string    { return "terraform" }
func (terraformContract) Command() string { return "terraform" }

func (terraformContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func (terraformContract) ValidateUnwrapShell() error { return nil }

type goContract struct{}

func (goContract) Name() string    { return "go" }
func (goContract) Command() string { return "go" }

func (goContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func (goContract) ValidateUnwrapShell() error { return nil }

type shellContract struct{}

func (shellContract) Name() string               { return "shell" }
func (shellContract) Command() string            { return "shell" }
func (shellContract) ValidateUnwrapShell() error { return nil }

type wrapperContract struct{}

func (wrapperContract) Name() string    { return "wrapper" }
func (wrapperContract) Command() string { return "wrapper" }
func (wrapperContract) ValidateUnwrapWrapper(spec policy.UnwrapWrapperSpec) error {
	return validateAllowedWrappers(spec.Wrappers)
}

func validateAllowedWrappers(wrappers []string) error {
	allowed := map[string]struct{}{
		"env":     {},
		"command": {},
		"exec":    {},
		"nohup":   {},
	}
	if len(wrappers) == 0 {
		return fmt.Errorf("must declare at least one wrapper")
	}
	for _, wrapper := range wrappers {
		if _, ok := allowed[wrapper]; !ok {
			return fmt.Errorf("wrapper %q is not supported by built-in contracts", wrapper)
		}
	}
	return nil
}
