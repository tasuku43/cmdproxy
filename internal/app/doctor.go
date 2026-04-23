package app

import (
	"github.com/tasuku43/cc-bash-proxy/internal/adapter/claude"
	"github.com/tasuku43/cc-bash-proxy/internal/app/doctoring"
	configrepo "github.com/tasuku43/cc-bash-proxy/internal/infra/config"
)

func RunDoctor(env Env) DoctorResult {
	loaded := configrepo.LoadEffective(env.Home, env.XDGConfigHome)
	return DoctorResult{
		Report: doctoring.Run(loaded, claude.Tool, env.Cwd, env.Home),
	}
}
