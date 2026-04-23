package app

import (
	"github.com/tasuku43/cc-bash-proxy/internal/config"
	"github.com/tasuku43/cc-bash-proxy/internal/doctor"
	"github.com/tasuku43/cc-bash-proxy/internal/integration"
)

func RunDoctor(env Env) DoctorResult {
	loaded := config.LoadEffective(env.Home, env.XDGConfigHome)
	return DoctorResult{
		Report: doctor.Run(loaded, integration.ToolClaude, env.Cwd, env.Home),
	}
}
