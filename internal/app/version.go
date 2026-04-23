package app

import "github.com/tasuku43/cc-bash-proxy/internal/infra/buildinfo"

func RunVersion() VersionResult {
	return VersionResult{Info: buildinfo.Read()}
}
