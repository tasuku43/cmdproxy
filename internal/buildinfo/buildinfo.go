package buildinfo

import "runtime/debug"

type Info struct {
	Version     string `json:"version"`
	Module      string `json:"module"`
	GoVersion   string `json:"go_version"`
	VCSRevision string `json:"vcs_revision,omitempty"`
	VCSTime     string `json:"vcs_time,omitempty"`
	VCSModified string `json:"vcs_modified,omitempty"`
}

func Read() Info {
	info := Info{
		Version: "dev",
		Module:  "github.com/tasuku43/cc-bash-proxy",
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		if bi.Main.Path != "" {
			info.Module = bi.Main.Path
		}
		info.GoVersion = bi.GoVersion
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.VCSRevision = s.Value
			case "vcs.time":
				info.VCSTime = s.Value
			case "vcs.modified":
				info.VCSModified = s.Value
			}
		}
	}

	return info
}
