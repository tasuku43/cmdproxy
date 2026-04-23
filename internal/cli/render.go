package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/app"
)

func writeVerifyText(w io.Writer, result app.VerifyResult) {
	fmt.Fprintf(w, "cc-bash-proxy %s\n", result.BuildInfo.Version)
	fmt.Fprintf(w, "tool: %s\n", result.Tool)
	if result.BuildInfo.VCSRevision != "" {
		fmt.Fprintf(w, "vcs.revision: %s\n", result.BuildInfo.VCSRevision)
	} else {
		fmt.Fprintln(w, "vcs.revision: <missing>")
	}
	for _, check := range result.Report.Checks {
		writeDoctorCheck(w, check)
	}
	if result.Verified {
		fmt.Fprintln(w, "verified: true")
		if result.ArtifactBuilt {
			fmt.Fprintf(w, "artifact: %s\n", strings.Join(result.ArtifactCache, ", "))
		}
		return
	}
	fmt.Fprintln(w, "verified: false")
	for _, reason := range result.Failures {
		fmt.Fprintf(w, "failure: %s\n", reason)
	}
}

func writeVersionText(w io.Writer, result app.VersionResult) {
	fmt.Fprintf(w, "cc-bash-proxy %s\n", result.Info.Version)
	fmt.Fprintf(w, "module: %s\n", result.Info.Module)
	if result.Info.GoVersion != "" {
		fmt.Fprintf(w, "go: %s\n", result.Info.GoVersion)
	}
	if result.Info.VCSRevision != "" {
		fmt.Fprintf(w, "vcs.revision: %s\n", result.Info.VCSRevision)
	}
	if result.Info.VCSTime != "" {
		fmt.Fprintf(w, "vcs.time: %s\n", result.Info.VCSTime)
	}
	if result.Info.VCSModified != "" {
		fmt.Fprintf(w, "vcs.modified: %s\n", result.Info.VCSModified)
	}
}

func writeLine(w io.Writer, line string) {
	fmt.Fprintln(w, line)
}
