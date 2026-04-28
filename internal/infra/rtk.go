package infra

import (
	"bytes"
	"os/exec"
	"strings"
)

func RewriteRTK(command string) (string, bool) {
	// RTK integration only. The hook calls this after permission evaluation and
	// never for deny; the rewrite result belongs to external RTK, not
	// cc-bash-guard policy evaluation.
	cmd := exec.Command("rtk", "rewrite", command)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	rewritten := strings.TrimSpace(string(out))
	if rewritten == "" || rewritten == command {
		return "", false
	}
	return rewritten, true
}
