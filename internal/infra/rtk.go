package infra

import (
	"bytes"
	"os/exec"
	"strings"
)

func RewriteRTK(command string) (string, bool) {
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
