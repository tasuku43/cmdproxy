package directive

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/invocation"
)

func UnwrapShellDashC(command string) (string, bool) {
	parsed := invocation.Parse(command)
	if !invocation.IsShellCommand(parsed.Command) {
		return "", false
	}
	if len(parsed.Args) < 2 || parsed.Args[0] != "-c" {
		return "", false
	}
	payload := strings.TrimSpace(parsed.Args[1])
	if payload == "" || !invocation.IsSafeSingleCommand(payload) {
		return "", false
	}
	return payload, true
}

func MoveFlagToEnv(command string, flag string, env string) (string, bool) {
	if strings.TrimSpace(flag) == "" || strings.TrimSpace(env) == "" {
		return "", false
	}

	tokens := invocation.Tokens(command)
	if len(tokens) == 0 {
		return "", false
	}

	prefixEnd := 0
	for prefixEnd < len(tokens) && invocation.IsEnvAssignment(tokens[prefixEnd]) {
		prefixEnd++
	}
	if prefixEnd >= len(tokens) {
		return "", false
	}

	flagStartIndex, flagEndIndex, value, ok := findFlagValue(tokens[prefixEnd+1:], flag)
	if !ok {
		return "", false
	}

	absoluteFlagStart := prefixEnd + 1 + flagStartIndex
	absoluteFlagEnd := prefixEnd + 1 + flagEndIndex
	rewritten := make([]string, 0, len(tokens)-(absoluteFlagEnd-absoluteFlagStart+1))
	rewritten = append(rewritten, tokens[:prefixEnd]...)
	rewritten = append(rewritten, env+"="+value)
	rewritten = append(rewritten, tokens[prefixEnd:absoluteFlagStart]...)
	rewritten = append(rewritten, tokens[absoluteFlagEnd+1:]...)
	return invocation.Join(rewritten), true
}

func MoveEnvToFlag(command string, env string, flag string) (string, bool) {
	if strings.TrimSpace(env) == "" || strings.TrimSpace(flag) == "" {
		return "", false
	}

	tokens := invocation.Tokens(command)
	if len(tokens) == 0 {
		return "", false
	}

	prefixEnd := 0
	for prefixEnd < len(tokens) && invocation.IsEnvAssignment(tokens[prefixEnd]) {
		prefixEnd++
	}
	if prefixEnd >= len(tokens) {
		return "", false
	}
	if _, _, _, ok := findFlagValue(tokens[prefixEnd+1:], flag); ok {
		return "", false
	}

	envIndex := -1
	envValue := ""
	for i := 0; i < prefixEnd; i++ {
		name, value, _ := strings.Cut(tokens[i], "=")
		if name == env {
			envIndex = i
			envValue = value
			break
		}
	}
	if envIndex == -1 {
		return "", false
	}

	rewritten := make([]string, 0, len(tokens)+1)
	rewritten = append(rewritten, tokens[:envIndex]...)
	rewritten = append(rewritten, tokens[envIndex+1:prefixEnd]...)
	rewritten = append(rewritten, tokens[prefixEnd])
	rewritten = append(rewritten, flag, envValue)
	rewritten = append(rewritten, tokens[prefixEnd+1:]...)
	return invocation.Join(rewritten), true
}

func UnwrapWrapper(command string, wrappers []string) (string, bool) {
	if len(wrappers) == 0 {
		return "", false
	}
	allowed := map[string]struct{}{}
	for _, wrapper := range wrappers {
		if strings.TrimSpace(wrapper) == "" {
			return "", false
		}
		allowed[wrapper] = struct{}{}
	}

	tokens := invocation.Tokens(command)
	if len(tokens) == 0 {
		return "", false
	}

	i := 0
	changed := false
	prefixAssignments := make([]string, 0)
	for i < len(tokens) {
		switch invocation.BaseCommand(tokens[i]) {
		case "env":
			if _, ok := allowed["env"]; !ok {
				goto done
			}
			i++
			for i < len(tokens) && invocation.IsEnvAssignment(tokens[i]) {
				prefixAssignments = append(prefixAssignments, tokens[i])
				i++
			}
			if i < len(tokens) && strings.HasPrefix(tokens[i], "-") {
				return "", false
			}
			changed = true
		case "command", "exec", "nohup":
			if _, ok := allowed[invocation.BaseCommand(tokens[i])]; !ok {
				goto done
			}
			i++
			changed = true
		default:
			goto done
		}
	}

done:
	if !changed || i >= len(tokens) {
		return "", false
	}
	rewritten := make([]string, 0, len(prefixAssignments)+len(tokens[i:]))
	rewritten = append(rewritten, prefixAssignments...)
	rewritten = append(rewritten, tokens[i:]...)
	if slices.Equal(rewritten, tokens) {
		return "", false
	}
	return invocation.Join(rewritten), true
}

func StripCommandPath(command string) (string, bool) {
	tokens := invocation.Tokens(command)
	if len(tokens) == 0 {
		return "", false
	}

	prefixEnd := 0
	for prefixEnd < len(tokens) && invocation.IsEnvAssignment(tokens[prefixEnd]) {
		prefixEnd++
	}
	if prefixEnd >= len(tokens) {
		return "", false
	}

	commandToken := tokens[prefixEnd]
	if !invocation.IsAbsoluteCommand(commandToken) {
		return "", false
	}

	base := filepath.Base(commandToken)
	if strings.TrimSpace(base) == "" || base == commandToken {
		return "", false
	}
	if _, err := exec.LookPath(base); err != nil {
		return "", false
	}

	rewritten := append([]string(nil), tokens...)
	rewritten[prefixEnd] = base
	if slices.Equal(rewritten, tokens) {
		return "", false
	}
	return invocation.Join(rewritten), true
}

func findFlagValue(tokens []string, flag string) (int, int, string, bool) {
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token == flag {
			if i+1 >= len(tokens) {
				return 0, 0, "", false
			}
			return i, i + 1, tokens[i+1], true
		}
		prefix := flag + "="
		if strings.HasPrefix(token, prefix) {
			return i, i, strings.TrimPrefix(token, prefix), true
		}
	}
	return 0, 0, "", false
}
