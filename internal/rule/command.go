package rule

import (
	"path/filepath"
	"strings"
	"unicode"
)

type ParsedCommand struct {
	EnvAssignments map[string]string
	Command        string
	Subcommand     string
	Args           []string
}

func ParseCommand(command string) ParsedCommand {
	tokens := tokenizeCommand(command)
	envAssignments := map[string]string{}

	i := 0
	for i < len(tokens) && isEnvAssignment(tokens[i]) {
		name, value, _ := strings.Cut(tokens[i], "=")
		envAssignments[name] = value
		i++
	}

	commandToken, args := unwrapCommand(tokens[i:])
	parsed := ParsedCommand{
		EnvAssignments: envAssignments,
		Command:        basenameCommand(commandToken),
		Args:           args,
	}
	if len(args) > 0 {
		parsed.Subcommand = args[0]
	}
	return parsed
}

func tokenizeCommand(command string) []string {
	var tokens []string
	var current strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	flush := func() {
		if current.Len() == 0 {
			return
		}
		tokens = append(tokens, current.String())
		current.Reset()
	}

	for _, r := range command {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				current.WriteRune(r)
			}
		case inDouble:
			switch r {
			case '"':
				inDouble = false
			case '\\':
				escaped = true
			default:
				current.WriteRune(r)
			}
		default:
			switch {
			case unicode.IsSpace(r):
				flush()
			case r == '\'':
				inSingle = true
			case r == '"':
				inDouble = true
			case r == '\\':
				escaped = true
			default:
				current.WriteRune(r)
			}
		}
	}
	flush()
	return tokens
}

func unwrapCommand(tokens []string) (string, []string) {
	if len(tokens) == 0 {
		return "", nil
	}

	i := 0
	for i < len(tokens) {
		token := basenameCommand(tokens[i])
		switch token {
		case "command", "exec":
			i++
			continue
		case "env":
			i++
			for i < len(tokens) && isEnvAssignment(tokens[i]) {
				i++
			}
			continue
		default:
			return tokens[i], append([]string(nil), tokens[i+1:]...)
		}
	}
	return "", nil
}

func basenameCommand(token string) string {
	if token == "" {
		return ""
	}
	return filepath.Base(token)
}

func isEnvAssignment(token string) bool {
	name, value, ok := strings.Cut(token, "=")
	if !ok || name == "" || value == "" {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
