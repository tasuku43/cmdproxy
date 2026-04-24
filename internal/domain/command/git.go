package command

import "strings"

type GitParser struct{}

func (GitParser) Program() string {
	return "git"
}

func (GitParser) Parse(inv Invocation) (Command, bool) {
	if inv.Program != "git" {
		return Command{}, false
	}

	cmd := Command{
		Raw:          inv.Raw,
		Program:      inv.Program,
		ProgramToken: inv.ProgramToken,
		Env:          inv.Env,
		Args:         append([]string(nil), inv.Words...),
		Parser:       GitParser{}.Program(),
	}

	i := 0
	for i < len(inv.Words) {
		word := inv.Words[i]
		switch {
		case word == "-C":
			if i+1 >= len(inv.Words) {
				cmd.ActionPath = append(cmd.ActionPath, inv.Words[i:]...)
				return cmd, true
			}
			value := inv.Words[i+1]
			cmd.GlobalOptions = append(cmd.GlobalOptions, "-C="+value)
			cmd.WorkingDirectory = value
			i += 2
		case word == "-c":
			if i+1 >= len(inv.Words) {
				cmd.ActionPath = append(cmd.ActionPath, inv.Words[i:]...)
				return cmd, true
			}
			cmd.GlobalOptions = append(cmd.GlobalOptions, "-c="+inv.Words[i+1])
			i += 2
		case isGitGlobalOptionWithValue(word, "--git-dir"):
			value, consumed := gitOptionValue(word, "--git-dir", inv.Words, i)
			if !consumed {
				cmd.ActionPath = append(cmd.ActionPath, inv.Words[i:]...)
				return cmd, true
			}
			cmd.GlobalOptions = append(cmd.GlobalOptions, "--git-dir="+value)
			i += gitConsumedWords(word)
		case isGitGlobalOptionWithValue(word, "--work-tree"):
			value, consumed := gitOptionValue(word, "--work-tree", inv.Words, i)
			if !consumed {
				cmd.ActionPath = append(cmd.ActionPath, inv.Words[i:]...)
				return cmd, true
			}
			cmd.GlobalOptions = append(cmd.GlobalOptions, "--work-tree="+value)
			i += gitConsumedWords(word)
		case isGitGlobalOptionWithValue(word, "--namespace"):
			value, consumed := gitOptionValue(word, "--namespace", inv.Words, i)
			if !consumed {
				cmd.ActionPath = append(cmd.ActionPath, inv.Words[i:]...)
				return cmd, true
			}
			cmd.GlobalOptions = append(cmd.GlobalOptions, "--namespace="+value)
			i += gitConsumedWords(word)
		case word == "--no-pager" || word == "--bare":
			cmd.GlobalOptions = append(cmd.GlobalOptions, word)
			i++
		default:
			cmd.ActionPath, cmd.Options = splitGitAction(inv.Words[i:])
			return cmd, true
		}
	}

	return cmd, true
}

func isGitGlobalOptionWithValue(word string, name string) bool {
	return word == name || strings.HasPrefix(word, name+"=")
}

func gitOptionValue(word string, name string, words []string, i int) (string, bool) {
	if value, ok := strings.CutPrefix(word, name+"="); ok {
		return value, true
	}
	if i+1 >= len(words) {
		return "", false
	}
	return words[i+1], true
}

func gitConsumedWords(word string) int {
	if strings.Contains(word, "=") {
		return 1
	}
	return 2
}

func splitGitAction(words []string) ([]string, []string) {
	actionPath := []string{}
	options := []string{}
	for i, word := range words {
		if i > 0 && strings.HasPrefix(word, "-") && word != "-" {
			options = append(options, word)
			continue
		}
		actionPath = append(actionPath, word)
	}
	if len(options) == 0 {
		options = nil
	}
	return actionPath, options
}
