package command

import "strings"

type GitParser struct{}

func (GitParser) Program() string {
	return "git"
}

func (GitParser) Parse(base Command) (Command, bool) {
	if base.Program != "git" {
		return Command{}, false
	}

	cmd := base
	cmd.Parser = GitParser{}.Program()
	cmd.SemanticParser = GitParser{}.Program()
	cmd.Args = []string{}

	i := 0
	for i < len(base.RawWords) {
		word := base.RawWords[i]
		switch {
		case word == "-C":
			if i+1 >= len(base.RawWords) {
				cmd.ActionPath = append(cmd.ActionPath, base.RawWords[i:]...)
				return cmd, true
			}
			value := base.RawWords[i+1]
			cmd.GlobalOptions = append(cmd.GlobalOptions, Option{Name: "-C", Value: value, HasValue: true, Position: i})
			cmd.WorkingDirectory = value
			i += 2
		case word == "-c":
			if i+1 >= len(base.RawWords) {
				cmd.ActionPath = append(cmd.ActionPath, base.RawWords[i:]...)
				return cmd, true
			}
			cmd.GlobalOptions = append(cmd.GlobalOptions, Option{Name: "-c", Value: base.RawWords[i+1], HasValue: true, Position: i})
			i += 2
		case isGitGlobalOptionWithValue(word, "--git-dir"):
			value, consumed := gitOptionValue(word, "--git-dir", base.RawWords, i)
			if !consumed {
				cmd.ActionPath = append(cmd.ActionPath, base.RawWords[i:]...)
				return cmd, true
			}
			cmd.GlobalOptions = append(cmd.GlobalOptions, Option{Name: "--git-dir", Value: value, HasValue: true, Position: i})
			i += gitConsumedWords(word)
		case isGitGlobalOptionWithValue(word, "--work-tree"):
			value, consumed := gitOptionValue(word, "--work-tree", base.RawWords, i)
			if !consumed {
				cmd.ActionPath = append(cmd.ActionPath, base.RawWords[i:]...)
				return cmd, true
			}
			cmd.GlobalOptions = append(cmd.GlobalOptions, Option{Name: "--work-tree", Value: value, HasValue: true, Position: i})
			i += gitConsumedWords(word)
		case isGitGlobalOptionWithValue(word, "--namespace"):
			value, consumed := gitOptionValue(word, "--namespace", base.RawWords, i)
			if !consumed {
				cmd.ActionPath = append(cmd.ActionPath, base.RawWords[i:]...)
				return cmd, true
			}
			cmd.GlobalOptions = append(cmd.GlobalOptions, Option{Name: "--namespace", Value: value, HasValue: true, Position: i})
			i += gitConsumedWords(word)
		case word == "--no-pager" || word == "--bare":
			cmd.GlobalOptions = append(cmd.GlobalOptions, Option{Name: word, Position: i})
			i++
		default:
			cmd.ActionPath, cmd.Options, cmd.Args = splitGitAction(base.RawWords[i:], i)
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

func splitGitAction(words []string, startPosition int) ([]string, []Option, []string) {
	if len(words) > 0 && words[0] == "--" {
		return append([]string(nil), words...), nil, []string{}
	}

	var actionPath []string
	var options []Option
	args := []string{}
	for i, word := range words {
		if i == 0 {
			actionPath = append(actionPath, word)
			continue
		}
		if strings.HasPrefix(word, "-") && word != "-" {
			options = append(options, parseOptionWord(word, startPosition+i))
			continue
		}
		args = append(args, word)
	}
	return actionPath, options, args
}
