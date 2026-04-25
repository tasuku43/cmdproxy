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
			cmd.Git = buildGitSemantic(cmd.ActionPath, cmd.Options, cmd.Args)
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

func buildGitSemantic(actionPath []string, options []Option, args []string) *GitSemantic {
	if len(actionPath) == 0 {
		return nil
	}
	semantic := &GitSemantic{
		Verb:  actionPath[0],
		Flags: normalizedGitFlags(options),
	}
	switch semantic.Verb {
	case "diff":
		if gitHasAnyOption(options, "--cached", "--staged") {
			semantic.Cached = true
			semantic.Staged = true
		}
	case "push":
		if gitHasAnyOption(options, "--force", "-f", "--force-with-lease", "--force-if-includes") {
			semantic.Force = true
		}
		positional := gitPositionalArgs(args)
		if len(positional) > 0 {
			semantic.Remote = positional[0]
		}
		if len(positional) > 1 {
			semantic.Branch = positional[1]
			semantic.Ref = positional[1]
		}
	case "reset":
		if gitHasAnyOption(options, "--hard") {
			semantic.Hard = true
		}
		positional := gitPositionalArgs(args)
		if len(positional) > 0 {
			semantic.Ref = positional[0]
		}
	case "clean":
		semantic.Force = gitHasShortFlag(options, 'f') || gitHasAnyOption(options, "--force")
		semantic.Recursive = gitHasShortFlag(options, 'd')
		semantic.IncludeIgnored = gitHasShortFlag(options, 'x') || gitHasAnyOption(options, "--ignored")
	case "checkout":
		positional := gitPositionalArgs(args)
		if len(positional) > 0 {
			semantic.Branch = positional[0]
			semantic.Ref = positional[0]
		}
	case "switch":
		positional := gitPositionalArgs(args)
		if len(positional) > 0 {
			if gitHasAnyOption(options, "-c", "-C", "--create", "--force-create") && len(positional) > 0 {
				semantic.Branch = positional[0]
			} else {
				semantic.Branch = positional[0]
			}
			semantic.Ref = semantic.Branch
		}
	}
	return semantic
}

func normalizedGitFlags(options []Option) []string {
	flags := make([]string, 0, len(options))
	for _, option := range options {
		flags = append(flags, option.Name)
		name := option.Name
		if len(name) > 2 && strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "--") {
			for _, flag := range name[1:] {
				flags = append(flags, "-"+string(flag))
			}
		}
	}
	return flags
}

func gitPositionalArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--" {
			break
		}
		out = append(out, arg)
	}
	return out
}

func gitHasAnyOption(options []Option, names ...string) bool {
	for _, option := range options {
		for _, name := range names {
			if option.Name == name {
				return true
			}
		}
	}
	return false
}

func gitHasShortFlag(options []Option, flag byte) bool {
	for _, option := range options {
		name := option.Name
		if len(name) < 2 || !strings.HasPrefix(name, "-") || strings.HasPrefix(name, "--") {
			continue
		}
		if strings.ContainsRune(name[1:], rune(flag)) {
			return true
		}
	}
	return false
}
