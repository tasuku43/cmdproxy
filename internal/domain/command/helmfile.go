package command

import "strings"

type HelmfileParser struct{}

func (HelmfileParser) Program() string {
	return "helmfile"
}

func (HelmfileParser) Parse(base Command) (Command, bool) {
	if base.Program != "helmfile" {
		return Command{}, false
	}

	cmd := base
	cmd.Parser = HelmfileParser{}.Program()
	cmd.SemanticParser = HelmfileParser{}.Program()
	cmd.Args = []string{}

	semantic := &HelmfileSemantic{}
	if value := base.Env["HELMFILE_ENVIRONMENT"]; value != "" {
		semantic.Environment = value
	}
	var positionals []string

	for i := 0; i < len(base.RawWords); i++ {
		word := base.RawWords[i]
		switch {
		case helmfileOptionWithValue(word, "-e", "--environment"):
			value, consumed := helmfileOptionValue(word, "--environment", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: helmfileOptionName(word, "-e", "--environment"), Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.Environment = value
				i += helmfileConsumedWords(word)
			}
		case helmfileOptionWithValue(word, "-f", "--file"):
			value, consumed := helmfileOptionValue(word, "--file", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: helmfileOptionName(word, "-f", "--file"), Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.Files = append(semantic.Files, value)
				i += helmfileConsumedWords(word)
			}
		case helmfileOptionWithValue(word, "-n", "--namespace"):
			value, consumed := helmfileOptionValue(word, "--namespace", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: helmfileOptionName(word, "-n", "--namespace"), Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.Namespace = value
				i += helmfileConsumedWords(word)
			}
		case helmfileOptionWithValue(word, "", "--kube-context"):
			value, consumed := helmfileOptionValue(word, "--kube-context", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: "--kube-context", Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.KubeContext = value
				i += helmfileConsumedWords(word)
			}
		case helmfileOptionWithValue(word, "-l", "--selector"):
			value, consumed := helmfileOptionValue(word, "--selector", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: helmfileOptionName(word, "-l", "--selector"), Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.Selectors = append(semantic.Selectors, value)
				i += helmfileConsumedWords(word)
			}
		case helmfileOptionWithValue(word, "", "--cascade"):
			value, consumed := helmfileOptionValue(word, "--cascade", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: "--cascade", Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.Cascade = value
				i += helmfileConsumedWords(word)
			}
		case helmfileOptionWithValue(word, "", "--state-values-file"):
			value, consumed := helmfileOptionValue(word, "--state-values-file", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: "--state-values-file", Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.StateValuesFiles = append(semantic.StateValuesFiles, value)
				i += helmfileConsumedWords(word)
			}
		case helmfileOptionWithValue(word, "", "--state-values-set"):
			value, consumed := helmfileOptionValue(word, "--state-values-set", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: "--state-values-set", Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.StateValuesSetKeys = append(semantic.StateValuesSetKeys, helmfileStateValueKey(value))
				i += helmfileConsumedWords(word)
			}
		case helmfileOptionWithValue(word, "", "--state-values-set-string"):
			value, consumed := helmfileOptionValue(word, "--state-values-set-string", base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: "--state-values-set-string", Value: value, HasValue: consumed, Position: i})
			if consumed {
				semantic.StateValuesSetStringKeys = append(semantic.StateValuesSetStringKeys, helmfileStateValueKey(value))
				i += helmfileConsumedWords(word)
			}
		case word == "-i" || word == "--interactive":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.Interactive = true
		case word == "--dry-run":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			v := true
			semantic.DryRun = &v
		case word == "--wait":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.Wait = true
		case word == "--wait-for-jobs":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.WaitForJobs = true
		case word == "--skip-diff":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.SkipDiff = true
		case word == "--skip-needs":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.SkipNeeds = true
		case word == "--include-needs":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.IncludeNeeds = true
		case word == "--include-transitive-needs":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.IncludeTransitiveNeeds = true
		case word == "--purge":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.Purge = true
		case word == "--delete-wait":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			semantic.DeleteWait = true
		case strings.HasPrefix(word, "-") && word != "-":
			cmd.Options = append(cmd.Options, parseOptionWord(word, i))
		default:
			positionals = append(positionals, word)
		}
	}

	if len(positionals) > 0 {
		semantic.Verb = positionals[0]
		cmd.ActionPath = []string{semantic.Verb}
		cmd.Args = append([]string(nil), positionals[1:]...)
	}
	semantic.Flags = normalizedHelmfileFlags(cmd.Options)
	cmd.Helmfile = semantic
	cmd.Namespace = semantic.Namespace
	return cmd, true
}

func helmfileOptionWithValue(word string, short string, long string) bool {
	if short != "" && word == short {
		return true
	}
	return word == long || strings.HasPrefix(word, long+"=")
}

func helmfileOptionName(word string, short string, long string) string {
	if short != "" && word == short {
		return short
	}
	return long
}

func helmfileOptionValue(word string, long string, words []string, i int) (string, bool) {
	if value, ok := strings.CutPrefix(word, long+"="); ok {
		return value, true
	}
	if i+1 >= len(words) {
		return "", false
	}
	return words[i+1], true
}

func helmfileConsumedWords(word string) int {
	if strings.Contains(word, "=") {
		return 0
	}
	return 1
}

func helmfileStateValueKey(value string) string {
	key, _, ok := strings.Cut(value, "=")
	if !ok {
		return value
	}
	return key
}

func normalizedHelmfileFlags(options []Option) []string {
	flags := make([]string, 0, len(options)*2)
	for _, option := range options {
		flags = append(flags, option.Name)
		if option.HasValue {
			flags = append(flags, option.Name+"="+option.Value)
		}
	}
	return flags
}
