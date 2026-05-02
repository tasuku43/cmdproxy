package command

import "strings"

type XargsParser struct{}

func init() {
	RegisterDefaultParser(XargsParser{})
}

func (XargsParser) Program() string {
	return "xargs"
}

func (XargsParser) Parse(base Command) (Command, bool) {
	if base.Program != "xargs" {
		return Command{}, false
	}

	cmd := base
	cmd.Parser = XargsParser{}.Program()
	cmd.SemanticParser = XargsParser{}.Program()
	cmd.Args = []string{}
	cmd.Xargs = buildXargsSemantic(base.RawWords)
	return cmd, true
}

func buildXargsSemantic(words []string) *XargsSemantic {
	semantic := &XargsSemantic{
		DynamicArgs: true,
	}

	i := 0
	for i < len(words) {
		word := words[i]
		if word == "--" {
			i++
			break
		}
		if word == "-" || !strings.HasPrefix(word, "-") {
			break
		}

		name, value, hasInlineValue := strings.Cut(word, "=")
		semantic.Flags = append(semantic.Flags, name)

		switch {
		case word == "-0" || word == "--null":
			semantic.NullSeparated = true
			i++
		case word == "-r" || word == "--no-run-if-empty":
			semantic.NoRunIfEmpty = true
			i++
		case word == "-I":
			semantic.ReplaceMode = true
			if i+1 < len(words) {
				i += 2
			} else {
				i++
			}
		case word == "--replace" || word == "--replace-str":
			semantic.ReplaceMode = true
			i++
		case strings.HasPrefix(word, "-I") && word != "-I":
			semantic.ReplaceMode = true
			i++
		case strings.HasPrefix(word, "--replace=") || strings.HasPrefix(word, "--replace-str="):
			semantic.ReplaceMode = true
			i++
		case word == "-i" || word == "--replace":
			semantic.ReplaceMode = true
			if i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") {
				i += 2
			} else {
				i++
			}
		case word == "-n" || word == "--max-args" || word == "-P" || word == "--max-procs":
			if i+1 < len(words) {
				if word == "-P" || word == "--max-procs" {
					semantic.Parallel = words[i+1] != "0" && words[i+1] != "1"
				} else {
					semantic.MaxArgs = words[i+1]
				}
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(word, "-n") && len(word) > 2:
			semantic.MaxArgs = strings.TrimPrefix(word, "-n")
			i++
		case strings.HasPrefix(word, "-P") && len(word) > 2:
			value := strings.TrimPrefix(word, "-P")
			semantic.Parallel = value != "0" && value != "1"
			i++
		case (name == "--max-args" || name == "--max-procs") && hasInlineValue:
			if name == "--max-procs" {
				semantic.Parallel = value != "0" && value != "1"
			} else {
				semantic.MaxArgs = value
			}
			i++
		case word == "-E" || word == "-s" || word == "--max-chars" || word == "-L" || word == "--max-lines":
			if i+1 < len(words) {
				i += 2
			} else {
				i++
			}
		case strings.HasPrefix(word, "-E") || strings.HasPrefix(word, "-s") || strings.HasPrefix(word, "-L"):
			i++
		default:
			i++
		}
	}

	if i >= len(words) {
		semantic.InnerCommand = "echo"
		semantic.ImplicitEcho = true
		return semantic
	}
	semantic.InnerCommand = words[i]
	semantic.InnerArgs = append([]string(nil), words[i+1:]...)
	return semantic
}
