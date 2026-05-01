package command

import "strings"

type GwsParser struct{}

func init() {
	RegisterDefaultParser(GwsParser{})
}

func (GwsParser) Program() string {
	return "gws"
}

func (GwsParser) Parse(base Command) (Command, bool) {
	if base.Program != "gws" {
		return Command{}, false
	}

	cmd := base
	cmd.Parser = GwsParser{}.Program()
	cmd.SemanticParser = GwsParser{}.Program()
	cmd.Args = []string{}

	var action []string
	seenOption := false
	seenHelper := false
	for i := 0; i < len(base.RawWords); i++ {
		word := base.RawWords[i]
		switch {
		case gwsOptionWithValue(word, "--params", "", "--json", "--upload", "--sanitize", "--scopes", "--timezone", "--tz"):
			name, value, consumed := gwsOptionValue(word, base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: name, Value: value, HasValue: consumed, Position: i})
			seenOption = true
			if consumed && !strings.Contains(word, "=") {
				i++
			}
		case word == "-s":
			value, consumed := gwsShortOptionValue(base.RawWords, i)
			cmd.Options = append(cmd.Options, Option{Name: "-s", Value: value, HasValue: consumed, Position: i})
			seenOption = true
			if consumed {
				i++
			}
		case word == "--dry-run" || word == "--page-all" || word == "--unmasked" || word == "--today" || word == "--debug":
			cmd.Options = append(cmd.Options, Option{Name: word, Position: i})
			seenOption = true
		case strings.HasPrefix(word, "-") && word != "-":
			cmd.Options = append(cmd.Options, parseOptionWord(word, i))
			seenOption = true
		default:
			if seenOption || seenHelper {
				cmd.Args = append(cmd.Args, word)
				continue
			}
			action = append(action, word)
			if strings.HasPrefix(word, "+") {
				seenHelper = true
			}
		}
	}

	cmd.ActionPath = append([]string(nil), action...)
	cmd.Gws = buildGwsSemantic(action, cmd.Options)
	return cmd, true
}

func gwsOptionWithValue(word string, names ...string) bool {
	for _, name := range names {
		if name == "" {
			continue
		}
		if word == name || strings.HasPrefix(word, name+"=") {
			return true
		}
	}
	return false
}

func gwsOptionValue(word string, words []string, i int) (string, string, bool) {
	name, value, ok := strings.Cut(word, "=")
	if ok {
		return name, value, true
	}
	if i+1 >= len(words) {
		return word, "", false
	}
	return word, words[i+1], true
}

func gwsShortOptionValue(words []string, i int) (string, bool) {
	if i+1 >= len(words) {
		return "", false
	}
	return words[i+1], true
}

func buildGwsSemantic(action []string, options []Option) *GwsSemantic {
	semantic := &GwsSemantic{
		Flags: normalizedGwsFlags(options),
	}
	if len(action) > 0 {
		semantic.Service = action[0]
	}
	if len(action) > 1 {
		methodIndex, helper := gwsMethodIndex(action)
		semantic.Helper = helper
		semantic.Method = action[methodIndex]
		semantic.ResourcePath = append([]string(nil), action[1:methodIndex]...)
	}
	semantic.DryRun = hasOption(options, "--dry-run")
	semantic.PageAll = hasOption(options, "--page-all")
	semantic.Upload = hasOption(options, "--upload")
	semantic.Sanitize = hasOption(options, "--sanitize")
	semantic.Params = hasOption(options, "--params")
	semantic.JSONBody = hasOption(options, "--json")
	semantic.Unmasked = hasOption(options, "--unmasked")
	semantic.Scopes = splitGwsScopes(lastOptionValueAny(options, "--scopes", "-s"))
	semantic.Mutating = gwsMethodIn(semantic.Method, gwsMutatingMethods())
	semantic.Destructive = gwsMethodIn(semantic.Method, gwsDestructiveMethods())
	semantic.ReadOnly = gwsMethodIn(semantic.Method, gwsReadOnlyMethods())
	return semantic
}

func gwsMethodIndex(action []string) (int, bool) {
	methodIndex := len(action) - 1
	for i, token := range action[1:] {
		if strings.HasPrefix(token, "+") {
			return i + 1, true
		}
	}
	for i := 1; i < len(action); i++ {
		if gwsKnownDiscoveryMethod(action[i]) {
			return i, false
		}
	}
	return methodIndex, false
}

func gwsKnownDiscoveryMethod(method string) bool {
	return gwsMethodIn(method, gwsDiscoveryMethods())
}

func normalizedGwsFlags(options []Option) []string {
	flags := make([]string, 0, len(options))
	for _, option := range options {
		if option.Name == "" {
			continue
		}
		flags = append(flags, option.Name)
	}
	return flags
}

func splitGwsScopes(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' '
	})
	scopes := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	return scopes
}

func gwsMethodIn(method string, names map[string]struct{}) bool {
	if method == "" {
		return false
	}
	normalized := strings.TrimPrefix(method, "+")
	if _, ok := names[method]; ok {
		return true
	}
	_, ok := names[normalized]
	return ok
}

func gwsMutatingMethods() map[string]struct{} {
	return map[string]struct{}{
		"create": {}, "update": {}, "patch": {}, "delete": {}, "remove": {}, "clear": {},
		"emptyTrash": {}, "trash": {}, "untrash": {}, "send": {}, "append": {},
		"batchUpdate": {}, "watch": {}, "push": {}, "renew": {}, "insert": {},
		"+send": {}, "+upload": {},
	}
}

func gwsDiscoveryMethods() map[string]struct{} {
	methods := map[string]struct{}{}
	for method := range gwsReadOnlyMethods() {
		methods[method] = struct{}{}
	}
	for method := range gwsMutatingMethods() {
		methods[method] = struct{}{}
	}
	for method := range gwsDestructiveMethods() {
		methods[method] = struct{}{}
	}
	for _, method := range []string{
		"batchGet", "batchDelete", "batchClear", "batchUpdate", "copy", "export",
		"import", "insert", "move", "undelete",
	} {
		methods[method] = struct{}{}
	}
	return methods
}

func gwsDestructiveMethods() map[string]struct{} {
	return map[string]struct{}{
		"delete": {}, "remove": {}, "clear": {}, "emptyTrash": {}, "trash": {}, "batchDelete": {},
		"+delete": {}, "+remove": {},
	}
}

func gwsReadOnlyMethods() map[string]struct{} {
	return map[string]struct{}{
		"list": {}, "get": {}, "show": {}, "schema": {},
		"+read": {}, "+agenda": {}, "+triage": {}, "+standup-report": {}, "+meeting-prep": {},
	}
}

func lastOptionValueAny(options []Option, names ...string) string {
	value := ""
	for _, option := range options {
		for _, name := range names {
			if option.Name == name && option.HasValue {
				value = option.Value
			}
		}
	}
	return value
}
