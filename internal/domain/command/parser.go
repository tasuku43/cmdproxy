package command

import (
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/invocation"
)

type Invocation struct {
	Raw          string
	ProgramToken string
	Program      string
	Env          map[string]string
	Words        []string
}

type CommandParser interface {
	Program() string
	Parse(inv Invocation) (Command, bool)
}

type CommandParserRegistry struct {
	parsers  map[string]CommandParser
	fallback CommandParser
}

func NewInvocation(raw string) Invocation {
	parsed := invocation.Parse(raw)
	return Invocation{
		Raw:          raw,
		ProgramToken: parsed.CommandToken,
		Program:      parsed.Command,
		Env:          parsed.EnvAssignments,
		Words:        append([]string(nil), parsed.Args...),
	}
}

func DefaultParserRegistry() *CommandParserRegistry {
	return NewCommandParserRegistry(GitParser{})
}

func NewCommandParserRegistry(parsers ...CommandParser) *CommandParserRegistry {
	registry := &CommandParserRegistry{
		parsers:  map[string]CommandParser{},
		fallback: GenericParser{},
	}
	for _, parser := range parsers {
		registry.Register(parser)
	}
	return registry
}

func (r *CommandParserRegistry) Register(parser CommandParser) {
	if parser == nil || parser.Program() == "" {
		return
	}
	r.parsers[parser.Program()] = parser
}

func (r *CommandParserRegistry) Parse(inv Invocation) (Command, bool) {
	if r == nil {
		return GenericParser{}.Parse(inv)
	}
	if parser := r.parsers[inv.Program]; parser != nil {
		return parser.Parse(inv)
	}
	return r.fallback.Parse(inv)
}

type GenericParser struct{}

func (GenericParser) Program() string {
	return "generic"
}

func (GenericParser) Parse(inv Invocation) (Command, bool) {
	if inv.Program == "" {
		return Command{}, false
	}
	globalOptions, actionPath, options := splitGenericWords(inv.Words)
	return Command{
		Raw:           inv.Raw,
		Program:       inv.Program,
		ProgramToken:  inv.ProgramToken,
		Env:           inv.Env,
		GlobalOptions: globalOptions,
		ActionPath:    actionPath,
		Options:       options,
		RawWords:      append([]string(nil), inv.Words...),
		Args:          append([]string(nil), inv.Words...),
		Parser:        GenericParser{}.Program(),
	}, true
}

func splitGenericWords(words []string) ([]Option, []string, []Option) {
	var globalOptions []Option
	actionPath := []string{}
	var options []Option
	seenAction := false

	for i, word := range words {
		if strings.HasPrefix(word, "-") && word != "-" {
			if seenAction {
				options = append(options, parseOptionWord(word, i))
			} else {
				globalOptions = append(globalOptions, parseOptionWord(word, i))
			}
			continue
		}
		seenAction = true
		actionPath = append(actionPath, word)
	}

	return globalOptions, actionPath, options
}

func parseOptionWord(word string, position int) Option {
	name, value, ok := strings.Cut(word, "=")
	if ok && name != "" {
		return Option{Name: name, Value: value, HasValue: true, Position: position}
	}
	return Option{Name: word, Position: position}
}
