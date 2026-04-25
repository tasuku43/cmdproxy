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
	Parse(base Command) (Command, bool)
}

type CommandParserRegistry struct {
	parsers map[string]CommandParser
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
		parsers: map[string]CommandParser{},
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
	base, ok := GenericParser{}.Parse(inv)
	if !ok {
		return Command{}, false
	}
	if r == nil {
		return base, true
	}
	if parser := r.parsers[inv.Program]; parser != nil {
		cmd, ok := parser.Parse(base)
		if ok {
			return cmd, true
		}
	}
	return base, true
}

type GenericParser struct{}

func (GenericParser) Program() string {
	return "generic"
}

func (GenericParser) Parse(inv Invocation) (Command, bool) {
	if inv.Program == "" {
		return Command{}, false
	}
	return Command{
		Raw:          inv.Raw,
		Program:      inv.Program,
		ProgramToken: inv.ProgramToken,
		Env:          inv.Env,
		RawWords:     append([]string(nil), inv.Words...),
		RawOptions:   splitRawOptions(inv.Words),
		Parser:       GenericParser{}.Program(),
	}, true
}

func splitRawOptions(words []string) []Option {
	var options []Option

	for i, word := range words {
		if strings.HasPrefix(word, "-") && word != "-" {
			options = append(options, parseOptionWord(word, i))
		}
	}

	return options
}

func parseOptionWord(word string, position int) Option {
	name, value, ok := strings.Cut(word, "=")
	if ok && name != "" {
		return Option{Name: name, Value: value, HasValue: true, Position: position}
	}
	return Option{Name: word, Position: position}
}
