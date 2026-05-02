package policy

import (
	commandpkg "github.com/tasuku43/cc-bash-guard/internal/domain/command"
)

func init() {
	registerSemanticHandler(semanticHandler{
		command:  "xargs",
		match:    func(s SemanticMatchSpec, cmd commandpkg.Command) bool { return s.Xargs().matches(cmd) },
		validate: ValidateXargsSemanticMatchSpec,
	})
}

func (s XargsSemanticSpec) matches(cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "xargs" || cmd.Xargs == nil {
		return false
	}
	xargs := cmd.Xargs
	if s.InnerCommand != "" && xargs.InnerCommand != s.InnerCommand {
		return false
	}
	if len(s.InnerCommandIn) > 0 && !containsString(s.InnerCommandIn, xargs.InnerCommand) {
		return false
	}
	for _, arg := range s.InnerArgsContains {
		if !containsString(xargs.InnerArgs, arg) {
			return false
		}
	}
	if s.NullSeparated != nil && xargs.NullSeparated != *s.NullSeparated {
		return false
	}
	if s.NoRunIfEmpty != nil && xargs.NoRunIfEmpty != *s.NoRunIfEmpty {
		return false
	}
	if s.ReplaceMode != nil && xargs.ReplaceMode != *s.ReplaceMode {
		return false
	}
	if s.Parallel != nil && xargs.Parallel != *s.Parallel {
		return false
	}
	if s.MaxArgs != "" && xargs.MaxArgs != s.MaxArgs {
		return false
	}
	if s.DynamicArgs != nil && xargs.DynamicArgs != *s.DynamicArgs {
		return false
	}
	if s.ImplicitEcho != nil && xargs.ImplicitEcho != *s.ImplicitEcho {
		return false
	}
	for _, flag := range s.FlagsContains {
		if !containsString(xargs.Flags, flag) {
			return false
		}
	}
	for _, prefix := range s.FlagsPrefixes {
		if !containsPrefix(xargs.Flags, prefix) {
			return false
		}
	}
	return true
}
