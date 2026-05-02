package command

import "testing"

func TestParseXargsSemantic(t *testing.T) {
	plan := Parse(`xargs -0 -r -n1 grep -n foo`)
	if len(plan.Commands) != 1 {
		t.Fatalf("Commands len = %d, want 1", len(plan.Commands))
	}
	cmd := plan.Commands[0]
	if cmd.SemanticParser != "xargs" || cmd.Xargs == nil {
		t.Fatalf("parser state = (%q, %q, %v), want xargs semantic", cmd.Parser, cmd.SemanticParser, cmd.Xargs)
	}
	if cmd.Xargs.InnerCommand != "grep" {
		t.Fatalf("InnerCommand = %q, want grep", cmd.Xargs.InnerCommand)
	}
	if !cmd.Xargs.NullSeparated || !cmd.Xargs.NoRunIfEmpty {
		t.Fatalf("NullSeparated/NoRunIfEmpty = %v/%v, want true/true", cmd.Xargs.NullSeparated, cmd.Xargs.NoRunIfEmpty)
	}
	if cmd.Xargs.MaxArgs != "1" {
		t.Fatalf("MaxArgs = %q, want 1", cmd.Xargs.MaxArgs)
	}
	if len(cmd.Xargs.InnerArgs) != 2 || cmd.Xargs.InnerArgs[0] != "-n" || cmd.Xargs.InnerArgs[1] != "foo" {
		t.Fatalf("InnerArgs = %#v, want [-n foo]", cmd.Xargs.InnerArgs)
	}
}

func TestParseXargsImplicitEcho(t *testing.T) {
	plan := Parse(`xargs -0`)
	if len(plan.Commands) != 1 || plan.Commands[0].Xargs == nil {
		t.Fatalf("Commands = %#v, want xargs command", plan.Commands)
	}
	xargs := plan.Commands[0].Xargs
	if xargs.InnerCommand != "echo" || !xargs.ImplicitEcho {
		t.Fatalf("InnerCommand/ImplicitEcho = %q/%v, want echo/true", xargs.InnerCommand, xargs.ImplicitEcho)
	}
}
