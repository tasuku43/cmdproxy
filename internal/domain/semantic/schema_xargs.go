package semantic

var xargsSchema = Schema{
	Command:     "xargs",
	order:       95,
	Description: "xargs wrapper execution with dynamic stdin-derived arguments.",
	Parser:      "xargs",
	Fields: []Field{
		stringField("inner_command", "Command token xargs will execute, or echo when xargs has no explicit command."),
		stringListField("inner_command_in", "Allowed xargs inner command tokens."),
		stringListField("inner_args_contains", "Static inner command arguments that must be present after the inner command token."),
		boolField("null_separated", "True when -0 or --null is present."),
		boolField("no_run_if_empty", "True when -r or --no-run-if-empty is present."),
		boolField("replace_mode", "True when -I, -i, --replace, or --replace-str is present."),
		boolField("parallel", "True when -P/--max-procs allows more than one process."),
		stringField("max_args", "Value from -n/--max-args when present."),
		boolField("dynamic_args", "Always true for parsed xargs commands because stdin supplies runtime argv."),
		boolField("implicit_echo", "True when xargs has no explicit command and will execute echo."),
		stringListField("flags_contains", "Parser-recognized xargs option tokens that must be present."),
		stringListField("flags_prefixes", "Parser-recognized xargs option tokens that must start with these prefixes."),
	},
	Examples: []Example{
		{Title: "Allow a narrow grep through xargs", YAML: `permission:
  allow:
    - command:
        name: xargs
        semantic:
          inner_command: grep
          null_separated: true
          no_run_if_empty: true
          replace_mode: false
          parallel: false`},
	},
	Notes: []string{
		"`xargs` semantic rules do not make `command.name: grep` match `xargs grep`; xargs must be allowed explicitly.",
		"`dynamic_args` records that stdin can append runtime arguments. Keep allow rules narrow.",
	},
}

func init() {
	RegisterSchema(xargsSchema)
}
