package semantic

var gwsSchema = Schema{
	Command:     "gws",
	order:       60,
	Description: "Google Workspace CLI dynamic Discovery and helper commands.",
	Parser:      "gws",
	Fields: []Field{
		stringField("service", "First non-global gws action token, such as drive, gmail, calendar, sheets, docs, chat, auth, schema, events, workflow, modelarmor, or script."),
		stringListField("service_in", "Allowed gws services."),
		stringListField("resource_path", "Exact resource path tokens between service and method, such as [files] or [spreadsheets, values]."),
		stringListField("resource_path_contains", "Resource path tokens that must be present."),
		stringField("method", "Final Discovery method or helper command name, such as list, get, create, delete, update, patch, export, login, +send, or +upload."),
		stringListField("method_in", "Allowed gws methods or helper names."),
		boolField("helper", "True when the parsed method starts with +."),
		boolField("mutating", "True for methods inferred to write or change server state."),
		boolField("destructive", "True for methods inferred to delete, clear, trash, or remove data."),
		boolField("read_only", "True for methods inferred to read without mutation."),
		boolField("dry_run", "True when --dry-run is present."),
		boolField("page_all", "True when --page-all is present."),
		boolField("upload", "True when --upload is present."),
		boolField("sanitize", "True when --sanitize is present."),
		boolField("params", "True when --params is present."),
		boolField("json_body", "True when --json is present."),
		boolField("unmasked", "True when --unmasked is present."),
		stringListField("scopes", "Scopes selected by --scopes or -s, split on commas and spaces."),
		stringListField("flags_contains", "Parser-recognized gws option tokens that must be present; this does not scan raw argv words."),
		stringListField("flags_prefixes", "Parser-recognized gws option tokens that must start with these prefixes; this depends on the gws parser."),
	},
	Examples: []Example{
		{Title: "Allow Drive file listing", YAML: `permission:
  allow:
    - command:
        name: gws
        semantic:
          service: drive
          resource_path: [files]
          method: list`},
	},
	Notes: []string{
		"`gws` dynamically builds much of its command surface from Google Discovery Service, so this schema exposes generic service/resource_path/method fields instead of a closed list of API methods.",
		"Known Discovery method names are split from following positional arguments, so commands like `gws drive files get 1abcDEF` parse as `resource_path: [files]` and `method: get`.",
		"`mutating`, `destructive`, and `read_only` are conservative method-name inferences; use explicit service, resource_path, and method fields for tighter policies.",
	},
}

func init() {
	RegisterSchema(gwsSchema)
}
