package semantic

//go:generate go run ../../devtools/gen-semantic-coverage

type Schema struct {
	Command      string    `json:"command"`
	SemanticPath string    `json:"semantic_path"`
	Description  string    `json:"description"`
	Parser       string    `json:"parser"`
	Fields       []Field   `json:"fields"`
	Examples     []Example `json:"examples"`
	Notes        []string  `json:"notes,omitempty"`
	order        int
}

type Field struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Values      []string `json:"values,omitempty"`
	Since       string   `json:"since,omitempty"`
}

type Example struct {
	Title string `json:"title"`
	YAML  string `json:"yaml"`
}

var schemas []Schema

func RegisterSchema(schema Schema) {
	if schema.Command == "" {
		return
	}
	schemas = append(schemas, schema)
}

func AllSchemas() []Schema {
	out := make([]Schema, 0, len(schemas))
	for _, schema := range schemas {
		out = append(out, withSemanticPath(schema))
	}
	sortSchemas(out)
	return out
}

func Lookup(command string) (Schema, bool) {
	for _, schema := range schemas {
		if schema.Command == command {
			return withSemanticPath(schema), true
		}
	}
	return Schema{}, false
}

func SchemasByCommand() map[string]Schema {
	byCommand := map[string]Schema{}
	for _, schema := range AllSchemas() {
		byCommand[schema.Command] = schema
	}
	return byCommand
}

func SupportedCommands() []string {
	all := AllSchemas()
	commands := make([]string, 0, len(all))
	for _, schema := range all {
		commands = append(commands, schema.Command)
	}
	return commands
}

func FieldNames(command string) []string {
	schema, ok := Lookup(command)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(schema.Fields))
	for _, field := range schema.Fields {
		names = append(names, field.Name)
	}
	return names
}

func IsFieldSupported(command, field string) bool {
	for _, supported := range FieldNames(command) {
		if supported == field {
			return true
		}
	}
	return false
}

func withSemanticPath(schema Schema) Schema {
	schema.SemanticPath = "command.semantic"
	return schema
}

func sortSchemas(values []Schema) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && schemaLess(values[j], values[j-1]); j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func schemaLess(a, b Schema) bool {
	if a.order != b.order {
		return a.order < b.order
	}
	return a.Command < b.Command
}

func stringField(name, description string) Field {
	return Field{Name: name, Type: "string", Description: description}
}

func stringListField(name, description string) Field {
	return Field{Name: name, Type: "[]string", Description: description}
}

func boolField(name, description string) Field {
	return Field{Name: name, Type: "bool", Description: description}
}
