package command

import (
	"strings"

	"github.com/tasuku43/cc-bash-proxy/internal/domain/invocation"
	"mvdan.cc/sh/v3/syntax"
)

type Command struct {
	// Structural layer: produced for every command before any CLI-specific parser runs.
	Raw          string
	Program      string
	ProgramToken string
	Env          map[string]string
	RawWords     []string
	RawOptions   []Option
	Parser       string

	// Semantic layer: optional fields added by CLI-specific parsers.
	GlobalOptions    []Option
	ActionPath       []string
	Options          []Option
	Args             []string
	WorkingDirectory string
	Namespace        string
	ResourceType     string
	ResourceName     string
	SemanticParser   string
	Git              *GitSemantic
}

type Option struct {
	Name     string
	Value    string
	HasValue bool
	Position int
}

type GitSemantic struct {
	Verb           string
	Remote         string
	Branch         string
	Ref            string
	Force          bool
	Hard           bool
	Recursive      bool
	IncludeIgnored bool
	Cached         bool
	Staged         bool
	Flags          []string
}

func (c Command) HasOption(name string) bool {
	return hasOption(c.Options, name)
}

func (c Command) OptionValues(name string) []string {
	return optionValues(c.Options, name)
}

func (c Command) HasGlobalOption(name string) bool {
	return hasOption(c.GlobalOptions, name)
}

func (c Command) GlobalOptionValues(name string) []string {
	return optionValues(c.GlobalOptions, name)
}

func hasOption(options []Option, name string) bool {
	for _, option := range options {
		if option.Name == name {
			return true
		}
	}
	return false
}

func optionValues(options []Option, name string) []string {
	var values []string
	for _, option := range options {
		if option.Name == name && option.HasValue {
			values = append(values, option.Value)
		}
	}
	return values
}

type CommandPlan struct {
	Raw                    string
	Commands               []Command
	Shape                  ShellShape
	SafeForStructuredAllow bool
	Diagnostics            []Diagnostic
}

type ShellShape struct {
	Kind                   ShellShapeKind
	HasPipeline            bool
	HasConditional         bool
	HasSequence            bool
	HasBackground          bool
	HasRedirection         bool
	HasSubshell            bool
	HasCommandSubstitution bool
	HasProcessSubstitution bool
}

type ShellShapeKind string

const (
	ShellShapeSimple   ShellShapeKind = "simple"
	ShellShapeCompound ShellShapeKind = "compound"
	ShellShapeUnknown  ShellShapeKind = "unknown"
)

type Diagnostic struct {
	Severity string
	Message  string
}

type EvaluationSafety struct {
	Safe    bool
	Reasons []string
}

func Parse(raw string) CommandPlan {
	return ParseWithRegistry(raw, DefaultParserRegistry())
}

func ParseWithRegistry(raw string, registry *CommandParserRegistry) CommandPlan {
	plan := CommandPlan{
		Raw:   raw,
		Shape: ShellShape{Kind: ShellShapeUnknown},
	}

	if strings.TrimSpace(raw) == "" {
		plan.Diagnostics = append(plan.Diagnostics, Diagnostic{Severity: "error", Message: "empty command"})
		return plan
	}

	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(raw), "")
	if err != nil {
		plan.Diagnostics = append(plan.Diagnostics, Diagnostic{Severity: "error", Message: err.Error()})
		return plan
	}

	walker := planWalker{raw: raw, registry: registry}
	if len(file.Stmts) > 1 || len(file.Last) > 0 {
		walker.shape.HasSequence = true
	}
	for _, stmt := range file.Stmts {
		walker.visitStmt(stmt)
	}

	plan.Commands = walker.commands
	plan.Shape = walker.shape.finalize()
	// CommandPlan describes shell shape and CLI semantics; invocation owns the
	// safety gate used by allow-list matching.
	plan.SafeForStructuredAllow = plan.Shape.Kind == ShellShapeSimple &&
		len(plan.Commands) == 1 &&
		len(plan.Diagnostics) == 0 &&
		invocation.IsStructuredSafeForAllow(raw)
	return plan
}

func IsSafeForEvaluation(plan CommandPlan) bool {
	return EvaluationSafetyForPlan(plan).Safe
}

func EvaluationSafetyForPlan(plan CommandPlan) EvaluationSafety {
	reasons := unsafeEvaluationReasons(plan)
	return EvaluationSafety{
		Safe:    len(reasons) == 0,
		Reasons: reasons,
	}
}

func unsafeEvaluationReasons(plan CommandPlan) []string {
	var reasons []string
	if len(plan.Diagnostics) > 0 {
		for _, diagnostic := range plan.Diagnostics {
			if diagnostic.Severity == "error" {
				reasons = append(reasons, "parse_error")
				break
			}
		}
		if len(reasons) == 0 {
			reasons = append(reasons, "diagnostics")
		}
		return dedupeStrings(reasons)
	}

	if plan.Shape.Kind == ShellShapeUnknown {
		reasons = append(reasons, "unknown_shape")
	}
	if plan.Shape.HasRedirection {
		reasons = append(reasons, "redirect")
	}
	if plan.Shape.HasSubshell {
		reasons = append(reasons, "subshell")
	}
	if plan.Shape.HasBackground {
		reasons = append(reasons, "background")
	}
	if plan.Shape.HasCommandSubstitution {
		reasons = append(reasons, "command_substitution")
	}
	if plan.Shape.HasProcessSubstitution {
		reasons = append(reasons, "process_substitution")
	}
	if plan.Shape.HasPipeline && plan.Shape.hasNonPipelineCompoundFeature() {
		reasons = append(reasons, "pipeline_compound_shape")
	}
	if len(reasons) > 0 {
		return dedupeStrings(reasons)
	}

	if plan.Shape.Kind == ShellShapeCompound {
		if len(plan.Commands) == 0 {
			reasons = append(reasons, "unknown_shape")
			return dedupeStrings(reasons)
		}
		for _, cmd := range plan.Commands {
			if !invocation.IsStructuredSafeForAllow(cmd.Raw) {
				reasons = append(reasons, "unsafe_ast")
				break
			}
		}
		return dedupeStrings(reasons)
	}

	if plan.Shape.Kind != ShellShapeSimple {
		reasons = append(reasons, "unknown_shape")
	} else if !invocation.IsStructuredSafeForAllow(plan.Raw) {
		reasons = append(reasons, "unsafe_ast")
	}

	return dedupeStrings(reasons)
}

func (s ShellShape) hasNonPipelineCompoundFeature() bool {
	return s.HasConditional ||
		s.HasSequence ||
		s.HasBackground ||
		s.HasRedirection ||
		s.HasSubshell ||
		s.HasCommandSubstitution ||
		s.HasProcessSubstitution
}

func (s ShellShape) Flags() []string {
	flags := make([]string, 0, 8)
	if s.HasPipeline {
		flags = append(flags, "pipeline")
	}
	if s.HasConditional {
		flags = append(flags, "conditional")
	}
	if s.HasSequence {
		flags = append(flags, "sequence")
	}
	if s.HasBackground {
		flags = append(flags, "background")
	}
	if s.HasRedirection {
		flags = append(flags, "redirection")
	}
	if s.HasSubshell {
		flags = append(flags, "subshell")
	}
	if s.HasCommandSubstitution {
		flags = append(flags, "command_substitution")
	}
	if s.HasProcessSubstitution {
		flags = append(flags, "process_substitution")
	}
	return flags
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

type planWalker struct {
	raw      string
	registry *CommandParserRegistry
	shape    ShellShape
	commands []Command
}

func (w *planWalker) visitStmt(stmt *syntax.Stmt) {
	if stmt == nil {
		return
	}
	if stmt.Background || stmt.Coprocess || stmt.Disown {
		w.shape.HasBackground = true
	}
	if len(stmt.Redirs) > 0 {
		w.shape.HasRedirection = true
	}
	if len(stmt.Comments) > 0 || stmt.Negated {
		w.shape.Kind = ShellShapeUnknown
	}
	w.visitCommand(stmt.Cmd)
	for _, redir := range stmt.Redirs {
		w.visitWord(redir.Word)
		w.visitWord(redir.Hdoc)
	}
}

func (w *planWalker) visitCommand(cmd syntax.Command) {
	switch x := cmd.(type) {
	case nil:
		return
	case *syntax.CallExpr:
		w.visitCall(x)
	case *syntax.BinaryCmd:
		w.visitBinary(x)
	case *syntax.Subshell:
		w.shape.HasSubshell = true
		for _, stmt := range x.Stmts {
			w.visitStmt(stmt)
		}
	case *syntax.Block:
		w.shape.Kind = ShellShapeUnknown
		for _, stmt := range x.Stmts {
			w.visitStmt(stmt)
		}
	default:
		w.shape.Kind = ShellShapeUnknown
	}
}

func (w *planWalker) visitBinary(cmd *syntax.BinaryCmd) {
	switch cmd.Op {
	case syntax.AndStmt:
		w.shape.HasConditional = true
	case syntax.OrStmt:
		w.shape.HasConditional = true
	case syntax.Pipe, syntax.PipeAll:
		w.shape.HasPipeline = true
	default:
		w.shape.Kind = ShellShapeUnknown
	}
	w.visitStmt(cmd.X)
	w.visitStmt(cmd.Y)
}

func (w *planWalker) visitCall(call *syntax.CallExpr) {
	for _, assign := range call.Assigns {
		if assign != nil {
			w.visitWord(assign.Value)
		}
	}
	for _, arg := range call.Args {
		w.visitWord(arg)
	}
	if len(call.Args) == 0 {
		return
	}

	raw := w.nodeRaw(call)
	inv := NewInvocation(raw)
	if cmd, ok := w.registry.Parse(inv); ok {
		w.commands = append(w.commands, cmd)
	}
}

func (w *planWalker) visitWord(word *syntax.Word) {
	if word == nil {
		return
	}
	for _, part := range word.Parts {
		w.visitWordPart(part)
	}
}

func (w *planWalker) visitWordPart(part syntax.WordPart) {
	switch x := part.(type) {
	case *syntax.CmdSubst:
		w.shape.HasCommandSubstitution = true
		for _, stmt := range x.Stmts {
			w.visitStmt(stmt)
		}
	case *syntax.ProcSubst:
		w.shape.HasProcessSubstitution = true
		for _, stmt := range x.Stmts {
			w.visitStmt(stmt)
		}
	case *syntax.DblQuoted:
		for _, nested := range x.Parts {
			w.visitWordPart(nested)
		}
	case *syntax.ParamExp, *syntax.ArithmExp, *syntax.ExtGlob, *syntax.BraceExp:
		w.shape.Kind = ShellShapeUnknown
	}
}

func (w *planWalker) nodeRaw(node syntax.Node) string {
	if node == nil || !node.Pos().IsValid() || !node.End().IsValid() {
		return ""
	}
	start := int(node.Pos().Offset())
	end := int(node.End().Offset())
	if start < 0 || end < start || end > len(w.raw) {
		return ""
	}
	return strings.TrimSpace(w.raw[start:end])
}

func (s ShellShape) finalize() ShellShape {
	if s.Kind == ShellShapeUnknown {
		return s
	}
	if s.HasPipeline ||
		s.HasConditional ||
		s.HasSequence ||
		s.HasBackground ||
		s.HasRedirection ||
		s.HasSubshell ||
		s.HasCommandSubstitution ||
		s.HasProcessSubstitution {
		s.Kind = ShellShapeCompound
		return s
	}
	if s.Kind == "" {
		s.Kind = ShellShapeSimple
	}
	return s
}
