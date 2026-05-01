package command

import (
	"strings"

	"github.com/tasuku43/cc-bash-guard/internal/domain/invocation"
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
	ShapeFlags   []string

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
	AWS              *AWSSemantic
	Kubectl          *KubectlSemantic
	Gh               *GhSemantic
	Gws              *GwsSemantic
	Helm             *HelmSemantic
	Helmfile         *HelmfileSemantic
	ArgoCD           *ArgoCDSemantic
	Docker           *DockerSemantic
	Terraform        *TerraformSemantic
}

type Option struct {
	Name     string
	Value    string
	HasValue bool
	Position int
}

type GitSemantic struct {
	Verb            string
	Remote          string
	Branch          string
	Ref             string
	Force           bool
	ForceWithLease  bool
	ForceIfIncludes bool
	Hard            bool
	Recursive       bool
	IncludeIgnored  bool
	Cached          bool
	Staged          bool
	Flags           []string
}

type AWSSemantic struct {
	Service         string
	Operation       string
	Profile         string
	Region          string
	EndpointURL     string
	DryRun          *bool
	NoCLIPager      *bool
	Flags           []string
	ProfileConflict bool
	RegionSource    string
}

type KubectlSemantic struct {
	Verb          string
	Subverb       string
	ResourceType  string
	ResourceName  string
	Namespace     string
	Context       string
	Kubeconfig    string
	AllNamespaces bool
	DryRun        *bool
	Force         bool
	Recursive     bool
	Filenames     []string
	Selectors     []string
	Container     string
	Flags         []string
}

type GhSemantic struct {
	Area           string
	Verb           string
	Repo           string
	Hostname       string
	Org            string
	EnvName        string
	Web            bool
	Method         string
	Endpoint       string
	Paginate       bool
	Input          bool
	Silent         bool
	IncludeHeaders bool
	FieldKeys      []string
	RawFieldKeys   []string
	HeaderKeys     []string
	PRNumber       string
	IssueNumber    string
	SecretName     string
	Tag            string
	WorkflowName   string
	WorkflowID     string
	SearchType     string
	Query          string
	Base           string
	Head           string
	Ref            string
	State          string
	Labels         []string
	Assignees      []string
	Title          string
	Body           string
	Draft          bool
	Prerelease     bool
	Latest         bool
	Fill           bool
	Force          bool
	Admin          bool
	Auto           bool
	DeleteBranch   bool
	MergeStrategy  string
	RunID          string
	Failed         bool
	Job            string
	Debug          bool
	ExitStatus     bool
	Flags          []string
}

type GwsSemantic struct {
	Service      string
	ResourcePath []string
	Method       string
	Helper       bool
	Mutating     bool
	Destructive  bool
	ReadOnly     bool
	DryRun       bool
	PageAll      bool
	Upload       bool
	Sanitize     bool
	Params       bool
	JSONBody     bool
	Unmasked     bool
	Scopes       []string
	Flags        []string
}

type HelmSemantic struct {
	Verb                 string
	Subverb              string
	Release              string
	Chart                string
	Namespace            string
	KubeContext          string
	Kubeconfig           string
	DryRun               bool
	Force                bool
	Atomic               bool
	Wait                 bool
	WaitForJobs          bool
	Install              bool
	ReuseValues          bool
	ResetValues          bool
	ResetThenReuseValues bool
	CleanupOnFail        bool
	CreateNamespace      bool
	DependencyUpdate     bool
	Devel                bool
	KeepHistory          bool
	Cascade              string
	ValuesFiles          []string
	SetKeys              []string
	SetStringKeys        []string
	SetFileKeys          []string
	RepoName             string
	RepoURL              string
	Registry             string
	PluginName           string
	Flags                []string
}

type HelmfileSemantic struct {
	Verb                     string
	Environment              string
	Files                    []string
	Namespace                string
	KubeContext              string
	Selectors                []string
	Interactive              bool
	DryRun                   *bool
	Wait                     bool
	WaitForJobs              bool
	SkipDiff                 bool
	SkipNeeds                bool
	IncludeNeeds             bool
	IncludeTransitiveNeeds   bool
	Purge                    bool
	Cascade                  string
	DeleteWait               bool
	StateValuesFiles         []string
	StateValuesSetKeys       []string
	StateValuesSetStringKeys []string
	Flags                    []string
}

type ArgoCDSemantic struct {
	Verb     string
	AppName  string
	Project  string
	Revision string
	Flags    []string
}

type DockerSemantic struct {
	Verb              string
	Subverb           string
	ComposeCommand    string
	Image             string
	Container         string
	Service           string
	Context           string
	Host              string
	File              string
	Files             []string
	ProjectName       string
	Profile           string
	Profiles          []string
	DryRun            bool
	Detach            bool
	Interactive       bool
	Tty               bool
	RM                bool
	Force             bool
	Privileged        bool
	User              string
	Workdir           string
	Entrypoint        string
	Network           string
	NetworkHost       bool
	PID               string
	PIDHost           bool
	IPC               string
	IPCHost           bool
	UTS               string
	UTSHost           bool
	CapAdd            []string
	CapDrop           []string
	SecurityOpt       []string
	Device            bool
	Devices           []string
	Mounts            []string
	Volumes           []string
	HostMount         bool
	RootMount         bool
	DockerSocketMount bool
	EnvFiles          []string
	EnvKeys           []string
	Ports             []string
	PublishAll        bool
	Pull              string
	NoCache           bool
	BuildArgKeys      []string
	Target            string
	Platform          string
	All               bool
	VolumesFlag       bool
	Prune             bool
	AllResources      bool
	RemoveOrphans     bool
	Flags             []string
}

type TerraformSemantic struct {
	Subcommand          string
	GlobalChdir         string
	WorkspaceSubcommand string
	StateSubcommand     string
	ProvidersSubcommand string
	MetadataSubcommand  string
	Target              bool
	Targets             []string
	Replace             bool
	Replaces            []string
	Destroy             bool
	AutoApprove         bool
	Input               *bool
	Lock                *bool
	Refresh             *bool
	RefreshOnly         bool
	Out                 string
	PlanFile            string
	VarFiles            []string
	Vars                bool
	Backend             *bool
	Upgrade             bool
	Reconfigure         bool
	MigrateState        bool
	Recursive           bool
	Check               bool
	JSON                bool
	Force               bool
	Flags               []string
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
	Normalized             []NormalizedCommand
}

type NormalizedCommand struct {
	OriginalToken string
	CommandName   string
	Raw           string
	Reason        string
}

type ShellShape struct {
	Kind                   ShellShapeKind
	HasPipeline            bool
	HasConditional         bool
	HasSequence            bool
	HasBackground          bool
	HasRedirection         bool
	RedirectionFlags       []string
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
		plan.Diagnostics = append(plan.Diagnostics, Diagnostic{Severity: "error", Message: shellParseErrorMessage(raw, err)})
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
	plan.Diagnostics = append(plan.Diagnostics, walker.diagnostics...)
	plan.Normalized = append(plan.Normalized, walker.normalized...)
	// CommandPlan describes shell shape and CLI semantics; invocation owns the
	// safety gate used by allow-list matching.
	plan.SafeForStructuredAllow = plan.Shape.Kind == ShellShapeSimple &&
		len(plan.Commands) == 1 &&
		len(plan.Diagnostics) == 0 &&
		plan.structuredSafeForAllow()
	return plan
}

func shellParseErrorMessage(raw string, err error) string {
	message := err.Error()
	if strings.Contains(raw, "<") && strings.Contains(raw, ">") {
		message += "; if <id> is meant as a placeholder, replace it with a literal value such as 1abcDEF"
	}
	return message
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
	} else if !plan.structuredSafeForAllow() {
		reasons = append(reasons, "unsafe_ast")
	}

	return dedupeStrings(reasons)
}

func (p CommandPlan) structuredSafeForAllow() bool {
	if len(p.Shape.RedirectionFlags) == 0 {
		return invocation.IsStructuredSafeForAllow(p.Raw)
	}
	return false
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
	flags = append(flags, s.RedirectionFlags...)
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
	raw         string
	registry    *CommandParserRegistry
	shape       ShellShape
	commands    []Command
	diagnostics []Diagnostic
	normalized  []NormalizedCommand
	stmtFlags   []string
}

func (w *planWalker) visitStmt(stmt *syntax.Stmt) {
	if stmt == nil {
		return
	}
	if stmt.Background || stmt.Coprocess || stmt.Disown {
		w.shape.HasBackground = true
	}
	redirFlags := redirectionFlags(stmt.Redirs)
	if len(redirFlags) > 0 {
		w.shape.HasRedirection = true
	}
	w.shape.RedirectionFlags = append(w.shape.RedirectionFlags, redirFlags...)
	if len(stmt.Comments) > 0 || stmt.Negated {
		w.shape.Kind = ShellShapeUnknown
	}
	previousStmtFlags := w.stmtFlags
	w.stmtFlags = redirFlags
	w.visitCommand(stmt.Cmd)
	w.stmtFlags = previousStmtFlags
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
		cmd.ShapeFlags = append(cmd.ShapeFlags, w.stmtFlags...)
		if cmd.ProgramToken != "" && cmd.Program != cmd.ProgramToken {
			w.normalized = append(w.normalized, NormalizedCommand{
				OriginalToken: cmd.ProgramToken,
				CommandName:   cmd.Program,
				Raw:           cmd.Raw,
				Reason:        "basename",
			})
		}
		if inner, ok := shellDashCInnerCommand(cmd); ok {
			innerPlan := ParseWithRegistry(inner, w.registry)
			w.shape = mergeShellShape(w.shape, innerPlan.Shape)
			w.commands = append(w.commands, innerPlan.Commands...)
			w.diagnostics = append(w.diagnostics, innerPlan.Diagnostics...)
			w.normalized = append(w.normalized, innerPlan.Normalized...)
			w.normalized = append(w.normalized, NormalizedCommand{
				OriginalToken: cmd.ProgramToken,
				CommandName:   cmd.Program,
				Raw:           cmd.Raw,
				Reason:        "shell_dash_c",
			})
			return
		}
		if inner, ok := rtkProxyInnerCommand(cmd); ok {
			innerPlan := ParseWithRegistry(inner, w.registry)
			w.shape = mergeShellShape(w.shape, innerPlan.Shape)
			w.commands = append(w.commands, innerPlan.Commands...)
			w.diagnostics = append(w.diagnostics, innerPlan.Diagnostics...)
			w.normalized = append(w.normalized, innerPlan.Normalized...)
			w.normalized = append(w.normalized, NormalizedCommand{
				OriginalToken: cmd.ProgramToken,
				CommandName:   cmd.Program,
				Raw:           cmd.Raw,
				Reason:        "rtk_proxy",
			})
			return
		}
		w.commands = append(w.commands, cmd)
	}
}

func shellDashCInnerCommand(cmd Command) (string, bool) {
	if !isShellCommandName(cmd.Program) {
		return "", false
	}
	if len(cmd.RawWords) < 2 || cmd.RawWords[0] != "-c" {
		return "", false
	}
	return cmd.RawWords[1], true
}

func isShellCommandName(name string) bool {
	switch name {
	case "bash", "sh", "zsh", "dash", "ksh":
		return true
	default:
		return false
	}
}

func rtkProxyInnerCommand(cmd Command) (string, bool) {
	if cmd.Program != "rtk" || len(cmd.RawWords) < 2 || cmd.RawWords[0] != "proxy" {
		return "", false
	}
	innerWords := cmd.RawWords[1:]
	if innerWords[0] == "--" {
		innerWords = innerWords[1:]
	}
	if len(innerWords) == 0 {
		return "", false
	}
	return invocation.Join(innerWords), true
}

func mergeShellShape(a ShellShape, b ShellShape) ShellShape {
	if b.Kind == ShellShapeUnknown {
		a.Kind = ShellShapeUnknown
	}
	a.HasPipeline = a.HasPipeline || b.HasPipeline
	a.HasConditional = a.HasConditional || b.HasConditional
	a.HasSequence = a.HasSequence || b.HasSequence
	a.HasBackground = a.HasBackground || b.HasBackground
	a.HasRedirection = a.HasRedirection || b.HasRedirection
	a.RedirectionFlags = append(a.RedirectionFlags, b.RedirectionFlags...)
	a.HasSubshell = a.HasSubshell || b.HasSubshell
	a.HasCommandSubstitution = a.HasCommandSubstitution || b.HasCommandSubstitution
	a.HasProcessSubstitution = a.HasProcessSubstitution || b.HasProcessSubstitution
	return a
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
	s.RedirectionFlags = dedupeStrings(s.RedirectionFlags)
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

func redirectionFlags(redirs []*syntax.Redirect) []string {
	flags := make([]string, 0, len(redirs))
	for _, redir := range redirs {
		if redir == nil {
			continue
		}
		flags = append(flags, redirectionFlagsForRedirect(redir)...)
	}
	return dedupeStrings(flags)
}

func redirectionFlagsForRedirect(redir *syntax.Redirect) []string {
	switch redir.Op {
	case syntax.DplOut:
		if isFdWord(redir.Word) {
			return []string{"redirect_stream_merge"}
		}
		return []string{"redirect_output_dup"}
	case syntax.DplIn:
		if isFdWord(redir.Word) {
			return []string{"redirect_stream_merge"}
		}
		return []string{"redirect_input_dup"}
	case syntax.RdrOut, syntax.RdrClob, syntax.RdrAll, syntax.RdrAllClob:
		if isDevNullWord(redir.Word) {
			return devNullOutputRedirectFlags(redir)
		}
		return []string{"redirect_file_write"}
	case syntax.AppOut, syntax.AppClob, syntax.AppAll, syntax.AppAllClob:
		if isDevNullWord(redir.Word) {
			return devNullOutputRedirectFlags(redir)
		}
		return []string{"redirect_append_file"}
	case syntax.RdrIn, syntax.RdrInOut:
		if isDevNullWord(redir.Word) {
			return []string{"redirect_from_devnull", "stdin_from_devnull"}
		}
		return []string{"redirect_stdin_from_file"}
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		return []string{"redirect_heredoc"}
	default:
		return []string{"redirect_unknown"}
	}
}

func devNullOutputRedirectFlags(redir *syntax.Redirect) []string {
	flags := []string{"redirect_to_devnull"}
	if redir.Op == syntax.RdrAll || redir.Op == syntax.RdrAllClob || redir.Op == syntax.AppAll || redir.Op == syntax.AppAllClob {
		return append(flags, "stdout_to_devnull", "stderr_to_devnull")
	}
	switch redirectFD(redir) {
	case "2":
		return append(flags, "stderr_to_devnull")
	case "", "1":
		return append(flags, "stdout_to_devnull")
	default:
		return append(flags, "redirect_unknown")
	}
}

func redirectFD(redir *syntax.Redirect) string {
	if redir == nil || redir.N == nil {
		return ""
	}
	return redir.N.Value
}

func hasUnsafeRedirectionFlag(flags []string) bool {
	for _, flag := range flags {
		switch flag {
		case "redirect_stream_merge", "redirect_file_write", "redirect_append_file", "redirect_output_dup", "redirect_input_dup", "redirect_unknown":
			return true
		}
	}
	return false
}

func isFdWord(word *syntax.Word) bool {
	value, ok := literalWordValue(word)
	if !ok || value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isDevNullWord(word *syntax.Word) bool {
	value, ok := literalWordValue(word)
	return ok && value == "/dev/null"
}

func literalWordValue(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var b strings.Builder
	for _, part := range word.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		b.WriteString(lit.Value)
	}
	return b.String(), true
}
