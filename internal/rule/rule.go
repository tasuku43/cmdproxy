package rule

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	LayerUser = "user"
)

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type File struct {
	Version int        `yaml:"version"`
	Rules   []RuleSpec `yaml:"rules"`
}

type RuleSpec struct {
	ID            string    `yaml:"id"`
	Pattern       string    `yaml:"pattern"`
	Matcher       MatchSpec `yaml:"match"`
	Message       string    `yaml:"message"`
	BlockExamples []string  `yaml:"block_examples"`
	AllowExamples []string  `yaml:"allow_examples"`
}

type MatchSpec struct {
	Command      string   `yaml:"command" json:"command,omitempty"`
	CommandIn    []string `yaml:"command_in" json:"command_in,omitempty"`
	Subcommand   string   `yaml:"subcommand" json:"subcommand,omitempty"`
	ArgsContains []string `yaml:"args_contains" json:"args_contains,omitempty"`
	ArgsPrefixes []string `yaml:"args_prefixes" json:"args_prefixes,omitempty"`
	EnvRequires  []string `yaml:"env_requires" json:"env_requires,omitempty"`
	EnvMissing   []string `yaml:"env_missing" json:"env_missing,omitempty"`
}

type evalFile struct {
	Version int
	Rules   []evalRuleSpec
}

type evalRuleSpec struct {
	ID              string
	Pattern         string
	Match           MatchSpec
	Message         string
	BlockExampleLen int
	AllowExampleLen int
}

type evalCacheFile struct {
	Version       int              `json:"version"`
	SourcePath    string           `json:"source_path"`
	SourceSize    int64            `json:"source_size"`
	SourceModTime int64            `json:"source_mod_time"`
	CompiledRules []evalCachedRule `json:"compiled_rules"`
}

type evalCachedRule struct {
	ID      string    `json:"id"`
	Pattern string    `json:"pattern"`
	Match   MatchSpec `json:"match,omitempty"`
	Message string    `json:"message"`
}

type Source struct {
	Layer string `json:"layer"`
	Path  string `json:"path"`
}

type Rule struct {
	RuleSpec
	Source Source `json:"source"`
	re     *regexp.Regexp
}

type Loaded struct {
	Rules  []Rule
	Files  []Source
	Errors []error
}

type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Issues, "; ")
}

func ConfigPaths(home string, xdgConfigHome string) []Source {
	userConfigBase := xdgConfigHome
	if userConfigBase == "" {
		userConfigBase = filepath.Join(home, ".config")
	}
	return []Source{{
		Layer: LayerUser,
		Path:  filepath.Join(userConfigBase, "cmdguard", "cmdguard.yml"),
	}}
}

func CachePath(home string, xdgCacheHome string) string {
	cacheBase := xdgCacheHome
	if cacheBase == "" {
		cacheBase = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheBase, "cmdguard", "eval-cache-v1.json")
}

func LoadEffective(cwd string, home string, xdgConfigHome string) Loaded {
	return loadEffectiveWithLoader(home, xdgConfigHome, LoadFileIfPresent)
}

func LoadEffectiveForEval(home string, xdgConfigHome string, xdgCacheHome string) Loaded {
	loader := func(src Source) ([]Rule, error) {
		return LoadFileForEvalIfPresent(src, CachePath(home, xdgCacheHome))
	}
	return loadEffectiveWithLoader(home, xdgConfigHome, loader)
}

func loadEffectiveWithLoader(home string, xdgConfigHome string, loader func(Source) ([]Rule, error)) Loaded {
	var loaded Loaded
	for _, src := range ConfigPaths(home, xdgConfigHome) {
		rules, err := loader(src)
		if err != nil {
			loaded.Errors = append(loaded.Errors, err)
			continue
		}
		if len(rules) == 0 {
			continue
		}
		loaded.Files = append(loaded.Files, src)
		loaded.Rules = append(loaded.Rules, rules...)
	}

	dupErrs := validateDuplicateIDs(loaded.Rules)
	loaded.Errors = append(loaded.Errors, dupErrs...)
	return loaded
}

func LoadFileIfPresent(src Source) ([]Rule, error) {
	data, err := readConfigFile(src)
	if err != nil {
		return nil, err
	}
	if data == "" {
		return nil, nil
	}
	file, err := decodeFullFile(src, data)
	if err != nil {
		return nil, err
	}

	issues := validateFile(file)
	if len(issues) > 0 {
		for i := range issues {
			issues[i] = fmt.Sprintf("%s config %s: %s", src.Layer, src.Path, issues[i])
		}
		return nil, &ValidationError{Issues: issues}
	}

	rules := make([]Rule, 0, len(file.Rules))
	for _, spec := range file.Rules {
		rules = append(rules, newRule(spec, src))
	}
	return rules, nil
}

func LoadFileForEvalIfPresent(src Source, cachePath string) ([]Rule, error) {
	info, err := os.Stat(src.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s config read failed: %w", src.Layer, err)
	}
	if rules, ok := loadEvalCache(src, cachePath, info); ok {
		return rules, nil
	}

	data, err := readConfigFile(src)
	if err != nil {
		return nil, err
	}
	if data == "" {
		return nil, nil
	}
	file, err := decodeEvalFile(src, data)
	if err != nil {
		return nil, err
	}

	issues := validateEvalFile(file)
	if len(issues) > 0 {
		for i := range issues {
			issues[i] = fmt.Sprintf("%s config %s: %s", src.Layer, src.Path, issues[i])
		}
		return nil, &ValidationError{Issues: issues}
	}

	rules := make([]Rule, 0, len(file.Rules))
	cached := make([]evalCachedRule, 0, len(file.Rules))
	for _, spec := range file.Rules {
		ruleSpec := RuleSpec{
			ID:      spec.ID,
			Pattern: spec.Pattern,
			Matcher: spec.Match,
			Message: spec.Message,
		}
		rules = append(rules, newRule(ruleSpec, src))
		cached = append(cached, evalCachedRule{
			ID:      spec.ID,
			Pattern: spec.Pattern,
			Match:   spec.Match,
			Message: spec.Message,
		})
	}
	writeEvalCache(cachePath, evalCacheFile{
		Version:       1,
		SourcePath:    src.Path,
		SourceSize:    info.Size(),
		SourceModTime: info.ModTime().UnixNano(),
		CompiledRules: cached,
	})
	return rules, nil
}

func readConfigFile(src Source) (string, error) {
	data, err := os.ReadFile(src.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("%s config read failed: %w", src.Layer, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return "", fmt.Errorf("%s config %s is empty", src.Layer, src.Path)
	}
	return string(data), nil
}

func decodeFullFile(src Source, data string) (File, error) {
	dec := yaml.NewDecoder(strings.NewReader(data))
	dec.KnownFields(true)

	var file File
	if err := dec.Decode(&file); err != nil {
		return File{}, fmt.Errorf("%s config %s is invalid: %w", src.Layer, src.Path, err)
	}
	return file, nil
}

func decodeEvalFile(src Source, data string) (evalFile, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(data), &root); err != nil {
		return evalFile{}, fmt.Errorf("%s config %s is invalid: %w", src.Layer, src.Path, err)
	}
	if len(root.Content) == 0 {
		return evalFile{}, fmt.Errorf("%s config %s is invalid: empty YAML document", src.Layer, src.Path)
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return evalFile{}, fmt.Errorf("%s config %s is invalid: top-level must be a mapping", src.Layer, src.Path)
	}

	file := evalFile{}
	seenTopLevel := map[string]struct{}{}
	for i := 0; i < len(doc.Content); i += 2 {
		key := doc.Content[i]
		val := doc.Content[i+1]
		if _, ok := seenTopLevel[key.Value]; ok {
			continue
		}
		seenTopLevel[key.Value] = struct{}{}
		switch key.Value {
		case "version":
			if val.Kind != yaml.ScalarNode {
				return evalFile{}, fmt.Errorf("%s config %s is invalid: version must be a scalar", src.Layer, src.Path)
			}
			var version int
			if err := val.Decode(&version); err != nil {
				return evalFile{}, fmt.Errorf("%s config %s is invalid: version must be an integer", src.Layer, src.Path)
			}
			file.Version = version
		case "rules":
			rules, err := decodeEvalRules(src, val)
			if err != nil {
				return evalFile{}, err
			}
			file.Rules = rules
		default:
			return evalFile{}, fmt.Errorf("%s config %s is invalid: field %q not allowed", src.Layer, src.Path, key.Value)
		}
	}
	return file, nil
}

func decodeEvalRules(src Source, node *yaml.Node) ([]evalRuleSpec, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s config %s is invalid: rules must be a sequence", src.Layer, src.Path)
	}
	rules := make([]evalRuleSpec, 0, len(node.Content))
	for idx, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s config %s is invalid: rules[%d] must be a mapping", src.Layer, src.Path, idx)
		}
		ruleSpec, err := decodeEvalRule(src, idx, item)
		if err != nil {
			return nil, err
		}
		rules = append(rules, ruleSpec)
	}
	return rules, nil
}

func decodeEvalRule(src Source, idx int, node *yaml.Node) (evalRuleSpec, error) {
	var spec evalRuleSpec
	seenFields := map[string]struct{}{}
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		seenFields[key.Value] = struct{}{}
		switch key.Value {
		case "id":
			if val.Kind != yaml.ScalarNode {
				return evalRuleSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].id must be a string", src.Layer, src.Path, idx)
			}
			spec.ID = val.Value
		case "pattern":
			if val.Kind != yaml.ScalarNode {
				return evalRuleSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].pattern must be a string", src.Layer, src.Path, idx)
			}
			spec.Pattern = val.Value
		case "match":
			match, err := decodeEvalMatch(src, idx, val)
			if err != nil {
				return evalRuleSpec{}, err
			}
			spec.Match = match
		case "message":
			if val.Kind != yaml.ScalarNode {
				return evalRuleSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].message must be a string", src.Layer, src.Path, idx)
			}
			spec.Message = val.Value
		case "block_examples":
			if val.Kind != yaml.SequenceNode {
				return evalRuleSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].block_examples must be a sequence", src.Layer, src.Path, idx)
			}
			spec.BlockExampleLen = len(val.Content)
		case "allow_examples":
			if val.Kind != yaml.SequenceNode {
				return evalRuleSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].allow_examples must be a sequence", src.Layer, src.Path, idx)
			}
			spec.AllowExampleLen = len(val.Content)
		default:
			return evalRuleSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].%s not allowed", src.Layer, src.Path, idx, key.Value)
		}
	}
	return spec, nil
}

func decodeEvalMatch(src Source, idx int, node *yaml.Node) (MatchSpec, error) {
	if node.Kind != yaml.MappingNode {
		return MatchSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].match must be a mapping", src.Layer, src.Path, idx)
	}
	var match MatchSpec
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		switch key.Value {
		case "command":
			if val.Kind != yaml.ScalarNode {
				return MatchSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].match.command must be a string", src.Layer, src.Path, idx)
			}
			match.Command = val.Value
		case "command_in":
			values, err := decodeStringSequence(src, idx, "match.command_in", val)
			if err != nil {
				return MatchSpec{}, err
			}
			match.CommandIn = values
		case "subcommand":
			if val.Kind != yaml.ScalarNode {
				return MatchSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].match.subcommand must be a string", src.Layer, src.Path, idx)
			}
			match.Subcommand = val.Value
		case "args_contains":
			values, err := decodeStringSequence(src, idx, "match.args_contains", val)
			if err != nil {
				return MatchSpec{}, err
			}
			match.ArgsContains = values
		case "args_prefixes":
			values, err := decodeStringSequence(src, idx, "match.args_prefixes", val)
			if err != nil {
				return MatchSpec{}, err
			}
			match.ArgsPrefixes = values
		case "env_requires":
			values, err := decodeStringSequence(src, idx, "match.env_requires", val)
			if err != nil {
				return MatchSpec{}, err
			}
			match.EnvRequires = values
		case "env_missing":
			values, err := decodeStringSequence(src, idx, "match.env_missing", val)
			if err != nil {
				return MatchSpec{}, err
			}
			match.EnvMissing = values
		default:
			return MatchSpec{}, fmt.Errorf("%s config %s is invalid: rules[%d].match.%s not allowed", src.Layer, src.Path, idx, key.Value)
		}
	}
	return match, nil
}

func decodeStringSequence(src Source, idx int, field string, node *yaml.Node) ([]string, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s config %s is invalid: rules[%d].%s must be a sequence", src.Layer, src.Path, idx, field)
	}
	values := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%s config %s is invalid: rules[%d].%s must contain only strings", src.Layer, src.Path, idx, field)
		}
		values = append(values, item.Value)
	}
	return values, nil
}

func validateFile(file File) []string {
	var issues []string
	if file.Version != 1 {
		issues = append(issues, "version must be 1")
	}
	if len(file.Rules) == 0 {
		issues = append(issues, "rules must be non-empty")
	}

	seen := map[string]struct{}{}
	for i, r := range file.Rules {
		prefix := fmt.Sprintf("rules[%d]", i)
		if !ruleIDPattern.MatchString(r.ID) {
			issues = append(issues, prefix+".id must match [a-z0-9][a-z0-9-]*")
		}
		if _, ok := seen[r.ID]; ok && r.ID != "" {
			issues = append(issues, prefix+".id duplicates another rule in the same file")
		}
		seen[r.ID] = struct{}{}
		issues = append(issues, validateRuleMatcher(prefix, r.Pattern, r.Matcher)...)
		if strings.TrimSpace(r.Message) == "" {
			issues = append(issues, prefix+".message must be non-empty")
		}
		if len(r.BlockExamples) == 0 {
			issues = append(issues, prefix+".block_examples must be non-empty")
		}
		if len(r.AllowExamples) == 0 {
			issues = append(issues, prefix+".allow_examples must be non-empty")
		}
	}

	return issues
}

func validateEvalFile(file evalFile) []string {
	var issues []string
	if file.Version != 1 {
		issues = append(issues, "version must be 1")
	}
	if len(file.Rules) == 0 {
		issues = append(issues, "rules must be non-empty")
	}

	seen := map[string]struct{}{}
	for i, r := range file.Rules {
		prefix := fmt.Sprintf("rules[%d]", i)
		if !ruleIDPattern.MatchString(r.ID) {
			issues = append(issues, prefix+".id must match [a-z0-9][a-z0-9-]*")
		}
		if _, ok := seen[r.ID]; ok && r.ID != "" {
			issues = append(issues, prefix+".id duplicates another rule in the same file")
		}
		seen[r.ID] = struct{}{}
		issues = append(issues, validateRuleMatcher(prefix, r.Pattern, r.Match)...)
		if strings.TrimSpace(r.Message) == "" {
			issues = append(issues, prefix+".message must be non-empty")
		}
		if r.BlockExampleLen == 0 {
			issues = append(issues, prefix+".block_examples must be non-empty")
		}
		if r.AllowExampleLen == 0 {
			issues = append(issues, prefix+".allow_examples must be non-empty")
		}
	}

	return issues
}

func (r Rule) Match(command string) (bool, error) {
	if !isZeroMatchSpec(r.Matcher) {
		return r.Matcher.matches(ParseCommand(command)), nil
	}
	if r.re != nil {
		return r.re.MatchString(command), nil
	}
	compiled, err := regexp.Compile(r.Pattern)
	if err != nil {
		return false, err
	}
	return compiled.MatchString(command), nil
}

func (m MatchSpec) matches(parsed ParsedCommand) bool {
	if parsed.Command == "" {
		return false
	}
	if m.Command != "" && parsed.Command != m.Command {
		return false
	}
	if len(m.CommandIn) > 0 && !containsString(m.CommandIn, parsed.Command) {
		return false
	}
	if m.Subcommand != "" && parsed.Subcommand != m.Subcommand {
		return false
	}
	for _, arg := range m.ArgsContains {
		if !containsString(parsed.Args, arg) {
			return false
		}
	}
	for _, prefix := range m.ArgsPrefixes {
		if !containsPrefix(parsed.Args, prefix) {
			return false
		}
	}
	for _, env := range m.EnvRequires {
		if _, ok := parsed.EnvAssignments[env]; !ok {
			return false
		}
	}
	for _, env := range m.EnvMissing {
		if _, ok := parsed.EnvAssignments[env]; ok {
			return false
		}
	}
	return true
}

func validateRuleMatcher(prefix string, pattern string, match MatchSpec) []string {
	var issues []string
	hasPattern := strings.TrimSpace(pattern) != ""
	hasMatch := !isZeroMatchSpec(match)

	switch {
	case hasPattern && hasMatch:
		issues = append(issues, prefix+" must not set both pattern and match")
	case !hasPattern && !hasMatch:
		issues = append(issues, prefix+" must set exactly one of pattern or match")
	case hasPattern:
		if _, err := regexp.Compile(pattern); err != nil {
			issues = append(issues, prefix+".pattern failed to compile: "+err.Error())
		}
	case hasMatch:
		issues = append(issues, validateMatchSpec(prefix+".match", match)...)
	}
	return issues
}

func validateMatchSpec(prefix string, match MatchSpec) []string {
	var issues []string
	if isZeroMatchSpec(match) {
		return []string{prefix + " must not be empty"}
	}
	if strings.TrimSpace(match.Command) == "" && match.Command != "" {
		issues = append(issues, prefix+".command must be non-empty")
	}
	if strings.TrimSpace(match.Subcommand) == "" && match.Subcommand != "" {
		issues = append(issues, prefix+".subcommand must be non-empty")
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".command_in", match.CommandIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".args_contains", match.ArgsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".args_prefixes", match.ArgsPrefixes)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".env_requires", match.EnvRequires)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".env_missing", match.EnvMissing)...)
	return issues
}

func validateNonEmptyStrings(prefix string, values []string) []string {
	var issues []string
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, fmt.Sprintf("%s[%d] must be non-empty", prefix, i))
		}
	}
	return issues
}

func isZeroMatchSpec(match MatchSpec) bool {
	return match.Command == "" &&
		len(match.CommandIn) == 0 &&
		match.Subcommand == "" &&
		len(match.ArgsContains) == 0 &&
		len(match.ArgsPrefixes) == 0 &&
		len(match.EnvRequires) == 0 &&
		len(match.EnvMissing) == 0
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func newRule(spec RuleSpec, src Source) Rule {
	r := Rule{RuleSpec: spec, Source: src}
	if strings.TrimSpace(spec.Pattern) != "" {
		r.re, _ = regexp.Compile(spec.Pattern)
	}
	return r
}

func validateDuplicateIDs(rules []Rule) []error {
	seen := map[string]Source{}
	var errs []error
	for _, r := range rules {
		if prev, ok := seen[r.ID]; ok {
			errs = append(errs, fmt.Errorf("duplicate rule id %q across %s and %s", r.ID, prev.Path, r.Source.Path))
			continue
		}
		seen[r.ID] = r.Source
	}
	return errs
}

func ErrorStrings(errs []error) []string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			parts = append(parts, ve.Issues...)
			continue
		}
		parts = append(parts, err.Error())
	}
	slices.Sort(parts)
	return parts
}

func loadEvalCache(src Source, cachePath string, info os.FileInfo) ([]Rule, bool) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false
	}
	var cache evalCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, false
	}
	if cache.Version != 1 || cache.SourcePath != src.Path || cache.SourceSize != info.Size() || cache.SourceModTime != info.ModTime().UnixNano() {
		return nil, false
	}
	rules := make([]Rule, 0, len(cache.CompiledRules))
	for _, spec := range cache.CompiledRules {
		if strings.TrimSpace(spec.Pattern) != "" {
			if _, err := regexp.Compile(spec.Pattern); err != nil {
				return nil, false
			}
		}
		rules = append(rules, newRule(RuleSpec{
			ID:      spec.ID,
			Pattern: spec.Pattern,
			Matcher: spec.Match,
			Message: spec.Message,
		}, src))
	}
	return rules, true
}

func writeEvalCache(cachePath string, cache evalCacheFile) {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return
	}
	_ = os.WriteFile(cachePath, data, 0o644)
}
