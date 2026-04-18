package rule

import (
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

type evalFile struct {
	Version int            `yaml:"version"`
	Rules   []evalRuleSpec `yaml:"rules"`
}

type RuleSpec struct {
	ID            string   `yaml:"id"`
	Pattern       string   `yaml:"pattern"`
	Message       string   `yaml:"message"`
	BlockExamples []string `yaml:"block_examples"`
	AllowExamples []string `yaml:"allow_examples"`
}

type evalRuleSpec struct {
	ID            string         `yaml:"id"`
	Pattern       string         `yaml:"pattern"`
	Message       string         `yaml:"message"`
	BlockExamples skipStringList `yaml:"block_examples"`
	AllowExamples skipStringList `yaml:"allow_examples"`
}

type skipStringList struct {
	Count int
}

func (l *skipStringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("must be a YAML sequence")
	}
	l.Count = len(node.Content)
	return nil
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

func LoadEffective(cwd string, home string, xdgConfigHome string) Loaded {
	return loadEffectiveWithLoader(home, xdgConfigHome, LoadFileIfPresent)
}

func LoadEffectiveForEval(home string, xdgConfigHome string) Loaded {
	return loadEffectiveWithLoader(home, xdgConfigHome, LoadFileForEvalIfPresent)
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
		compiled, _ := regexp.Compile(spec.Pattern)
		rules = append(rules, Rule{RuleSpec: spec, Source: src, re: compiled})
	}
	return rules, nil
}

func LoadFileForEvalIfPresent(src Source) ([]Rule, error) {
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
	for _, spec := range file.Rules {
		compiled, _ := regexp.Compile(spec.Pattern)
		rules = append(rules, Rule{
			RuleSpec: RuleSpec{
				ID:      spec.ID,
				Pattern: spec.Pattern,
				Message: spec.Message,
			},
			Source: src,
			re:     compiled,
		})
	}
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
	dec := yaml.NewDecoder(strings.NewReader(data))
	dec.KnownFields(true)

	var file evalFile
	if err := dec.Decode(&file); err != nil {
		return evalFile{}, fmt.Errorf("%s config %s is invalid: %w", src.Layer, src.Path, err)
	}
	return file, nil
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
		if strings.TrimSpace(r.Pattern) == "" {
			issues = append(issues, prefix+".pattern must be non-empty")
		} else if _, err := regexp.Compile(r.Pattern); err != nil {
			issues = append(issues, prefix+".pattern failed to compile: "+err.Error())
		}
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
		if strings.TrimSpace(r.Pattern) == "" {
			issues = append(issues, prefix+".pattern must be non-empty")
		} else if _, err := regexp.Compile(r.Pattern); err != nil {
			issues = append(issues, prefix+".pattern failed to compile: "+err.Error())
		}
		if strings.TrimSpace(r.Message) == "" {
			issues = append(issues, prefix+".message must be non-empty")
		}
		if r.BlockExamples.Count == 0 {
			issues = append(issues, prefix+".block_examples must be non-empty")
		}
		if r.AllowExamples.Count == 0 {
			issues = append(issues, prefix+".allow_examples must be non-empty")
		}
	}

	return issues
}

func (r Rule) Match(command string) (bool, error) {
	if r.re != nil {
		return r.re.MatchString(command), nil
	}
	compiled, err := regexp.Compile(r.Pattern)
	if err != nil {
		return false, err
	}
	return compiled.MatchString(command), nil
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
