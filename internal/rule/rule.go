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
	LayerProject = "project"
	LayerUser    = "user"
)

type File struct {
	Version int        `yaml:"version"`
	Rules   []RuleSpec `yaml:"rules"`
}

type RuleSpec struct {
	ID            string   `yaml:"id"`
	Pattern       string   `yaml:"pattern"`
	Message       string   `yaml:"message"`
	BlockExamples []string `yaml:"block_examples"`
	AllowExamples []string `yaml:"allow_examples"`
}

type Source struct {
	Layer string `json:"layer"`
	Path  string `json:"path"`
}

type Rule struct {
	RuleSpec
	Source Source `json:"source"`
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

func ConfigPaths(cwd string, home string, xdgConfigHome string) []Source {
	paths := []Source{
		{Layer: LayerProject, Path: filepath.Join(cwd, ".cmdguard.yml")},
	}

	userConfigBase := xdgConfigHome
	if userConfigBase == "" {
		userConfigBase = filepath.Join(home, ".config")
	}
	paths = append(paths, Source{
		Layer: LayerUser,
		Path:  filepath.Join(userConfigBase, "cmdguard", "cmdguard.yml"),
	})
	return paths
}

func LoadEffective(cwd string, home string, xdgConfigHome string) Loaded {
	var loaded Loaded
	for _, src := range ConfigPaths(cwd, home, xdgConfigHome) {
		rules, err := LoadFileIfPresent(src)
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
	data, err := os.ReadFile(src.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s config read failed: %w", src.Layer, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("%s config %s is empty", src.Layer, src.Path)
	}

	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)

	var file File
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("%s config %s is invalid: %w", src.Layer, src.Path, err)
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
		rules = append(rules, Rule{RuleSpec: spec, Source: src})
	}
	return rules, nil
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
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`).MatchString(r.ID) {
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
