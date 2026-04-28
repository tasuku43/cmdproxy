package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tasuku43/cc-bash-guard/internal/adapter/claude"
	"github.com/tasuku43/cc-bash-guard/internal/domain/policy"
	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
	"gopkg.in/yaml.v3"
)

const LayerUser = "user"
const LayerProject = "project"

const EvaluationSemanticsVersion = 3

type File = policy.PipelineSpec

type Source = policy.Source

type Loaded struct {
	Pipeline policy.Pipeline
	Files    []Source
	Errors   []error
}

type evalCacheFile struct {
	Version                    int                 `json:"version"`
	Tool                       string              `json:"tool"`
	Fingerprint                string              `json:"fingerprint"`
	SourcePath                 string              `json:"source_path,omitempty"`
	SourceHash                 string              `json:"source_hash,omitempty"`
	SourcePaths                []string            `json:"source_paths,omitempty"`
	SettingsPaths              []string            `json:"settings_paths,omitempty"`
	CmdproxyVersion            string              `json:"cmdproxy_version,omitempty"`
	EvaluationSemanticsVersion int                 `json:"evaluation_semantics_version"`
	VerifiedAt                 string              `json:"verified_at,omitempty"`
	Pipeline                   policy.PipelineSpec `json:"pipeline"`
}

type EffectiveArtifactStatus struct {
	Exists     bool
	Compatible bool
	Path       string
	Message    string
}

func ConfigPaths(home string, xdgConfigHome string) []Source {
	userConfigBase := xdgConfigHome
	if userConfigBase == "" {
		userConfigBase = filepath.Join(home, ".config")
	}
	return []Source{{
		Layer: LayerUser,
		Path:  filepath.Join(userConfigBase, "cc-bash-guard", "cc-bash-guard.yml"),
	}}
}

type EffectiveInputs struct {
	Tool          string
	ConfigSources []Source
	ConfigFiles   []Source
	SettingsPaths []string
	Fingerprint   string
}

func ResolveEffectiveInputs(cwd string, home string, xdgConfigHome string, tool string) EffectiveInputs {
	configSources := configSources(cwd, home, xdgConfigHome, tool)
	settingsPaths := existingPaths(settingsPaths(tool, cwd, home))
	configFiles := configDependencySources(configSources)
	fingerprint := effectiveFingerprint(tool, configFiles, settingsPaths)
	return EffectiveInputs{
		Tool:          tool,
		ConfigSources: configSources,
		ConfigFiles:   configFiles,
		SettingsPaths: settingsPaths,
		Fingerprint:   fingerprint,
	}
}

func HookCacheDir(home string, xdgCacheHome string) string {
	dirs := HookCacheDirs(home, xdgCacheHome)
	if len(dirs) == 0 {
		return filepath.Join(home, ".cache", "cc-bash-guard")
	}
	return dirs[0]
}

func HookCacheDirs(home string, xdgCacheHome string) []string {
	seen := map[string]struct{}{}
	var dirs []string
	add := func(base string) {
		if strings.TrimSpace(base) == "" {
			return
		}
		path := filepath.Join(base, "cc-bash-guard")
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		dirs = append(dirs, path)
	}
	add(xdgCacheHome)
	add(filepath.Join(home, ".cache"))
	return dirs
}

func LoadEffective(home string, xdgConfigHome string) Loaded {
	return loadEffectiveWithLoader(home, xdgConfigHome, LoadFileIfPresent)
}

func LoadEffectiveForTool(cwd string, home string, xdgConfigHome string, tool string) Loaded {
	return loadEffectiveWithSources(ResolveEffectiveInputs(cwd, home, xdgConfigHome, tool).ConfigSources, LoadFileIfPresent)
}

func LoadEffectiveForHook(home string, xdgConfigHome string, xdgCacheHome string) Loaded {
	loader := func(src Source) (policy.Pipeline, error) {
		return LoadVerifiedFileForHook(src, HookCacheDirs(home, xdgCacheHome))
	}
	return loadEffectiveWithLoader(home, xdgConfigHome, loader)
}

func LoadEffectiveForHookTool(cwd string, home string, xdgConfigHome string, xdgCacheHome string, tool string) Loaded {
	inputs := ResolveEffectiveInputs(cwd, home, xdgConfigHome, tool)
	loader := func(src Source) (policy.Pipeline, error) {
		return loadVerifiedEffectivePipeline(inputs, HookCacheDirs(home, xdgCacheHome))
	}
	return loadEffectiveWithSources([]Source{loadOnceSource(inputs)}, loader)
}

func loadEffectiveWithLoader(home string, xdgConfigHome string, loader func(Source) (policy.Pipeline, error)) Loaded {
	var loaded Loaded
	for _, src := range ConfigPaths(home, xdgConfigHome) {
		pipeline, err := loader(src)
		if err != nil {
			loaded.Errors = append(loaded.Errors, err)
			continue
		}
		if isZeroPipeline(pipeline.PipelineSpec) {
			continue
		}
		loaded.Files = append(loaded.Files, src)
		loaded.Pipeline = pipeline
	}
	return loaded
}

func loadEffectiveWithSources(sources []Source, loader func(Source) (policy.Pipeline, error)) Loaded {
	var loaded Loaded
	for _, src := range sources {
		pipeline, err := loader(src)
		if err != nil {
			loaded.Errors = append(loaded.Errors, err)
			continue
		}
		if isZeroPipeline(pipeline.PipelineSpec) {
			continue
		}
		loaded.Files = append(loaded.Files, src)
		loaded.Pipeline = mergePipelines(loaded.Pipeline, pipeline)
	}
	return loaded
}

func LoadFileIfPresent(src Source) (policy.Pipeline, error) {
	file, _, err := loadFileWithIncludes(src)
	if err != nil {
		return policy.Pipeline{}, err
	}
	if isZeroPipeline(file) {
		return policy.Pipeline{}, nil
	}
	issues := validateFileWithSources(file)
	if len(issues) > 0 {
		return policy.Pipeline{}, &policy.ValidationError{Issues: issues}
	}
	return policy.NewPipeline(file, src), nil
}

func LoadFileForEvalIfPresent(src Source, cacheDir string) (policy.Pipeline, error) {
	return loadFileForEval(src, cacheDir, false, "")
}

func LoadVerifiedFileForHook(src Source, cacheDirs []string) (policy.Pipeline, error) {
	return loadVerifiedFileForHook(src, cacheDirs)
}

func VerifyFile(src Source, cacheDir string, cmdproxyVersion string) (policy.Pipeline, error) {
	return compileAndWriteEvalFile(src, cacheDir, cmdproxyVersion)
}

func VerifyFileToAllCaches(src Source, cacheDirs []string, cmdproxyVersion string) (policy.Pipeline, error) {
	var pipeline policy.Pipeline
	var errs []string
	success := false
	for i, cacheDir := range cacheDirs {
		loaded, err := compileAndWriteEvalFile(src, cacheDir, cmdproxyVersion)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if !success || i == 0 {
			pipeline = loaded
		}
		success = true
	}
	if !success {
		if len(errs) == 0 {
			return policy.Pipeline{}, fmt.Errorf("failed to write verified artifacts")
		}
		return policy.Pipeline{}, errors.New(strings.Join(errs, "; "))
	}
	return pipeline, nil
}

func VerifyEffectiveToAllCaches(cwd string, home string, xdgConfigHome string, xdgCacheHome string, tool string, cmdproxyVersion string) (policy.Pipeline, error) {
	inputs := ResolveEffectiveInputs(cwd, home, xdgConfigHome, tool)
	pipeline, err := compileEffectivePipeline(inputs)
	if err != nil {
		return policy.Pipeline{}, err
	}
	cache := evalCacheFile{
		Version:                    2,
		Tool:                       tool,
		Fingerprint:                inputs.Fingerprint,
		SourcePaths:                sourcePaths(inputs.ConfigFiles),
		SettingsPaths:              inputs.SettingsPaths,
		CmdproxyVersion:            cmdproxyVersion,
		EvaluationSemanticsVersion: EvaluationSemanticsVersion,
		VerifiedAt:                 time.Now().UTC().Format(time.RFC3339),
		Pipeline:                   pipeline.PipelineSpec,
	}
	var errs []string
	success := false
	for _, cacheDir := range HookCacheDirs(home, xdgCacheHome) {
		cachePath := effectiveCachePath(cacheDir, tool, inputs.Fingerprint)
		if err := writeEvalCache(cachePath, cache); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		pruneOldEffectiveCaches(cacheDir, tool, cachePath)
		success = true
	}
	if !success {
		if len(errs) == 0 {
			return policy.Pipeline{}, fmt.Errorf("failed to write verified artifacts")
		}
		return policy.Pipeline{}, errors.New(strings.Join(errs, "; "))
	}
	return pipeline, nil
}

func VerifiedEffectiveArtifactExists(cwd string, home string, xdgConfigHome string, xdgCacheHome string, tool string) bool {
	return VerifiedEffectiveArtifactStatus(cwd, home, xdgConfigHome, xdgCacheHome, tool).Compatible
}

func VerifiedEffectiveArtifactStatus(cwd string, home string, xdgConfigHome string, xdgCacheHome string, tool string) EffectiveArtifactStatus {
	inputs := ResolveEffectiveInputs(cwd, home, xdgConfigHome, tool)
	for _, cacheDir := range HookCacheDirs(home, xdgCacheHome) {
		cachePath := effectiveCachePath(cacheDir, tool, inputs.Fingerprint)
		if _, ok, err := loadEffectiveEvalCache(cachePath, inputs); ok {
			return EffectiveArtifactStatus{Exists: true, Compatible: true, Path: cachePath, Message: "verified artifact is compatible"}
		} else if err != nil {
			return EffectiveArtifactStatus{Exists: true, Compatible: false, Path: cachePath, Message: err.Error()}
		}
	}
	return EffectiveArtifactStatus{Exists: false, Compatible: false, Message: "verified artifact not found; run cc-bash-guard verify"}
}

func loadFileForEval(src Source, cacheDir string, requireVerified bool, cmdproxyVersion string) (policy.Pipeline, error) {
	file, files, err := loadFileWithIncludes(src)
	if err != nil {
		return policy.Pipeline{}, err
	}
	if isZeroPipeline(file) {
		return policy.Pipeline{}, nil
	}
	sourceHash := configSourcesHash(files)
	cachePath := cachePathForHash(cacheDir, sourceHash)
	if pipeline, ok, err := loadEvalCache(src, cachePath, sourceHash, requireVerified); err != nil {
		return policy.Pipeline{}, err
	} else if ok {
		return pipeline, nil
	}
	if requireVerified {
		return policy.Pipeline{}, fmt.Errorf("%s config %s or included policy files changed since last verify; run cc-bash-guard verify. Included policy files are part of the verified artifact.", src.Layer, src.Path)
	}
	return compileEvalFile(src, cacheDir, cmdproxyVersion, file, files, sourceHash)
}

func compileAndWriteEvalFile(src Source, cacheDir string, cmdproxyVersion string) (policy.Pipeline, error) {
	file, files, err := loadFileWithIncludes(src)
	if err != nil {
		return policy.Pipeline{}, err
	}
	if isZeroPipeline(file) {
		return policy.Pipeline{}, nil
	}
	sourceHash := configSourcesHash(files)
	return compileEvalFile(src, cacheDir, cmdproxyVersion, file, files, sourceHash)
}

func compileEvalFile(src Source, cacheDir string, cmdproxyVersion string, file policy.PipelineSpec, files []Source, sourceHash string) (policy.Pipeline, error) {
	issues := validateFileWithSources(file)
	if len(issues) > 0 {
		return policy.Pipeline{}, &policy.ValidationError{Issues: issues}
	}
	cachePath := cachePathForHash(cacheDir, sourceHash)
	if err := writeEvalCache(cachePath, evalCacheFile{
		Version:                    1,
		SourcePath:                 src.Path,
		SourceHash:                 sourceHash,
		CmdproxyVersion:            cmdproxyVersion,
		EvaluationSemanticsVersion: EvaluationSemanticsVersion,
		VerifiedAt:                 time.Now().UTC().Format(time.RFC3339),
		SourcePaths:                sourcePaths(files),
		Pipeline:                   file,
	}); err != nil {
		return policy.Pipeline{}, err
	}
	pruneOldEvalCaches(cacheDir, cachePath)
	return policy.NewPipeline(file, src), nil
}

func loadVerifiedFileForHook(src Source, cacheDirs []string) (policy.Pipeline, error) {
	file, files, err := loadFileWithIncludes(src)
	if err != nil {
		return policy.Pipeline{}, err
	}
	if isZeroPipeline(file) {
		return policy.Pipeline{}, nil
	}
	sourceHash := configSourcesHash(files)
	for _, cacheDir := range cacheDirs {
		cachePath := cachePathForHash(cacheDir, sourceHash)
		if pipeline, ok, err := loadEvalCache(src, cachePath, sourceHash, true); err != nil {
			return policy.Pipeline{}, err
		} else if ok {
			return pipeline, nil
		}
	}
	return policy.Pipeline{}, fmt.Errorf("%s config %s or included policy files changed since last verify; verified artifact not found in %s; run cc-bash-guard verify. Included policy files are part of the verified artifact.", src.Layer, src.Path, strings.Join(cacheDirs, ", "))
}

func loadVerifiedEffectivePipeline(inputs EffectiveInputs, cacheDirs []string) (policy.Pipeline, error) {
	for _, cacheDir := range cacheDirs {
		cachePath := effectiveCachePath(cacheDir, inputs.Tool, inputs.Fingerprint)
		if pipeline, ok, err := loadEffectiveEvalCache(cachePath, inputs); err != nil {
			return policy.Pipeline{}, err
		} else if ok {
			return pipeline, nil
		}
	}
	return policy.Pipeline{}, fmt.Errorf("effective config for %s changed since last verify; verified artifact not found in %s; run cc-bash-guard verify. Included policy files are part of the verified artifact.", inputs.Tool, strings.Join(cacheDirs, ", "))
}

func decodeFile(src Source, data string) (File, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(data), &root); err != nil {
		return File{}, fmt.Errorf("%s config %s is invalid: %w", src.Layer, src.Path, err)
	}
	if yamlMappingHasKey(root, "claude_permission_merge_mode") {
		return File{}, fmt.Errorf("%s config %s is invalid: claude_permission_merge_mode is no longer supported; permission sources are merged using deny > ask > allow > abstain.", src.Layer, src.Path)
	}
	if issues := validateSemanticYAML(root); len(issues) > 0 {
		return File{}, fmt.Errorf("%s config %s is invalid: %s", src.Layer, src.Path, strings.Join(issues, "; "))
	}
	dec := yaml.NewDecoder(strings.NewReader(data))
	dec.KnownFields(true)
	var file File
	if err := dec.Decode(&file); err != nil {
		return File{}, fmt.Errorf("%s config %s is invalid: %w", src.Layer, src.Path, err)
	}
	return file, nil
}

type loadedConfigFile struct {
	Source Source
	File   File
}

func loadFileWithIncludes(src Source) (File, []Source, error) {
	data, err := readConfigFile(src)
	if err != nil {
		return File{}, nil, err
	}
	if data == "" {
		return File{}, nil, nil
	}
	rootPath, err := filepath.Abs(src.Path)
	if err != nil {
		return File{}, nil, fmt.Errorf("%s config %s is invalid: %w", src.Layer, src.Path, err)
	}
	loaded, err := resolveIncludes(Source{Layer: src.Layer, Path: rootPath}, map[string]int{}, nil)
	if err != nil {
		return File{}, nil, err
	}
	var effective File
	files := make([]Source, 0, len(loaded))
	for _, entry := range loaded {
		files = append(files, entry.Source)
		effective = mergeSpecs(effective, stampFileSources(entry.File, entry.Source))
	}
	effective.Include = nil
	return effective, files, nil
}

func resolveIncludes(src Source, visiting map[string]int, stack []string) ([]loadedConfigFile, error) {
	path := filepath.Clean(src.Path)
	if idx, ok := visiting[path]; ok {
		chain := append(append([]string{}, stack[idx:]...), path)
		return nil, fmt.Errorf("include cycle detected:\n  %s", strings.Join(chain, "\n  "))
	}
	if err := validateIncludedPath(src); err != nil {
		return nil, err
	}
	data, err := readRequiredConfigFile(src)
	if err != nil {
		return nil, err
	}
	file, err := decodeFile(src, data)
	if err != nil {
		return nil, err
	}
	visiting[path] = len(stack)
	stack = append(stack, path)
	var loaded []loadedConfigFile
	for i, include := range file.Include {
		include = strings.TrimSpace(include)
		if include == "" {
			return nil, fmt.Errorf("%s config %s include[%d] must be non-empty", src.Layer, src.Path, i)
		}
		if strings.Contains(include, "://") {
			return nil, fmt.Errorf("%s config %s include[%d] must be a local file path, got %q", src.Layer, src.Path, i, include)
		}
		includePath := include
		if !filepath.IsAbs(includePath) {
			includePath = filepath.Join(filepath.Dir(path), includePath)
		}
		includePath, err = filepath.Abs(includePath)
		if err != nil {
			return nil, fmt.Errorf("%s config %s include[%d] is invalid: %w", src.Layer, src.Path, i, err)
		}
		child := Source{Layer: src.Layer, Path: filepath.Clean(includePath)}
		childLoaded, err := resolveIncludes(child, visiting, stack)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, childLoaded...)
	}
	delete(visiting, path)
	file.Include = nil
	loaded = append(loaded, loadedConfigFile{Source: src, File: file})
	return loaded, nil
}

func validateIncludedPath(src Source) error {
	fi, err := os.Stat(src.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s config include file missing: %s", src.Layer, src.Path)
		}
		return fmt.Errorf("%s config include file %s could not be read: %w", src.Layer, src.Path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s config include path must be a regular file: %s", src.Layer, src.Path)
	}
	return nil
}

func readRequiredConfigFile(src Source) (string, error) {
	data, err := os.ReadFile(src.Path)
	if err != nil {
		return "", fmt.Errorf("%s config read failed: %w", src.Layer, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return "", fmt.Errorf("%s config %s is empty", src.Layer, src.Path)
	}
	return string(data), nil
}

func stampFileSources(file File, src Source) File {
	for i := range file.Permission.Deny {
		if file.Permission.Deny[i].Source == (Source{}) {
			file.Permission.Deny[i].Source = Source{Layer: src.Layer, Path: src.Path, Section: "permission.deny", Index: i}
		}
	}
	for i := range file.Permission.Ask {
		if file.Permission.Ask[i].Source == (Source{}) {
			file.Permission.Ask[i].Source = Source{Layer: src.Layer, Path: src.Path, Section: "permission.ask", Index: i}
		}
	}
	for i := range file.Permission.Allow {
		if file.Permission.Allow[i].Source == (Source{}) {
			file.Permission.Allow[i].Source = Source{Layer: src.Layer, Path: src.Path, Section: "permission.allow", Index: i}
		}
	}
	for i := range file.Test {
		if file.Test[i].Source == (Source{}) {
			file.Test[i].Source = Source{Layer: src.Layer, Path: src.Path, Section: "test", Index: i}
		}
	}
	return file
}

func mergeSpecs(base File, next File) File {
	base.Rewrite = append(base.Rewrite, next.Rewrite...)
	base.Permission.Deny = append(base.Permission.Deny, next.Permission.Deny...)
	base.Permission.Ask = append(base.Permission.Ask, next.Permission.Ask...)
	base.Permission.Allow = append(base.Permission.Allow, next.Permission.Allow...)
	base.Test = append(base.Test, next.Test...)
	return base
}

func validateSemanticYAML(root yaml.Node) []string {
	doc := &root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return nil
	}
	permission := yamlMapValue(doc, "permission")
	if permission == nil || permission.Kind != yaml.MappingNode {
		return nil
	}
	var issues []string
	for _, bucket := range []string{"deny", "ask", "allow"} {
		rules := yamlMapValue(permission, bucket)
		if rules == nil || rules.Kind != yaml.SequenceNode {
			continue
		}
		for i, rule := range rules.Content {
			prefix := fmt.Sprintf("permission.%s[%d].command", bucket, i)
			issues = append(issues, validatePermissionCommandSemanticYAML(prefix, rule)...)
		}
	}
	return issues
}

func validatePermissionCommandSemanticYAML(prefix string, rule *yaml.Node) []string {
	if rule == nil || rule.Kind != yaml.MappingNode {
		return nil
	}
	command := yamlMapValue(rule, "command")
	if command == nil || command.Kind != yaml.MappingNode {
		return nil
	}
	semantic := yamlMapValue(command, "semantic")
	if semantic == nil {
		return nil
	}
	if semantic.Kind != yaml.MappingNode {
		return []string{fmt.Sprintf("%s.semantic must be a mapping", prefix)}
	}
	nameNode := yamlMapValue(command, "name")
	name := ""
	if nameNode != nil && nameNode.Kind == yaml.ScalarNode {
		name = strings.TrimSpace(nameNode.Value)
	}
	if name == "" {
		return []string{fmt.Sprintf("%s.name must be set when semantic is used", prefix)}
	}
	schema, ok := semanticpkg.Lookup(name)
	if !ok {
		return []string{fmt.Sprintf("%s.semantic is not available for command %s. Use patterns, or add a semantic schema/parser for %s. See cc-bash-guard help semantic and docs/user/SEMANTIC_SCHEMAS.md.", prefix, name, name)}
	}
	fields := map[string]string{}
	for _, field := range schema.Fields {
		fields[field.Name] = field.Type
	}
	return validateSemanticFieldsYAML(prefix+".semantic", name, semantic, fields)
}

func validateSemanticFieldsYAML(prefix, name string, semantic *yaml.Node, fields map[string]string) []string {
	var issues []string
	for i := 0; i+1 < len(semantic.Content); i += 2 {
		key := semantic.Content[i]
		value := semantic.Content[i+1]
		field := key.Value
		wantType, ok := fields[field]
		if !ok {
			issues = append(issues, unsupportedSemanticYAMLIssue(prefix, name, field))
			continue
		}
		if gotType, ok := semanticYAMLTypeMismatch(value, wantType); ok {
			issues = append(issues, fmt.Sprintf("%s.%s must be %s, got %s. Command: %s.", prefix, field, wantType, gotType, name))
		}
	}
	return issues
}

func unsupportedSemanticYAMLIssue(prefix, command, field string) string {
	return fmt.Sprintf("%s.%s is not supported for command %s. Supported semantic fields for %s: %s. See cc-bash-guard help semantic %s or docs/user/SEMANTIC_SCHEMAS.md.", prefix, field, command, command, strings.Join(semanticpkg.FieldNames(command), ", "), command)
}

func semanticYAMLTypeMismatch(node *yaml.Node, want string) (string, bool) {
	switch want {
	case "string":
		if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
			return "", false
		}
	case "[]string":
		if node.Kind != yaml.SequenceNode {
			return yamlNodeType(node), true
		}
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
				return "[]" + yamlNodeType(item), true
			}
		}
		return "", false
	case "bool":
		if node.Kind == yaml.ScalarNode && node.Tag == "!!bool" {
			return "", false
		}
	}
	return yamlNodeType(node), true
}

func yamlNodeType(node *yaml.Node) string {
	if node == nil {
		return "null"
	}
	switch node.Kind {
	case yaml.SequenceNode:
		return "[]"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			return "string"
		case "!!bool":
			return "bool"
		case "!!int":
			return "int"
		case "!!float":
			return "float"
		case "!!null":
			return "null"
		default:
			return strings.TrimPrefix(node.Tag, "!!")
		}
	}
	return "unknown"
}

func yamlMappingHasKey(root yaml.Node, key string) bool {
	node := &root
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return true
		}
	}
	return false
}

func yamlMapValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func validateFileWithSources(file File) []string {
	var issues []string
	if len(file.Rewrite) > 0 {
		issues = append(issues, "top-level rewrite is no longer supported; cc-bash-guard policy evaluation no longer rewrites commands. Use permission.command / env / patterns, and rely on parser-backed normalization for evaluation.")
	}
	if policy.IsZeroPermissionSpec(file.Permission) {
		issues = append(issues, "must set at least one permission entry")
	}
	for _, rule := range file.Permission.Deny {
		prefix := sourcedPrefix(rule.Source, fmt.Sprintf("permission.deny[%d]", rule.Source.Index))
		issues = append(issues, policy.ValidatePermissionRule(prefix, rule, "deny")...)
	}
	for _, rule := range file.Permission.Ask {
		prefix := sourcedPrefix(rule.Source, fmt.Sprintf("permission.ask[%d]", rule.Source.Index))
		issues = append(issues, policy.ValidatePermissionRule(prefix, rule, "ask")...)
	}
	for _, rule := range file.Permission.Allow {
		prefix := sourcedPrefix(rule.Source, fmt.Sprintf("permission.allow[%d]", rule.Source.Index))
		issues = append(issues, policy.ValidatePermissionRule(prefix, rule, "allow")...)
	}
	for _, test := range file.Test {
		prefix := sourcedPrefix(test.Source, fmt.Sprintf("test[%d]", test.Source.Index))
		if strings.TrimSpace(test.In) == "" {
			issues = append(issues, prefix+".in must be non-empty")
		}
		if strings.TrimSpace(test.Rewritten) != "" {
			issues = append(issues, prefix+".rewritten is no longer supported; cc-bash-guard policy evaluation does not rewrite commands")
		}
		switch test.Decision {
		case "allow", "ask", "deny":
		default:
			issues = append(issues, prefix+".decision must be one of allow, ask, deny")
		}
	}
	return issues
}

func sourcedPrefix(src Source, scope string) string {
	if src.Path == "" {
		return scope
	}
	return src.Path + " " + scope
}

func loadEvalCache(src Source, cachePath string, sourceHash string, requireVerified bool) (policy.Pipeline, bool, error) {
	data, err := readTrustedCacheFile(cachePath)
	if err != nil {
		return policy.Pipeline{}, false, nil
	}
	var cache evalCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return policy.Pipeline{}, false, nil
	}
	if cache.Version != 1 || cache.SourcePath != src.Path || cache.SourceHash != sourceHash {
		return policy.Pipeline{}, false, nil
	}
	if requireVerified && strings.TrimSpace(cache.VerifiedAt) == "" {
		return policy.Pipeline{}, false, nil
	}
	if cache.EvaluationSemanticsVersion != EvaluationSemanticsVersion {
		return policy.Pipeline{}, false, incompatibleEvaluationSemanticsError(cachePath, cache.EvaluationSemanticsVersion)
	}
	return policy.NewPipeline(cache.Pipeline, src), true, nil
}

func loadEffectiveEvalCache(cachePath string, inputs EffectiveInputs) (policy.Pipeline, bool, error) {
	data, err := readTrustedCacheFile(cachePath)
	if err != nil {
		return policy.Pipeline{}, false, nil
	}
	var cache evalCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return policy.Pipeline{}, false, nil
	}
	if cache.Version != 2 || cache.Tool != inputs.Tool || cache.Fingerprint != inputs.Fingerprint || strings.TrimSpace(cache.VerifiedAt) == "" {
		return policy.Pipeline{}, false, nil
	}
	if cache.EvaluationSemanticsVersion != EvaluationSemanticsVersion {
		return policy.Pipeline{}, false, incompatibleEvaluationSemanticsError(cachePath, cache.EvaluationSemanticsVersion)
	}
	return policy.NewPipeline(cache.Pipeline, loadOnceSource(inputs)), true, nil
}

func incompatibleEvaluationSemanticsError(cachePath string, got int) error {
	return fmt.Errorf("verified artifact %s is incompatible: evaluation semantics version %d, current %d; run cc-bash-guard verify", cachePath, got, EvaluationSemanticsVersion)
}

func writeEvalCache(cachePath string, cache evalCacheFile) error {
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return writeTrustedCacheFile(cachePath, data)
}

func readTrustedCacheFile(cachePath string) ([]byte, error) {
	if err := validateTrustedCacheDir(filepath.Dir(cachePath)); err != nil {
		return nil, err
	}
	if err := validateTrustedCacheFile(cachePath); err != nil {
		return nil, err
	}
	return os.ReadFile(cachePath)
}

func writeTrustedCacheFile(cachePath string, data []byte) error {
	cacheDir := filepath.Dir(cachePath)
	if err := ensureTrustedCacheDir(cacheDir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(cacheDir, "."+filepath.Base(cachePath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, cachePath); err != nil {
		return err
	}
	committed = true
	return fsyncDir(cacheDir)
}

func ensureTrustedCacheDir(cacheDir string) error {
	fi, err := os.Lstat(cacheDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return err
		}
	} else {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("cache dir %s must not be a symlink", cacheDir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("cache dir %s is not a directory", cacheDir)
		}
		if err := validateCacheOwner(cacheDir, fi); err != nil {
			return err
		}
		if err := os.Chmod(cacheDir, 0o700); err != nil {
			return err
		}
	}
	return validateTrustedCacheDir(cacheDir)
}

func validateTrustedCacheDir(cacheDir string) error {
	fi, err := os.Lstat(cacheDir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache dir %s must not be a symlink", cacheDir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("cache dir %s is not a directory", cacheDir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("cache dir %s has unsafe permissions %o", cacheDir, fi.Mode().Perm())
	}
	if err := validateCacheOwner(cacheDir, fi); err != nil {
		return err
	}
	return nil
}

func validateTrustedCacheFile(cachePath string) error {
	fi, err := os.Lstat(cachePath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache file %s must not be a symlink", cachePath)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("cache file %s is not a regular file", cachePath)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("cache file %s has unsafe permissions %o", cachePath, fi.Mode().Perm())
	}
	if err := validateCacheOwner(cachePath, fi); err != nil {
		return err
	}
	return nil
}

func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	return nil
}

func pruneOldEvalCaches(cacheDir string, keepPath string) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "compiled-rules-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(cacheDir, name)
		if path == keepPath {
			continue
		}
		_ = os.Remove(path)
	}
}

func pruneOldEffectiveCaches(cacheDir string, tool string, keepPath string) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return
	}
	prefix := "compiled-" + tool + "-"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(cacheDir, name)
		if path == keepPath {
			continue
		}
		_ = os.Remove(path)
	}
}

func cachePathForHash(cacheDir string, sourceHash string) string {
	return filepath.Join(cacheDir, "compiled-rules-"+sourceHash+".json")
}

func effectiveCachePath(cacheDir string, tool string, fingerprint string) string {
	return filepath.Join(cacheDir, "compiled-"+tool+"-"+fingerprint+".json")
}

func contentHash(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func mergePipelines(base policy.Pipeline, next policy.Pipeline) policy.Pipeline {
	base.Rewrite = append(base.Rewrite, next.Rewrite...)
	base.Permission.Deny = append(base.Permission.Deny, next.Permission.Deny...)
	base.Permission.Ask = append(base.Permission.Ask, next.Permission.Ask...)
	base.Permission.Allow = append(base.Permission.Allow, next.Permission.Allow...)
	base.Test = append(base.Test, next.Test...)
	if base.Source == (policy.Source{}) {
		base.Source = next.Source
	}
	base = policy.NewPipeline(base.PipelineSpec, base.Source)
	return base
}

func compileEffectivePipeline(inputs EffectiveInputs) (policy.Pipeline, error) {
	loaded := loadEffectiveWithSources(inputs.ConfigSources, LoadFileIfPresent)
	if len(loaded.Errors) > 0 {
		return policy.Pipeline{}, loaded.Errors[0]
	}
	return loaded.Pipeline, nil
}

func loadOnceSource(inputs EffectiveInputs) Source {
	return Source{
		Layer: "effective",
		Path:  "effective:" + inputs.Tool,
	}
}

func sourcePaths(sources []Source) []string {
	paths := make([]string, 0, len(sources))
	for _, src := range sources {
		paths = append(paths, src.Path)
	}
	return paths
}

func configDependencySources(sources []Source) []Source {
	var deps []Source
	seen := map[string]struct{}{}
	for _, src := range sources {
		_, files, err := loadFileWithIncludes(src)
		if err != nil || len(files) == 0 {
			if _, ok := seen[src.Path]; !ok {
				seen[src.Path] = struct{}{}
				deps = append(deps, src)
			}
			continue
		}
		for _, file := range files {
			if _, ok := seen[file.Path]; ok {
				continue
			}
			seen[file.Path] = struct{}{}
			deps = append(deps, file)
		}
	}
	return deps
}

func existingPaths(paths []string) []string {
	var existing []string
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	return existing
}

func configSources(cwd string, home string, xdgConfigHome string, tool string) []Source {
	var sources []Source
	for _, path := range resolveUserConfigCandidates(home, xdgConfigHome) {
		if path == "" {
			continue
		}
		sources = append(sources, Source{Layer: LayerUser, Path: path})
		break
	}
	if root := projectRoot(tool, cwd); root != "" {
		for _, path := range resolveProjectConfigCandidates(root) {
			if path == "" {
				continue
			}
			sources = append(sources, Source{Layer: LayerProject, Path: path})
			break
		}
	}
	return sources
}

func settingsPaths(tool string, cwd string, home string) []string {
	if tool == claude.Tool {
		return claude.SettingsPaths(cwd, home)
	}
	return nil
}

func projectRoot(tool string, cwd string) string {
	if tool == claude.Tool {
		return claude.ProjectRoot(cwd)
	}
	return ""
}

func resolveUserConfigCandidates(home string, xdgConfigHome string) []string {
	base := xdgConfigHome
	if base == "" {
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, "cc-bash-guard")
	return configCandidates(dir)
}

func resolveProjectConfigCandidates(root string) []string {
	return configCandidates(filepath.Join(root, ".cc-bash-guard"))
}

func configCandidates(dir string) []string {
	candidates := []string{
		filepath.Join(dir, "cc-bash-guard.yml"),
		filepath.Join(dir, "cc-bash-guard.yaml"),
	}
	var existing []string
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}
	if len(existing) > 0 {
		sort.Strings(existing)
		return existing
	}
	return candidates
}

func effectiveFingerprint(tool string, sources []Source, settingsPaths []string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("tool=" + tool + "\n"))
	for _, src := range sources {
		_, _ = h.Write([]byte(src.Layer + ":" + src.Path + "\n"))
		if data, err := os.ReadFile(src.Path); err == nil {
			_, _ = h.Write(data)
		}
		_, _ = h.Write([]byte("\n"))
	}
	for _, path := range settingsPaths {
		_, _ = h.Write([]byte("settings:" + path + "\n"))
		if data, err := os.ReadFile(path); err == nil {
			_, _ = h.Write(data)
		}
		_, _ = h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func configSourcesHash(sources []Source) string {
	h := sha256.New()
	for _, src := range sources {
		_, _ = h.Write([]byte(src.Layer + ":" + src.Path + "\n"))
		if data, err := os.ReadFile(src.Path); err == nil {
			_, _ = h.Write(data)
		}
		_, _ = h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
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

func isZeroPipeline(spec policy.PipelineSpec) bool {
	return len(spec.Rewrite) == 0 && policy.IsZeroPermissionSpec(spec.Permission) && len(spec.Test) == 0
}
