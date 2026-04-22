package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tasuku43/cmdproxy/internal/contract"
	"github.com/tasuku43/cmdproxy/internal/domain/policy"
	"gopkg.in/yaml.v3"
)

const LayerUser = "user"

type File = policy.PipelineSpec

type Source = policy.Source

type Loaded struct {
	Pipeline policy.Pipeline
	Files    []Source
	Errors   []error
}

type evalCacheFile struct {
	Version         int                 `json:"version"`
	SourcePath      string              `json:"source_path"`
	SourceHash      string              `json:"source_hash"`
	CmdproxyVersion string              `json:"cmdproxy_version,omitempty"`
	VerifiedAt      string              `json:"verified_at,omitempty"`
	Pipeline        policy.PipelineSpec `json:"pipeline"`
}

func ConfigPaths(home string, xdgConfigHome string) []Source {
	userConfigBase := xdgConfigHome
	if userConfigBase == "" {
		userConfigBase = filepath.Join(home, ".config")
	}
	return []Source{{
		Layer: LayerUser,
		Path:  filepath.Join(userConfigBase, "cmdproxy", "cmdproxy.yml"),
	}}
}

func HookCacheDir(home string, xdgCacheHome string) string {
	dirs := HookCacheDirs(home, xdgCacheHome)
	if len(dirs) == 0 {
		return filepath.Join(home, ".cache", "cmdproxy")
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
		path := filepath.Join(base, "cmdproxy")
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		dirs = append(dirs, path)
	}
	add(filepath.Join(os.TempDir(), "cmdproxy-"+shortHash(home)))
	add(filepath.Join(home, ".cache"))
	add(xdgCacheHome)
	return dirs
}

func LoadEffective(home string, xdgConfigHome string) Loaded {
	return loadEffectiveWithLoader(home, xdgConfigHome, LoadFileIfPresent)
}

func LoadEffectiveForHook(home string, xdgConfigHome string, xdgCacheHome string) Loaded {
	loader := func(src Source) (policy.Pipeline, error) {
		return LoadVerifiedFileForHook(src, HookCacheDirs(home, xdgCacheHome))
	}
	return loadEffectiveWithLoader(home, xdgConfigHome, loader)
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

func LoadFileIfPresent(src Source) (policy.Pipeline, error) {
	data, err := readConfigFile(src)
	if err != nil {
		return policy.Pipeline{}, err
	}
	if data == "" {
		return policy.Pipeline{}, nil
	}
	file, err := decodeFile(src, data)
	if err != nil {
		return policy.Pipeline{}, err
	}
	issues := validateFile(file)
	if len(issues) > 0 {
		for i := range issues {
			issues[i] = fmt.Sprintf("%s config %s: %s", src.Layer, src.Path, issues[i])
		}
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

func loadFileForEval(src Source, cacheDir string, requireVerified bool, cmdproxyVersion string) (policy.Pipeline, error) {
	data, err := readConfigFile(src)
	if err != nil {
		return policy.Pipeline{}, err
	}
	if data == "" {
		return policy.Pipeline{}, nil
	}
	sourceHash := contentHash(data)
	cachePath := cachePathForHash(cacheDir, sourceHash)
	if pipeline, ok := loadEvalCache(src, cachePath, sourceHash, requireVerified); ok {
		return pipeline, nil
	}
	if requireVerified {
		return policy.Pipeline{}, fmt.Errorf("%s config %s changed since last verify; run cmdproxy verify", src.Layer, src.Path)
	}
	return compileEvalData(src, cacheDir, cmdproxyVersion, data, sourceHash)
}

func compileAndWriteEvalFile(src Source, cacheDir string, cmdproxyVersion string) (policy.Pipeline, error) {
	data, err := readConfigFile(src)
	if err != nil {
		return policy.Pipeline{}, err
	}
	if data == "" {
		return policy.Pipeline{}, nil
	}
	sourceHash := contentHash(data)
	return compileEvalData(src, cacheDir, cmdproxyVersion, data, sourceHash)
}

func compileEvalData(src Source, cacheDir string, cmdproxyVersion string, data string, sourceHash string) (policy.Pipeline, error) {
	file, err := decodeFile(src, data)
	if err != nil {
		return policy.Pipeline{}, err
	}
	issues := validateFile(file)
	if len(issues) > 0 {
		for i := range issues {
			issues[i] = fmt.Sprintf("%s config %s: %s", src.Layer, src.Path, issues[i])
		}
		return policy.Pipeline{}, &policy.ValidationError{Issues: issues}
	}
	cachePath := cachePathForHash(cacheDir, sourceHash)
	if err := writeEvalCache(cachePath, evalCacheFile{
		Version:         1,
		SourcePath:      src.Path,
		SourceHash:      sourceHash,
		CmdproxyVersion: cmdproxyVersion,
		VerifiedAt:      time.Now().UTC().Format(time.RFC3339),
		Pipeline:        file,
	}); err != nil {
		return policy.Pipeline{}, err
	}
	pruneOldEvalCaches(cacheDir, cachePath)
	return policy.NewPipeline(file, src), nil
}

func loadVerifiedFileForHook(src Source, cacheDirs []string) (policy.Pipeline, error) {
	data, err := readConfigFile(src)
	if err != nil {
		return policy.Pipeline{}, err
	}
	if data == "" {
		return policy.Pipeline{}, nil
	}
	sourceHash := contentHash(data)
	for _, cacheDir := range cacheDirs {
		cachePath := cachePathForHash(cacheDir, sourceHash)
		if pipeline, ok := loadEvalCache(src, cachePath, sourceHash, true); ok {
			return pipeline, nil
		}
	}
	return policy.Pipeline{}, fmt.Errorf("%s config %s changed since last verify; verified artifact not found in %s; run cmdproxy verify", src.Layer, src.Path, strings.Join(cacheDirs, ", "))
}

func decodeFile(src Source, data string) (File, error) {
	dec := yaml.NewDecoder(strings.NewReader(data))
	dec.KnownFields(true)
	var file File
	if err := dec.Decode(&file); err != nil {
		return File{}, fmt.Errorf("%s config %s is invalid: %w", src.Layer, src.Path, err)
	}
	return file, nil
}

func validateFile(file File) []string {
	var issues []string
	issues = append(issues, policy.ValidatePipeline(file)...)
	issues = append(issues, contract.ValidateRewrites(file.Rewrite)...)
	return issues
}

func loadEvalCache(src Source, cachePath string, sourceHash string, requireVerified bool) (policy.Pipeline, bool) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return policy.Pipeline{}, false
	}
	var cache evalCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return policy.Pipeline{}, false
	}
	if cache.Version != 1 || cache.SourcePath != src.Path || cache.SourceHash != sourceHash {
		return policy.Pipeline{}, false
	}
	if requireVerified && strings.TrimSpace(cache.VerifiedAt) == "" {
		return policy.Pipeline{}, false
	}
	return policy.NewPipeline(cache.Pipeline, src), true
}

func writeEvalCache(cachePath string, cache evalCacheFile) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0o644)
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

func cachePathForHash(cacheDir string, sourceHash string) string {
	return filepath.Join(cacheDir, "compiled-rules-"+sourceHash+".json")
}

func contentHash(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
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
