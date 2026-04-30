package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	commandpkg "github.com/tasuku43/cc-bash-guard/internal/domain/command"
)

const (
	claudeDir         = ".claude"
	settingsJSON      = "settings.json"
	settingsLocalJSON = "settings.local.json"
)

type PermissionVerdict string

const (
	PermissionAllow   PermissionVerdict = "allow"
	PermissionDeny    PermissionVerdict = "deny"
	PermissionAsk     PermissionVerdict = "ask"
	PermissionDefault PermissionVerdict = "default"
)

type PermissionExplanation struct {
	Outcome string           `json:"outcome"`
	Matched *PermissionMatch `json:"matched"`
}

type PermissionMatch struct {
	Bucket  string `json:"bucket"`
	Pattern string `json:"pattern"`
}

func CheckCommand(cmd string, cwd string, home string) PermissionVerdict {
	denyRules, askRules, allowRules := loadPermissionRules(cwd, home)
	return checkCommandWithRules(cmd, denyRules, askRules, allowRules)
}

func ExplainCommand(cmd string, cwd string, home string) PermissionExplanation {
	denyRules, askRules, allowRules := loadPermissionRules(cwd, home)
	return explainCommandWithRules(cmd, denyRules, askRules, allowRules)
}

func SettingsPaths(cwd string, home string) []string {
	return settingsPaths(cwd, home)
}

func SettingsFingerprintData(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return data
	}
	permissions, ok := root["permissions"].(map[string]any)
	if !ok {
		return []byte("{}")
	}
	relevant := map[string]any{}
	for _, key := range []string{"allow", "ask", "deny"} {
		if value, ok := permissions[key]; ok {
			relevant[key] = value
		}
	}
	canonical, err := json.Marshal(map[string]any{"permissions": relevant})
	if err != nil {
		return data
	}
	return canonical
}

func ProjectRoot(cwd string) string {
	return findProjectRoot(cwd)
}

func checkCommandWithRules(cmd string, denyRules []string, askRules []string, allowRules []string) PermissionVerdict {
	explained := explainCommandWithRules(cmd, denyRules, askRules, allowRules)
	switch explained.Outcome {
	case "deny":
		return PermissionDeny
	case "ask":
		return PermissionAsk
	case "allow":
		return PermissionAllow
	default:
		return PermissionDefault
	}
}

func explainCommandWithRules(cmd string, denyRules []string, askRules []string, allowRules []string) PermissionExplanation {
	plan := commandpkg.Parse(cmd)
	segments := commandSegmentsForPermission(cmd, plan)
	anyAsk := false
	var askPattern string
	allSegmentsAllowed := true
	var allowPattern string
	sawSegment := false

	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		sawSegment = true

		for _, pattern := range denyRules {
			if commandMatchesPattern(segment, pattern) {
				return PermissionExplanation{Outcome: "deny", Matched: &PermissionMatch{Bucket: "permission.deny", Pattern: pattern}}
			}
		}
		if !anyAsk {
			for _, pattern := range askRules {
				if commandMatchesPattern(segment, pattern) {
					anyAsk = true
					askPattern = pattern
					break
				}
			}
		}
		if allSegmentsAllowed {
			matched := false
			for _, pattern := range allowRules {
				if commandMatchesPattern(segment, pattern) {
					matched = true
					if allowPattern == "" {
						allowPattern = pattern
					}
					break
				}
			}
			if !matched {
				allSegmentsAllowed = false
			}
		}
	}

	if anyAsk {
		return PermissionExplanation{Outcome: "ask", Matched: &PermissionMatch{Bucket: "permission.ask", Pattern: askPattern}}
	}
	if sawSegment && allSegmentsAllowed && len(allowRules) > 0 && claudeCompositionAllows(plan.Shape) {
		return PermissionExplanation{Outcome: "allow", Matched: &PermissionMatch{Bucket: "permission.allow", Pattern: allowPattern}}
	}
	return PermissionExplanation{Outcome: "abstain"}
}

func loadPermissionRules(cwd string, home string) ([]string, []string, []string) {
	var denyRules []string
	var askRules []string
	var allowRules []string
	for _, path := range settingsPaths(cwd, home) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var root map[string]any
		if err := json.Unmarshal(data, &root); err != nil {
			continue
		}
		permissions, ok := root["permissions"].(map[string]any)
		if !ok {
			continue
		}
		appendBashRules(permissions["deny"], &denyRules)
		appendBashRules(permissions["ask"], &askRules)
		appendBashRules(permissions["allow"], &allowRules)
	}
	return denyRules, askRules, allowRules
}

func settingsPaths(cwd string, home string) []string {
	var paths []string
	if root := findProjectRoot(cwd); root != "" {
		paths = append(paths,
			filepath.Join(root, claudeDir, settingsJSON),
			filepath.Join(root, claudeDir, settingsLocalJSON),
		)
	}
	if strings.TrimSpace(home) != "" {
		paths = append(paths,
			filepath.Join(home, claudeDir, settingsJSON),
			filepath.Join(home, claudeDir, settingsLocalJSON),
		)
	}
	return paths
}

func findProjectRoot(cwd string) string {
	dir := strings.TrimSpace(cwd)
	if dir == "" {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, claudeDir)); err == nil {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func appendBashRules(value any, target *[]string) {
	items, ok := value.([]any)
	if !ok {
		return
	}
	for _, item := range items {
		s, ok := item.(string)
		if !ok || !strings.HasPrefix(s, "Bash(") {
			continue
		}
		*target = append(*target, extractBashPattern(s))
	}
}

func extractBashPattern(rule string) string {
	if inner, ok := strings.CutPrefix(rule, "Bash("); ok {
		if pattern, ok := strings.CutSuffix(inner, ")"); ok {
			return pattern
		}
	}
	return rule
}

func commandSegmentsForPermission(raw string, plan commandpkg.CommandPlan) []string {
	if plan.Shape.Kind == commandpkg.ShellShapeSimple {
		return []string{raw}
	}
	segments := make([]string, 0, len(plan.Commands))
	for _, cmd := range plan.Commands {
		segments = append(segments, cmd.Raw)
	}
	return segments
}

func claudeCompositionAllows(shape commandpkg.ShellShape) bool {
	if shape.Kind == commandpkg.ShellShapeSimple {
		return true
	}
	if shape.Kind != commandpkg.ShellShapeCompound {
		return false
	}
	if shape.HasBackground ||
		shape.HasRedirection ||
		shape.HasSubshell ||
		shape.HasCommandSubstitution ||
		shape.HasProcessSubstitution {
		return false
	}
	if shape.HasPipeline && (shape.HasConditional || shape.HasSequence) {
		return false
	}
	return shape.HasPipeline || shape.HasConditional || shape.HasSequence
}

func commandMatchesPattern(cmd string, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		prefix := strings.TrimSpace(strings.TrimSuffix(p, ":"))
		if prefix == "" || prefix == "*" {
			return true
		}
		if !strings.Contains(prefix, "*") {
			return cmd == prefix || strings.HasPrefix(cmd, prefix+" ")
		}
	}
	if strings.Contains(pattern, "*") {
		return globMatches(cmd, pattern)
	}
	return cmd == pattern || strings.HasPrefix(cmd, pattern+" ")
}

func globMatches(cmd string, pattern string) bool {
	normalized := strings.ReplaceAll(strings.ReplaceAll(pattern, ":*", " *"), "*:", "* ")
	parts := strings.Split(normalized, "*")
	allEmpty := true
	for _, part := range parts {
		if part != "" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return true
	}
	searchFrom := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		switch {
		case i == 0:
			if !strings.HasPrefix(cmd, part) {
				return false
			}
			searchFrom = len(part)
		case i == len(parts)-1:
			if !strings.HasSuffix(cmd[searchFrom:], part) {
				return false
			}
		default:
			remaining := cmd[searchFrom:]
			if pos := strings.Index(remaining, part); pos >= 0 {
				searchFrom += pos + len(part)
				continue
			}
			trimmed := strings.TrimRight(part, " ")
			if trimmed != "" && strings.HasSuffix(remaining, trimmed) {
				searchFrom += len(remaining)
				continue
			}
			return false
		}
	}
	return true
}
