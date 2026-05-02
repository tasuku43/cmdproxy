package policy

import "strings"

func ValidateXargsSemanticMatchSpec(prefix string, semantic SemanticMatchSpec) []string {
	return ValidateXargsSemanticSpec(prefix, semantic.Xargs())
}

func ValidateXargsSemanticSpec(prefix string, semantic XargsSemanticSpec) []string {
	var issues []string
	if IsZeroXargsSemanticSpec(semantic) {
		issues = append(issues, prefix+" must not be empty")
	}
	if strings.TrimSpace(semantic.InnerCommand) == "" && semantic.InnerCommand != "" {
		issues = append(issues, prefix+".inner_command must be non-empty")
	}
	if strings.TrimSpace(semantic.MaxArgs) == "" && semantic.MaxArgs != "" {
		issues = append(issues, prefix+".max_args must be non-empty")
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".inner_command_in", semantic.InnerCommandIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".inner_args_contains", semantic.InnerArgsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_contains", semantic.FlagsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_prefixes", semantic.FlagsPrefixes)...)
	return issues
}
