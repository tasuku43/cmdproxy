package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	commandpkg "github.com/tasuku43/cc-bash-guard/internal/domain/command"
	"github.com/tasuku43/cc-bash-guard/internal/domain/invocation"
	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
	"gopkg.in/yaml.v3"
)

type PipelineSpec struct {
	Include []string `yaml:"include" json:"-"`
	// Rewrite is retained only to reject unsupported configs with guidance.
	// It is not a supported user-facing feature.
	Rewrite    []map[string]any `yaml:"rewrite" json:"rewrite,omitempty"`
	Permission PermissionSpec   `yaml:"permission" json:"permission,omitempty"`
	Test       PipelineTestSpec `yaml:"test" json:"test,omitempty"`
}

type PermissionSpec struct {
	Deny  []PermissionRuleSpec `yaml:"deny" json:"deny,omitempty"`
	Ask   []PermissionRuleSpec `yaml:"ask" json:"ask,omitempty"`
	Allow []PermissionRuleSpec `yaml:"allow" json:"allow,omitempty"`
}

type PermissionRuleSpec struct {
	Name     string                `yaml:"name" json:"name,omitempty"`
	Command  PermissionCommandSpec `yaml:"command" json:"command,omitempty"`
	Env      PermissionEnvSpec     `yaml:"env" json:"env,omitempty"`
	Patterns []string              `yaml:"patterns" json:"patterns,omitempty"`
	Message  string                `yaml:"message" json:"message,omitempty"`
	Test     PermissionTestSpec    `yaml:"test" json:"test,omitempty"`
	Source   Source                `yaml:"-" json:"source,omitempty"`
}

type PermissionCommandSpec struct {
	Name           string             `yaml:"name" json:"name,omitempty"`
	NameIn         []string           `yaml:"name_in" json:"name_in,omitempty"`
	ShapeFlagsAny  []string           `yaml:"shape_flags_any" json:"shape_flags_any,omitempty"`
	ShapeFlagsAll  []string           `yaml:"shape_flags_all" json:"shape_flags_all,omitempty"`
	ShapeFlagsNone []string           `yaml:"shape_flags_none" json:"shape_flags_none,omitempty"`
	Semantic       *SemanticMatchSpec `yaml:"semantic" json:"semantic,omitempty"`
}

type PermissionEnvSpec struct {
	Requires []string `yaml:"requires" json:"requires,omitempty"`
	Missing  []string `yaml:"missing" json:"missing,omitempty"`
}

type PermissionTestSpec struct {
	Allow   []string `yaml:"allow" json:"allow,omitempty"`
	Ask     []string `yaml:"ask" json:"ask,omitempty"`
	Deny    []string `yaml:"deny" json:"deny,omitempty"`
	Abstain []string `yaml:"abstain" json:"abstain,omitempty"`
	Pass    []string `yaml:"pass" json:"pass,omitempty"`
}

type PipelineTestSpec []PipelineExpectCase

type PipelineExpectCase struct {
	In string `yaml:"in" json:"in,omitempty"`
	// Rewritten is retained only to reject unsupported tests with guidance.
	// cc-bash-guard tests assert permission decisions, not rewritten commands.
	Rewritten           string `yaml:"rewritten" json:"rewritten,omitempty"`
	Decision            string `yaml:"decision" json:"decision,omitempty"`
	AssertPolicyOutcome bool   `yaml:"-" json:"assert_policy_outcome,omitempty"`
	Source              Source `yaml:"-" json:"source,omitempty"`
}

func (s *PipelineTestSpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var cases []PipelineExpectCase
		if err := node.Decode(&cases); err != nil {
			return err
		}
		*s = cases
		return nil
	case yaml.MappingNode:
		var cases []PipelineExpectCase
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if seen[key] {
				return fmt.Errorf("test.%s is duplicated", key)
			}
			seen[key] = true
			switch key {
			case "deny", "ask", "allow", "abstain":
			default:
				return fmt.Errorf("test.%s is not supported; bucketed test keys must be one of deny, ask, allow, abstain", key)
			}
			var inputs []string
			if err := node.Content[i+1].Decode(&inputs); err != nil {
				return fmt.Errorf("test.%s must be a sequence of command strings: %w", key, err)
			}
			for _, in := range inputs {
				cases = append(cases, PipelineExpectCase{
					In:                  in,
					Decision:            key,
					AssertPolicyOutcome: key == "abstain",
				})
			}
		}
		*s = cases
		return nil
	default:
		return fmt.Errorf("test must be either a sequence of cases or a mapping of deny/ask/allow/abstain buckets")
	}
}

type MatchSpec struct {
	Command               string             `yaml:"command" json:"command,omitempty"`
	CommandIn             []string           `yaml:"command_in" json:"command_in,omitempty"`
	CommandIsAbsolutePath bool               `yaml:"command_is_absolute_path" json:"command_is_absolute_path,omitempty"`
	Subcommand            string             `yaml:"subcommand" json:"subcommand,omitempty"`
	ArgsContains          []string           `yaml:"args_contains" json:"args_contains,omitempty"`
	ArgsPrefixes          []string           `yaml:"args_prefixes" json:"args_prefixes,omitempty"`
	EnvRequires           []string           `yaml:"env_requires" json:"env_requires,omitempty"`
	EnvMissing            []string           `yaml:"env_missing" json:"env_missing,omitempty"`
	Semantic              *SemanticMatchSpec `yaml:"semantic" json:"semantic,omitempty"`
}

type SemanticMatchSpec struct {
	Verb                             string   `yaml:"verb" json:"verb,omitempty"`
	VerbIn                           []string `yaml:"verb_in" json:"verb_in,omitempty"`
	Remote                           string   `yaml:"remote" json:"remote,omitempty"`
	RemoteIn                         []string `yaml:"remote_in" json:"remote_in,omitempty"`
	Branch                           string   `yaml:"branch" json:"branch,omitempty"`
	BranchIn                         []string `yaml:"branch_in" json:"branch_in,omitempty"`
	Ref                              string   `yaml:"ref" json:"ref,omitempty"`
	RefIn                            []string `yaml:"ref_in" json:"ref_in,omitempty"`
	Force                            *bool    `yaml:"force" json:"force,omitempty"`
	ForceWithLease                   *bool    `yaml:"force_with_lease" json:"force_with_lease,omitempty"`
	ForceIfIncludes                  *bool    `yaml:"force_if_includes" json:"force_if_includes,omitempty"`
	Hard                             *bool    `yaml:"hard" json:"hard,omitempty"`
	Recursive                        *bool    `yaml:"recursive" json:"recursive,omitempty"`
	IncludeIgnored                   *bool    `yaml:"include_ignored" json:"include_ignored,omitempty"`
	Cached                           *bool    `yaml:"cached" json:"cached,omitempty"`
	Staged                           *bool    `yaml:"staged" json:"staged,omitempty"`
	FlagsContains                    []string `yaml:"flags_contains" json:"flags_contains,omitempty"`
	FlagsPrefixes                    []string `yaml:"flags_prefixes" json:"flags_prefixes,omitempty"`
	Service                          string   `yaml:"service" json:"service,omitempty"`
	ServiceIn                        []string `yaml:"service_in" json:"service_in,omitempty"`
	Operation                        string   `yaml:"operation" json:"operation,omitempty"`
	OperationIn                      []string `yaml:"operation_in" json:"operation_in,omitempty"`
	Profile                          string   `yaml:"profile" json:"profile,omitempty"`
	ProfileIn                        []string `yaml:"profile_in" json:"profile_in,omitempty"`
	Region                           string   `yaml:"region" json:"region,omitempty"`
	RegionIn                         []string `yaml:"region_in" json:"region_in,omitempty"`
	EndpointURL                      string   `yaml:"endpoint_url" json:"endpoint_url,omitempty"`
	EndpointURLPrefix                string   `yaml:"endpoint_url_prefix" json:"endpoint_url_prefix,omitempty"`
	DryRun                           *bool    `yaml:"dry_run" json:"dry_run,omitempty"`
	NoCLIPager                       *bool    `yaml:"no_cli_pager" json:"no_cli_pager,omitempty"`
	Subverb                          string   `yaml:"subverb" json:"subverb,omitempty"`
	SubverbIn                        []string `yaml:"subverb_in" json:"subverb_in,omitempty"`
	ResourceType                     string   `yaml:"resource_type" json:"resource_type,omitempty"`
	ResourceTypeIn                   []string `yaml:"resource_type_in" json:"resource_type_in,omitempty"`
	ResourceName                     string   `yaml:"resource_name" json:"resource_name,omitempty"`
	ResourceNameIn                   []string `yaml:"resource_name_in" json:"resource_name_in,omitempty"`
	Namespace                        string   `yaml:"namespace" json:"namespace,omitempty"`
	NamespaceIn                      []string `yaml:"namespace_in" json:"namespace_in,omitempty"`
	NamespaceMissing                 *bool    `yaml:"namespace_missing" json:"namespace_missing,omitempty"`
	Context                          string   `yaml:"context" json:"context,omitempty"`
	ContextIn                        []string `yaml:"context_in" json:"context_in,omitempty"`
	Kubeconfig                       string   `yaml:"kubeconfig" json:"kubeconfig,omitempty"`
	AllNamespaces                    *bool    `yaml:"all_namespaces" json:"all_namespaces,omitempty"`
	Filename                         string   `yaml:"filename" json:"filename,omitempty"`
	FilenameIn                       []string `yaml:"filename_in" json:"filename_in,omitempty"`
	FilenamePrefix                   string   `yaml:"filename_prefix" json:"filename_prefix,omitempty"`
	Selector                         string   `yaml:"selector" json:"selector,omitempty"`
	SelectorIn                       []string `yaml:"selector_in" json:"selector_in,omitempty"`
	SelectorContains                 []string `yaml:"selector_contains" json:"selector_contains,omitempty"`
	SelectorMissing                  *bool    `yaml:"selector_missing" json:"selector_missing,omitempty"`
	Container                        string   `yaml:"container" json:"container,omitempty"`
	Environment                      string   `yaml:"environment" json:"environment,omitempty"`
	EnvironmentIn                    []string `yaml:"environment_in" json:"environment_in,omitempty"`
	EnvironmentMissing               *bool    `yaml:"environment_missing" json:"environment_missing,omitempty"`
	File                             string   `yaml:"file" json:"file,omitempty"`
	FileIn                           []string `yaml:"file_in" json:"file_in,omitempty"`
	FilePrefix                       string   `yaml:"file_prefix" json:"file_prefix,omitempty"`
	FileMissing                      *bool    `yaml:"file_missing" json:"file_missing,omitempty"`
	KubeContext                      string   `yaml:"kube_context" json:"kube_context,omitempty"`
	KubeContextIn                    []string `yaml:"kube_context_in" json:"kube_context_in,omitempty"`
	KubeContextMissing               *bool    `yaml:"kube_context_missing" json:"kube_context_missing,omitempty"`
	Interactive                      *bool    `yaml:"interactive" json:"interactive,omitempty"`
	Wait                             *bool    `yaml:"wait" json:"wait,omitempty"`
	WaitForJobs                      *bool    `yaml:"wait_for_jobs" json:"wait_for_jobs,omitempty"`
	SkipDiff                         *bool    `yaml:"skip_diff" json:"skip_diff,omitempty"`
	SkipNeeds                        *bool    `yaml:"skip_needs" json:"skip_needs,omitempty"`
	IncludeNeeds                     *bool    `yaml:"include_needs" json:"include_needs,omitempty"`
	IncludeTransitiveNeeds           *bool    `yaml:"include_transitive_needs" json:"include_transitive_needs,omitempty"`
	Purge                            *bool    `yaml:"purge" json:"purge,omitempty"`
	Cascade                          string   `yaml:"cascade" json:"cascade,omitempty"`
	CascadeIn                        []string `yaml:"cascade_in" json:"cascade_in,omitempty"`
	DeleteWait                       *bool    `yaml:"delete_wait" json:"delete_wait,omitempty"`
	StateValuesFile                  string   `yaml:"state_values_file" json:"state_values_file,omitempty"`
	StateValuesFileIn                []string `yaml:"state_values_file_in" json:"state_values_file_in,omitempty"`
	StateValuesSetKeysContains       []string `yaml:"state_values_set_keys_contains" json:"state_values_set_keys_contains,omitempty"`
	StateValuesSetStringKeysContains []string `yaml:"state_values_set_string_keys_contains" json:"state_values_set_string_keys_contains,omitempty"`
	Area                             string   `yaml:"area" json:"area,omitempty"`
	AreaIn                           []string `yaml:"area_in" json:"area_in,omitempty"`
	Repo                             string   `yaml:"repo" json:"repo,omitempty"`
	RepoIn                           []string `yaml:"repo_in" json:"repo_in,omitempty"`
	Org                              string   `yaml:"org" json:"org,omitempty"`
	OrgIn                            []string `yaml:"org_in" json:"org_in,omitempty"`
	EnvName                          string   `yaml:"env" json:"env,omitempty"`
	EnvNameIn                        []string `yaml:"env_in" json:"env_in,omitempty"`
	AppName                          string   `yaml:"app_name" json:"app_name,omitempty"`
	AppNameIn                        []string `yaml:"app_name_in" json:"app_name_in,omitempty"`
	Project                          string   `yaml:"project" json:"project,omitempty"`
	ProjectIn                        []string `yaml:"project_in" json:"project_in,omitempty"`
	Revision                         string   `yaml:"revision" json:"revision,omitempty"`
	Hostname                         string   `yaml:"hostname" json:"hostname,omitempty"`
	HostnameIn                       []string `yaml:"hostname_in" json:"hostname_in,omitempty"`
	Web                              *bool    `yaml:"web" json:"web,omitempty"`
	Method                           string   `yaml:"method" json:"method,omitempty"`
	MethodIn                         []string `yaml:"method_in" json:"method_in,omitempty"`
	Endpoint                         string   `yaml:"endpoint" json:"endpoint,omitempty"`
	EndpointPrefix                   string   `yaml:"endpoint_prefix" json:"endpoint_prefix,omitempty"`
	EndpointContains                 []string `yaml:"endpoint_contains" json:"endpoint_contains,omitempty"`
	Paginate                         *bool    `yaml:"paginate" json:"paginate,omitempty"`
	Input                            *bool    `yaml:"input" json:"input,omitempty"`
	Silent                           *bool    `yaml:"silent" json:"silent,omitempty"`
	IncludeHeaders                   *bool    `yaml:"include_headers" json:"include_headers,omitempty"`
	FieldKeysContains                []string `yaml:"field_keys_contains" json:"field_keys_contains,omitempty"`
	RawFieldKeysContains             []string `yaml:"raw_field_keys_contains" json:"raw_field_keys_contains,omitempty"`
	HeaderKeysContains               []string `yaml:"header_keys_contains" json:"header_keys_contains,omitempty"`
	PRNumber                         string   `yaml:"pr_number" json:"pr_number,omitempty"`
	IssueNumber                      string   `yaml:"issue_number" json:"issue_number,omitempty"`
	SecretName                       string   `yaml:"secret_name" json:"secret_name,omitempty"`
	SecretNameIn                     []string `yaml:"secret_name_in" json:"secret_name_in,omitempty"`
	Tag                              string   `yaml:"tag" json:"tag,omitempty"`
	WorkflowName                     string   `yaml:"workflow_name" json:"workflow_name,omitempty"`
	WorkflowID                       string   `yaml:"workflow_id" json:"workflow_id,omitempty"`
	SearchType                       string   `yaml:"search_type" json:"search_type,omitempty"`
	SearchTypeIn                     []string `yaml:"search_type_in" json:"search_type_in,omitempty"`
	QueryContains                    string   `yaml:"query_contains" json:"query_contains,omitempty"`
	Base                             string   `yaml:"base" json:"base,omitempty"`
	Head                             string   `yaml:"head" json:"head,omitempty"`
	State                            string   `yaml:"state" json:"state,omitempty"`
	StateIn                          []string `yaml:"state_in" json:"state_in,omitempty"`
	LabelIn                          []string `yaml:"label_in" json:"label_in,omitempty"`
	AssigneeIn                       []string `yaml:"assignee_in" json:"assignee_in,omitempty"`
	TitleContains                    string   `yaml:"title_contains" json:"title_contains,omitempty"`
	BodyContains                     string   `yaml:"body_contains" json:"body_contains,omitempty"`
	Draft                            *bool    `yaml:"draft" json:"draft,omitempty"`
	Prerelease                       *bool    `yaml:"prerelease" json:"prerelease,omitempty"`
	Latest                           *bool    `yaml:"latest" json:"latest,omitempty"`
	Fill                             *bool    `yaml:"fill" json:"fill,omitempty"`
	Admin                            *bool    `yaml:"admin" json:"admin,omitempty"`
	Auto                             *bool    `yaml:"auto" json:"auto,omitempty"`
	DeleteBranch                     *bool    `yaml:"delete_branch" json:"delete_branch,omitempty"`
	MergeStrategy                    string   `yaml:"merge_strategy" json:"merge_strategy,omitempty"`
	MergeStrategyIn                  []string `yaml:"merge_strategy_in" json:"merge_strategy_in,omitempty"`
	RunID                            string   `yaml:"run_id" json:"run_id,omitempty"`
	Failed                           *bool    `yaml:"failed" json:"failed,omitempty"`
	Job                              string   `yaml:"job" json:"job,omitempty"`
	Debug                            *bool    `yaml:"debug" json:"debug,omitempty"`
	ExitStatus                       *bool    `yaml:"exit_status" json:"exit_status,omitempty"`
}

type GitSemanticSpec struct {
	Verb            string
	VerbIn          []string
	Remote          string
	RemoteIn        []string
	Branch          string
	BranchIn        []string
	Ref             string
	RefIn           []string
	Force           *bool
	ForceWithLease  *bool
	ForceIfIncludes *bool
	Hard            *bool
	Recursive       *bool
	IncludeIgnored  *bool
	Cached          *bool
	Staged          *bool
	FlagsContains   []string
	FlagsPrefixes   []string
}

type AWSSemanticSpec struct {
	Service           string
	ServiceIn         []string
	Operation         string
	OperationIn       []string
	Profile           string
	ProfileIn         []string
	Region            string
	RegionIn          []string
	EndpointURL       string
	EndpointURLPrefix string
	DryRun            *bool
	NoCLIPager        *bool
	FlagsContains     []string
	FlagsPrefixes     []string
}

type KubectlSemanticSpec struct {
	Verb             string
	VerbIn           []string
	Subverb          string
	SubverbIn        []string
	ResourceType     string
	ResourceTypeIn   []string
	ResourceName     string
	ResourceNameIn   []string
	Namespace        string
	NamespaceIn      []string
	NamespaceMissing *bool
	Context          string
	ContextIn        []string
	Kubeconfig       string
	AllNamespaces    *bool
	Filename         string
	FilenameIn       []string
	FilenamePrefix   string
	Selector         string
	SelectorIn       []string
	SelectorContains []string
	SelectorMissing  *bool
	Container        string
	DryRun           *bool
	Force            *bool
	Recursive        *bool
	FlagsContains    []string
	FlagsPrefixes    []string
}

type GHSemanticSpec struct {
	Area                 string
	AreaIn               []string
	Verb                 string
	VerbIn               []string
	Repo                 string
	RepoIn               []string
	Org                  string
	OrgIn                []string
	EnvName              string
	EnvNameIn            []string
	Hostname             string
	HostnameIn           []string
	Web                  *bool
	Method               string
	MethodIn             []string
	Endpoint             string
	EndpointPrefix       string
	EndpointContains     []string
	Paginate             *bool
	Input                *bool
	Silent               *bool
	IncludeHeaders       *bool
	FieldKeysContains    []string
	RawFieldKeysContains []string
	HeaderKeysContains   []string
	PRNumber             string
	IssueNumber          string
	SecretName           string
	SecretNameIn         []string
	Tag                  string
	WorkflowName         string
	WorkflowID           string
	SearchType           string
	SearchTypeIn         []string
	QueryContains        string
	Base                 string
	Head                 string
	Ref                  string
	RefIn                []string
	State                string
	StateIn              []string
	LabelIn              []string
	AssigneeIn           []string
	TitleContains        string
	BodyContains         string
	Draft                *bool
	Prerelease           *bool
	Latest               *bool
	Fill                 *bool
	Force                *bool
	Admin                *bool
	Auto                 *bool
	DeleteBranch         *bool
	MergeStrategy        string
	MergeStrategyIn      []string
	RunID                string
	Failed               *bool
	Job                  string
	Debug                *bool
	ExitStatus           *bool
	FlagsContains        []string
	FlagsPrefixes        []string
}

type HelmfileSemanticSpec struct {
	Verb                             string
	VerbIn                           []string
	Environment                      string
	EnvironmentIn                    []string
	EnvironmentMissing               *bool
	File                             string
	FileIn                           []string
	FilePrefix                       string
	FileMissing                      *bool
	Namespace                        string
	NamespaceIn                      []string
	NamespaceMissing                 *bool
	KubeContext                      string
	KubeContextIn                    []string
	KubeContextMissing               *bool
	Selector                         string
	SelectorIn                       []string
	SelectorContains                 []string
	SelectorMissing                  *bool
	Interactive                      *bool
	DryRun                           *bool
	Wait                             *bool
	WaitForJobs                      *bool
	SkipDiff                         *bool
	SkipNeeds                        *bool
	IncludeNeeds                     *bool
	IncludeTransitiveNeeds           *bool
	Purge                            *bool
	Cascade                          string
	CascadeIn                        []string
	DeleteWait                       *bool
	StateValuesFile                  string
	StateValuesFileIn                []string
	StateValuesSetKeysContains       []string
	StateValuesSetStringKeysContains []string
	FlagsContains                    []string
	FlagsPrefixes                    []string
}

type ArgoCDSemanticSpec struct {
	Verb          string
	VerbIn        []string
	AppName       string
	AppNameIn     []string
	Project       string
	ProjectIn     []string
	Revision      string
	FlagsContains []string
	FlagsPrefixes []string
}

func (s SemanticMatchSpec) Git() GitSemanticSpec {
	return GitSemanticSpec{
		Verb: s.Verb, VerbIn: s.VerbIn, Remote: s.Remote, RemoteIn: s.RemoteIn,
		Branch: s.Branch, BranchIn: s.BranchIn, Ref: s.Ref, RefIn: s.RefIn,
		Force: s.Force, ForceWithLease: s.ForceWithLease, ForceIfIncludes: s.ForceIfIncludes,
		Hard: s.Hard, Recursive: s.Recursive, IncludeIgnored: s.IncludeIgnored,
		Cached: s.Cached, Staged: s.Staged, FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) AWS() AWSSemanticSpec {
	return AWSSemanticSpec{
		Service: s.Service, ServiceIn: s.ServiceIn, Operation: s.Operation, OperationIn: s.OperationIn,
		Profile: s.Profile, ProfileIn: s.ProfileIn, Region: s.Region, RegionIn: s.RegionIn,
		EndpointURL: s.EndpointURL, EndpointURLPrefix: s.EndpointURLPrefix, DryRun: s.DryRun,
		NoCLIPager: s.NoCLIPager, FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) Kubectl() KubectlSemanticSpec {
	return KubectlSemanticSpec{
		Verb: s.Verb, VerbIn: s.VerbIn, Subverb: s.Subverb, SubverbIn: s.SubverbIn,
		ResourceType: s.ResourceType, ResourceTypeIn: s.ResourceTypeIn, ResourceName: s.ResourceName,
		ResourceNameIn: s.ResourceNameIn, Namespace: s.Namespace, NamespaceIn: s.NamespaceIn,
		NamespaceMissing: s.NamespaceMissing, Context: s.Context, ContextIn: s.ContextIn,
		Kubeconfig: s.Kubeconfig, AllNamespaces: s.AllNamespaces, Filename: s.Filename,
		FilenameIn: s.FilenameIn, FilenamePrefix: s.FilenamePrefix, Selector: s.Selector,
		SelectorIn: s.SelectorIn, SelectorContains: s.SelectorContains, SelectorMissing: s.SelectorMissing,
		Container: s.Container, DryRun: s.DryRun, Force: s.Force, Recursive: s.Recursive,
		FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) GH() GHSemanticSpec {
	return GHSemanticSpec{
		Area: s.Area, AreaIn: s.AreaIn, Verb: s.Verb, VerbIn: s.VerbIn, Repo: s.Repo, RepoIn: s.RepoIn,
		Org: s.Org, OrgIn: s.OrgIn, EnvName: s.EnvName, EnvNameIn: s.EnvNameIn,
		Hostname: s.Hostname, HostnameIn: s.HostnameIn, Web: s.Web, Method: s.Method,
		MethodIn: s.MethodIn, Endpoint: s.Endpoint, EndpointPrefix: s.EndpointPrefix,
		EndpointContains: s.EndpointContains, Paginate: s.Paginate, Input: s.Input, Silent: s.Silent,
		IncludeHeaders: s.IncludeHeaders, FieldKeysContains: s.FieldKeysContains,
		RawFieldKeysContains: s.RawFieldKeysContains, HeaderKeysContains: s.HeaderKeysContains,
		PRNumber: s.PRNumber, IssueNumber: s.IssueNumber, SecretName: s.SecretName,
		SecretNameIn: s.SecretNameIn, Tag: s.Tag, WorkflowName: s.WorkflowName, WorkflowID: s.WorkflowID,
		SearchType: s.SearchType, SearchTypeIn: s.SearchTypeIn, QueryContains: s.QueryContains,
		Base: s.Base, Head: s.Head, Ref: s.Ref, RefIn: s.RefIn, State: s.State, StateIn: s.StateIn,
		LabelIn: s.LabelIn, AssigneeIn: s.AssigneeIn, TitleContains: s.TitleContains,
		BodyContains: s.BodyContains, Draft: s.Draft, Prerelease: s.Prerelease, Latest: s.Latest,
		Fill: s.Fill, Force: s.Force, Admin: s.Admin, Auto: s.Auto, DeleteBranch: s.DeleteBranch,
		MergeStrategy: s.MergeStrategy, MergeStrategyIn: s.MergeStrategyIn, RunID: s.RunID,
		Failed: s.Failed, Job: s.Job, Debug: s.Debug, ExitStatus: s.ExitStatus,
		FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) Helmfile() HelmfileSemanticSpec {
	return HelmfileSemanticSpec{
		Verb: s.Verb, VerbIn: s.VerbIn, Environment: s.Environment, EnvironmentIn: s.EnvironmentIn,
		EnvironmentMissing: s.EnvironmentMissing, File: s.File, FileIn: s.FileIn, FilePrefix: s.FilePrefix,
		FileMissing: s.FileMissing, Namespace: s.Namespace, NamespaceIn: s.NamespaceIn,
		NamespaceMissing: s.NamespaceMissing, KubeContext: s.KubeContext, KubeContextIn: s.KubeContextIn,
		KubeContextMissing: s.KubeContextMissing, Selector: s.Selector, SelectorIn: s.SelectorIn,
		SelectorContains: s.SelectorContains, SelectorMissing: s.SelectorMissing, Interactive: s.Interactive,
		DryRun: s.DryRun, Wait: s.Wait, WaitForJobs: s.WaitForJobs, SkipDiff: s.SkipDiff,
		SkipNeeds: s.SkipNeeds, IncludeNeeds: s.IncludeNeeds, IncludeTransitiveNeeds: s.IncludeTransitiveNeeds,
		Purge: s.Purge, Cascade: s.Cascade, CascadeIn: s.CascadeIn, DeleteWait: s.DeleteWait,
		StateValuesFile: s.StateValuesFile, StateValuesFileIn: s.StateValuesFileIn,
		StateValuesSetKeysContains:       s.StateValuesSetKeysContains,
		StateValuesSetStringKeysContains: s.StateValuesSetStringKeysContains,
		FlagsContains:                    s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) ArgoCD() ArgoCDSemanticSpec {
	return ArgoCDSemanticSpec{
		Verb: s.Verb, VerbIn: s.VerbIn, AppName: s.AppName, AppNameIn: s.AppNameIn,
		Project: s.Project, ProjectIn: s.ProjectIn, Revision: s.Revision,
		FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

type Source struct {
	Layer   string `json:"layer"`
	Path    string `json:"path"`
	Section string `json:"section,omitempty"`
	Index   int    `json:"index"`
}

type Pipeline struct {
	PipelineSpec
	Source   Source `json:"source"`
	prepared preparedPipeline
}

type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Issues, "; ")
}

type Decision struct {
	Outcome         string
	Explicit        bool
	Reason          string
	Command         string
	OriginalCommand string
	Message         string
	Trace           []TraceStep
}

type TraceStep struct {
	Action              string   `json:"action"`
	Name                string   `json:"name,omitempty"`
	Effect              string   `json:"effect,omitempty"`
	Explicit            bool     `json:"explicit,omitempty"`
	RuleType            string   `json:"rule_type,omitempty"`
	From                string   `json:"from,omitempty"`
	To                  string   `json:"to,omitempty"`
	Message             string   `json:"message,omitempty"`
	Reason              string   `json:"reason,omitempty"`
	Command             string   `json:"command,omitempty"`
	CommandIndex        *int     `json:"command_index,omitempty"`
	Parser              string   `json:"parser,omitempty"`
	SemanticParser      string   `json:"semantic_parser,omitempty"`
	SemanticMatch       bool     `json:"semantic_match,omitempty"`
	SemanticFields      []string `json:"semantic_fields,omitempty"`
	AWSService          string   `json:"aws_service,omitempty"`
	AWSOperation        string   `json:"aws_operation,omitempty"`
	AWSProfile          string   `json:"aws_profile,omitempty"`
	AWSRegion           string   `json:"aws_region,omitempty"`
	KubectlVerb         string   `json:"kubectl_verb,omitempty"`
	KubectlSubverb      string   `json:"kubectl_subverb,omitempty"`
	KubectlResourceType string   `json:"kubectl_resource_type,omitempty"`
	KubectlResourceName string   `json:"kubectl_resource_name,omitempty"`
	KubectlNamespace    string   `json:"kubectl_namespace,omitempty"`
	KubectlContext      string   `json:"kubectl_context,omitempty"`
	GhArea              string   `json:"gh_area,omitempty"`
	GhVerb              string   `json:"gh_verb,omitempty"`
	GhRepo              string   `json:"gh_repo,omitempty"`
	GhHostname          string   `json:"gh_hostname,omitempty"`
	GhMethod            string   `json:"gh_method,omitempty"`
	GhEndpoint          string   `json:"gh_endpoint,omitempty"`
	HelmfileVerb        string   `json:"helmfile_verb,omitempty"`
	HelmfileEnvironment string   `json:"helmfile_environment,omitempty"`
	HelmfileFile        string   `json:"helmfile_file,omitempty"`
	HelmfileNamespace   string   `json:"helmfile_namespace,omitempty"`
	HelmfileKubeContext string   `json:"helmfile_kube_context,omitempty"`
	HelmfileSelectors   []string `json:"helmfile_selectors,omitempty"`
	HelmfileInteractive *bool    `json:"helmfile_interactive,omitempty"`
	ArgoCDVerb          string   `json:"argocd_verb,omitempty"`
	ArgoCDAppName       string   `json:"argocd_app_name,omitempty"`
	ArgoCDProject       string   `json:"argocd_project,omitempty"`
	ArgoCDRevision      string   `json:"argocd_revision,omitempty"`
	FromShape           string   `json:"from_shape,omitempty"`
	FromShapeFlags      []string `json:"from_shape_flags,omitempty"`
	FromSafe            *bool    `json:"from_safe,omitempty"`
	ToShape             string   `json:"to_shape,omitempty"`
	ToShapeFlags        []string `json:"to_shape_flags,omitempty"`
	ToSafe              *bool    `json:"to_safe,omitempty"`
	Program             string   `json:"program,omitempty"`
	ProgramToken        string   `json:"program_token,omitempty"`
	NormalizedCommand   string   `json:"normalized_command,omitempty"`
	NormalizedReason    string   `json:"normalized_reason,omitempty"`
	ActionPath          []string `json:"action_path,omitempty"`
	Shape               string   `json:"shape,omitempty"`
	ShapeFlags          []string `json:"shape_flags,omitempty"`
	Relaxed             bool     `json:"relaxed,omitempty"`
	Continue            bool     `json:"continue,omitempty"`
	Source              *Source  `json:"source,omitempty"`
}

const (
	permissionRuleTypeRaw        = "raw"
	permissionRuleTypeStructured = "structured"
)

type preparedPipeline struct {
	Ready bool
	Deny  []preparedPermissionRule
	Ask   []preparedPermissionRule
	Allow []preparedPermissionRule
}

type preparedPermissionRule struct {
	Spec     PermissionRuleSpec
	Selector preparedPermissionSelector
}

type preparedSelector struct {
	Match       MatchSpec
	HasPattern  bool
	Pattern     *regexp.Regexp
	HasPatterns bool
	Patterns    []*regexp.Regexp
}

type preparedPermissionSelector struct {
	Command     PermissionCommandSpec
	Env         PermissionEnvSpec
	HasPatterns bool
	Patterns    []*regexp.Regexp
}

func NewPipeline(spec PipelineSpec, src Source) Pipeline {
	spec = stampSources(spec, src)
	return Pipeline{PipelineSpec: spec, Source: src, prepared: preparePipeline(spec)}
}

func stampSources(spec PipelineSpec, src Source) PipelineSpec {
	for i := range spec.Permission.Deny {
		if spec.Permission.Deny[i].Source == (Source{}) {
			spec.Permission.Deny[i].Source = src
		}
	}
	for i := range spec.Permission.Ask {
		if spec.Permission.Ask[i].Source == (Source{}) {
			spec.Permission.Ask[i].Source = src
		}
	}
	for i := range spec.Permission.Allow {
		if spec.Permission.Allow[i].Source == (Source{}) {
			spec.Permission.Allow[i].Source = src
		}
	}
	for i := range spec.Test {
		if spec.Test[i].Source == (Source{}) {
			spec.Test[i].Source = src
		}
	}
	return spec
}

func preparePipeline(spec PipelineSpec) preparedPipeline {
	prepared := preparedPipeline{Ready: true}
	prepared.Deny = preparePermissionRules(spec.Permission.Deny)
	prepared.Ask = preparePermissionRules(spec.Permission.Ask)
	prepared.Allow = preparePermissionRules(spec.Permission.Allow)
	return prepared
}

func preparePermissionRules(rules []PermissionRuleSpec) []preparedPermissionRule {
	prepared := make([]preparedPermissionRule, 0, len(rules))
	for _, rule := range rules {
		prepared = append(prepared, preparedPermissionRule{
			Spec:     rule,
			Selector: preparePermissionSelector(rule),
		})
	}
	return prepared
}

func preparePermissionSelector(rule PermissionRuleSpec) preparedPermissionSelector {
	selector := preparedPermissionSelector{
		Command: rule.Command,
		Env:     rule.Env,
	}
	if len(rule.Patterns) > 0 {
		selector.HasPatterns = true
		selector.Patterns = make([]*regexp.Regexp, 0, len(rule.Patterns))
		for _, p := range rule.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				selector.Patterns = append(selector.Patterns, nil)
				continue
			}
			selector.Patterns = append(selector.Patterns, re)
		}
	}
	return selector
}

func prepareSelector(match MatchSpec, pattern string, patterns []string) preparedSelector {
	selector := preparedSelector{Match: match}
	if strings.TrimSpace(pattern) != "" {
		selector.HasPattern = true
		selector.Pattern, _ = regexp.Compile(pattern)
	}
	if len(patterns) > 0 {
		selector.HasPatterns = true
		selector.Patterns = make([]*regexp.Regexp, 0, len(patterns))
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				selector.Patterns = append(selector.Patterns, nil)
				continue
			}
			selector.Patterns = append(selector.Patterns, re)
		}
	}
	return selector
}

func sourcePtr(src Source) *Source {
	if src == (Source{}) {
		return nil
	}
	return &src
}

func Evaluate(p Pipeline, command string) (Decision, error) {
	trace := []TraceStep{}
	prepared := p.prepared
	if !prepared.Ready {
		prepared = preparePipeline(stampSources(p.PipelineSpec, p.Source))
	}

	plan := commandpkg.Parse(command)
	trace = append(trace, commandPlanTraceSteps(plan)...)
	safety := commandpkg.EvaluationSafetyForPlan(plan)
	if !safety.Safe {
		trace = append(trace, unsafeCommandTraceStep(plan, safety))
	}

	if rule, cmd, ok := firstPreparedPatternPermissionMatch(prepared.Deny, command, plan); ok {
		trace = append(trace, permissionPatternTraceStep("deny", rule, cmd))
		return Decision{Outcome: "deny", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredPermissionMatch(prepared.Deny, command); ok {
		trace = append(trace, permissionTraceStepForCommand("deny", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "deny", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if !safety.Safe {
		if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, false, false); ok {
			trace = append(trace, decision.Trace...)
			return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: command, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
		}
	}
	if rule, cmd, ok := firstPreparedPatternPermissionMatch(prepared.Ask, command, plan); ok {
		trace = append(trace, permissionPatternTraceStep("ask", rule, cmd))
		return Decision{Outcome: "ask", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredPermissionMatch(prepared.Ask, command); ok {
		trace = append(trace, permissionTraceStepForCommand("ask", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "ask", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if !safety.Safe {
		if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, true, false); ok {
			trace = append(trace, decision.Trace...)
			return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: command, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
		}
		trace = append(trace, TraceStep{Action: "permission", Effect: "ask", Name: "fail_closed", Reason: strings.Join(safety.Reasons, ",")})
		return Decision{Outcome: "ask", Explicit: true, Reason: "fail_closed", Command: command, OriginalCommand: command, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedStructuredAllowPermissionMatch(prepared.Allow, command); ok {
		trace = append(trace, permissionTraceStepForCommand("allow", permissionRuleTypeStructured, rule, cmd))
		return Decision{Outcome: "allow", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, false, true); ok {
		trace = append(trace, decision.Trace...)
		return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: command, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
	}
	if rule, cmd, ok := firstPreparedPatternAllowPermissionMatch(prepared.Allow, command, plan); ok {
		trace = append(trace, permissionPatternTraceStep("allow", rule, cmd))
		return Decision{Outcome: "allow", Explicit: true, Reason: "rule_match", Command: command, OriginalCommand: command, Message: rule.Message, Trace: trace}, nil
	}
	if decision, ok := evaluateCommandPlanComposition(prepared.Deny, prepared.Ask, prepared.Allow, plan, true, true); ok {
		trace = append(trace, decision.Trace...)
		return Decision{Outcome: decision.Outcome, Explicit: true, Reason: "composition", Command: command, OriginalCommand: command, Message: decision.Message, Trace: trace}, nil
	}

	trace = append(trace, TraceStep{Action: "permission", Effect: "abstain", Name: "no_match", Reason: "no permission rule matched"})
	return Decision{Outcome: "abstain", Reason: "no_match", Command: command, OriginalCommand: command, Trace: trace}, nil
}

func commandPlanTraceSteps(plan commandpkg.CommandPlan) []TraceStep {
	steps := make([]TraceStep, 0, len(plan.Normalized))
	for _, normalized := range plan.Normalized {
		steps = append(steps, TraceStep{
			Action:            "evaluate",
			Name:              "normalized_command",
			Command:           normalized.Raw,
			ProgramToken:      normalized.OriginalToken,
			NormalizedCommand: normalized.CommandName,
			NormalizedReason:  normalized.Reason,
		})
	}
	return steps
}

func boolPtr(v bool) *bool {
	return &v
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	deduped := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		deduped = append(deduped, value)
	}
	return deduped
}

func unsafeCommandTraceStep(plan commandpkg.CommandPlan, safety commandpkg.EvaluationSafety) TraceStep {
	return TraceStep{
		Action:     "permission",
		Name:       "fail_closed",
		Effect:     "ask",
		Reason:     strings.Join(safety.Reasons, ","),
		Shape:      string(plan.Shape.Kind),
		ShapeFlags: plan.Shape.Flags(),
	}
}

func permissionTraceStep(effect string, ruleType string, rule PermissionRuleSpec) TraceStep {
	predicate := permissionPredicateSummary(rule)
	name := strings.TrimSpace(rule.Name)
	if name == "" {
		name = predicate
	}
	return TraceStep{
		Action:   "permission",
		Name:     name,
		Effect:   effect,
		RuleType: ruleType,
		Message:  rule.Message,
		Reason:   predicate,
		Source:   sourcePtr(rule.Source),
	}
}

func permissionTraceStepForCommand(effect string, ruleType string, rule PermissionRuleSpec, cmd commandpkg.Command) TraceStep {
	step := permissionTraceStep(effect, ruleType, rule)
	step.Command = cmd.Raw
	step.Program = cmd.Program
	step.ActionPath = append([]string(nil), cmd.ActionPath...)
	step.Parser = cmd.Parser
	step.SemanticParser = cmd.SemanticParser
	if cmd.AWS != nil {
		step.AWSService = cmd.AWS.Service
		step.AWSOperation = cmd.AWS.Operation
		step.AWSProfile = cmd.AWS.Profile
		step.AWSRegion = cmd.AWS.Region
	}
	if cmd.Kubectl != nil {
		step.KubectlVerb = cmd.Kubectl.Verb
		step.KubectlSubverb = cmd.Kubectl.Subverb
		step.KubectlResourceType = cmd.Kubectl.ResourceType
		step.KubectlResourceName = cmd.Kubectl.ResourceName
		step.KubectlNamespace = cmd.Kubectl.Namespace
		step.KubectlContext = cmd.Kubectl.Context
	}
	if cmd.Gh != nil {
		step.GhArea = cmd.Gh.Area
		step.GhVerb = cmd.Gh.Verb
		step.GhRepo = cmd.Gh.Repo
		step.GhHostname = cmd.Gh.Hostname
		step.GhMethod = cmd.Gh.Method
		step.GhEndpoint = cmd.Gh.Endpoint
	}
	if cmd.Helmfile != nil {
		step.HelmfileVerb = cmd.Helmfile.Verb
		step.HelmfileEnvironment = cmd.Helmfile.Environment
		step.HelmfileFile = firstString(cmd.Helmfile.Files)
		step.HelmfileNamespace = cmd.Helmfile.Namespace
		step.HelmfileKubeContext = cmd.Helmfile.KubeContext
		step.HelmfileSelectors = append([]string(nil), cmd.Helmfile.Selectors...)
		step.HelmfileInteractive = boolPtr(cmd.Helmfile.Interactive)
	}
	if cmd.ArgoCD != nil {
		step.ArgoCDVerb = cmd.ArgoCD.Verb
		step.ArgoCDAppName = cmd.ArgoCD.AppName
		step.ArgoCDProject = cmd.ArgoCD.Project
		step.ArgoCDRevision = cmd.ArgoCD.Revision
	}
	if rule.Command.Semantic != nil {
		step.SemanticMatch = true
		step.SemanticFields = rule.Command.Semantic.fieldsUsed()
	}
	return step
}

func permissionPatternTraceStep(effect string, rule PermissionRuleSpec, cmd commandpkg.Command) TraceStep {
	if cmd.Program != "" {
		return permissionTraceStepForCommand(effect, permissionRuleTypeRaw, rule, cmd)
	}
	return permissionTraceStep(effect, permissionRuleTypeRaw, rule)
}

func firstPreparedPatternPermissionMatch(rules []preparedPermissionRule, command string, plan commandpkg.CommandPlan) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesPatterns(command) {
			return rule.Spec, commandpkg.Command{}, true
		}
		for _, cmd := range plan.Commands {
			if rule.Selector.matchesCommandPatternsValue(cmd) {
				return rule.Spec, cmd, true
			}
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

func firstPreparedStructuredPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if cmd, ok := rule.Selector.matchesCommand(command); ok {
			return rule.Spec, cmd, true
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

func firstPreparedStructuredAllowPermissionMatch(rules []preparedPermissionRule, command string) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if !allowRuleCanMatch(rule.Spec, command) {
			continue
		}
		if cmd, ok := rule.Selector.matchesCommand(command); ok {
			return rule.Spec, cmd, true
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

func firstPreparedPatternAllowPermissionMatch(rules []preparedPermissionRule, command string, plan commandpkg.CommandPlan) (PermissionRuleSpec, commandpkg.Command, bool) {
	for _, rule := range rules {
		if !allowRuleCanMatch(rule.Spec, command) {
			continue
		}
		if rule.Selector.matchesPatterns(command) {
			return rule.Spec, commandpkg.Command{}, true
		}
		if len(plan.Commands) == 1 && commandAllowRuleCanMatch(plan.Commands[0]) && rule.Selector.matchesCommandPatternsValue(plan.Commands[0]) {
			return rule.Spec, plan.Commands[0], true
		}
	}
	return PermissionRuleSpec{}, commandpkg.Command{}, false
}

type commandDecision struct {
	Outcome  string
	Rule     PermissionRuleSpec
	Matched  bool
	Explicit bool
	RuleType string
	Command  commandpkg.Command
}

type compositionDecision struct {
	Outcome  string
	Message  string
	Reason   string
	Source   Source
	RuleType string
	Trace    []TraceStep
}

func evaluateCommandPlanComposition(deny []preparedPermissionRule, ask []preparedPermissionRule, allow []preparedPermissionRule, plan commandpkg.CommandPlan, includeDefaultAsk bool, allowComposition bool) (compositionDecision, bool) {
	if plan.Shape.Kind == commandpkg.ShellShapeSimple || len(plan.Commands) == 0 {
		return compositionDecision{}, false
	}

	decisions := make([]commandDecision, 0, len(plan.Commands))
	for _, cmd := range plan.Commands {
		decisions = append(decisions, evaluatePreparedCommand(deny, ask, allow, cmd))
	}

	if decision, index, ok := firstCommandDecision(decisions, "deny", true); ok {
		decision := compositionDecision{
			Outcome:  "deny",
			Message:  decision.Rule.Message,
			Source:   decision.Rule.Source,
			RuleType: decision.RuleType,
			Reason:   fmt.Sprintf("command[%d] denied", index),
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	}
	if decision, index, ok := firstCommandDecision(decisions, "ask", !includeDefaultAsk); ok {
		decision := compositionDecision{
			Outcome:  "ask",
			Message:  decision.Rule.Message,
			Source:   decision.Rule.Source,
			RuleType: decision.RuleType,
			Reason:   fmt.Sprintf("command[%d] asked", index),
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	}

	allAllowed := true
	for _, decision := range decisions {
		if decision.Outcome != "allow" {
			allAllowed = false
			break
		}
	}
	if !allAllowed {
		return compositionDecision{}, false
	}
	if !allowComposition {
		if includeDefaultAsk {
			decision := compositionDecision{
				Outcome: "ask",
				Reason:  unsafeCompositionReason(plan.Shape),
			}
			decision.Trace = compositionTrace(plan, decisions, decision)
			return decision, true
		}
		return compositionDecision{}, false
	}

	if isAllowableCompositionShape(plan.Shape) {
		decision := compositionDecision{
			Outcome:  "allow",
			Message:  decisions[0].Rule.Message,
			Source:   decisions[0].Rule.Source,
			RuleType: permissionRuleTypeStructured,
			Reason:   "all commands allowed",
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	}

	if includeDefaultAsk {
		decision := compositionDecision{
			Outcome: "ask",
			Reason:  unsafeCompositionReason(plan.Shape),
		}
		decision.Trace = compositionTrace(plan, decisions, decision)
		return decision, true
	}
	return compositionDecision{}, false
}

func isAllowableCompositionShape(shape commandpkg.ShellShape) bool {
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

func unsafeCompositionReason(shape commandpkg.ShellShape) string {
	switch {
	case shape.HasProcessSubstitution:
		return "process substitution requires confirmation"
	case shape.HasCommandSubstitution:
		return "command substitution requires confirmation"
	case shape.HasRedirection:
		return "redirection requires confirmation"
	case shape.HasSubshell:
		return "subshell requires confirmation"
	case shape.HasBackground:
		return "background execution requires confirmation"
	case shape.HasPipeline && (shape.HasConditional || shape.HasSequence):
		return "pipeline compound shape requires confirmation"
	case shape.Kind == commandpkg.ShellShapeUnknown:
		return "unknown shell shape"
	default:
		return "unsafe command shape"
	}
}

func evaluatePreparedCommand(deny []preparedPermissionRule, ask []preparedPermissionRule, allow []preparedPermissionRule, cmd commandpkg.Command) commandDecision {
	if rule, ok := firstPreparedCommandPatternMatch(deny, cmd); ok {
		return commandDecision{Outcome: "deny", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeRaw, Command: cmd}
	}
	if rule, ok := firstPreparedCommandMatch(deny, cmd); ok {
		return commandDecision{Outcome: "deny", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeStructured, Command: cmd}
	}
	if rule, ok := firstPreparedCommandPatternMatch(ask, cmd); ok {
		return commandDecision{Outcome: "ask", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeRaw, Command: cmd}
	}
	if rule, ok := firstPreparedCommandMatch(ask, cmd); ok {
		return commandDecision{Outcome: "ask", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeStructured, Command: cmd}
	}
	if hasUnresolvedSemanticGuard(deny, cmd) || hasUnresolvedSemanticGuard(ask, cmd) {
		return commandDecision{Outcome: "ask", Explicit: true, Command: cmd}
	}
	if rule, ok := firstPreparedCommandAllowMatch(allow, cmd); ok {
		return commandDecision{Outcome: "allow", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeStructured, Command: cmd}
	}
	if rule, ok := firstPreparedCommandPatternAllowMatch(allow, cmd); ok {
		return commandDecision{Outcome: "allow", Rule: rule, Matched: true, Explicit: true, RuleType: permissionRuleTypeRaw, Command: cmd}
	}
	return commandDecision{Outcome: "ask", Command: cmd}
}

func firstCommandDecision(decisions []commandDecision, outcome string, explicitOnly bool) (commandDecision, int, bool) {
	for i, decision := range decisions {
		if explicitOnly && !decision.Matched {
			continue
		}
		if decision.Outcome == outcome {
			return decision, i, true
		}
	}
	return commandDecision{}, -1, false
}

func compositionTrace(plan commandpkg.CommandPlan, decisions []commandDecision, decision compositionDecision) []TraceStep {
	trace := make([]TraceStep, 0, len(decisions)+1)
	for i, commandDecision := range decisions {
		index := i
		cmd := commandDecision.Command
		trace = append(trace, TraceStep{
			Action:              "permission",
			Name:                "composition.command",
			Effect:              commandDecision.Outcome,
			Explicit:            commandDecision.Explicit,
			RuleType:            commandDecision.RuleType,
			Command:             cmd.Raw,
			CommandIndex:        &index,
			Parser:              cmd.Parser,
			SemanticParser:      cmd.SemanticParser,
			AWSService:          awsTraceService(cmd),
			AWSOperation:        awsTraceOperation(cmd),
			AWSProfile:          awsTraceProfile(cmd),
			AWSRegion:           awsTraceRegion(cmd),
			KubectlVerb:         kubectlTraceVerb(cmd),
			KubectlSubverb:      kubectlTraceSubverb(cmd),
			KubectlResourceType: kubectlTraceResourceType(cmd),
			KubectlResourceName: kubectlTraceResourceName(cmd),
			KubectlNamespace:    kubectlTraceNamespace(cmd),
			KubectlContext:      kubectlTraceContext(cmd),
			GhArea:              ghTraceArea(cmd),
			GhVerb:              ghTraceVerb(cmd),
			GhRepo:              ghTraceRepo(cmd),
			GhHostname:          ghTraceHostname(cmd),
			GhMethod:            ghTraceMethod(cmd),
			GhEndpoint:          ghTraceEndpoint(cmd),
			HelmfileVerb:        helmfileTraceVerb(cmd),
			HelmfileEnvironment: helmfileTraceEnvironment(cmd),
			HelmfileFile:        helmfileTraceFile(cmd),
			HelmfileNamespace:   helmfileTraceNamespace(cmd),
			HelmfileKubeContext: helmfileTraceKubeContext(cmd),
			HelmfileSelectors:   helmfileTraceSelectors(cmd),
			HelmfileInteractive: helmfileTraceInteractive(cmd),
			ArgoCDVerb:          argocdTraceVerb(cmd),
			ArgoCDAppName:       argocdTraceAppName(cmd),
			ArgoCDProject:       argocdTraceProject(cmd),
			ArgoCDRevision:      argocdTraceRevision(cmd),
			Program:             cmd.Program,
			ActionPath:          append([]string(nil), cmd.ActionPath...),
			Source:              sourcePtr(commandDecision.Rule.Source),
		})
	}
	trace = append(trace, TraceStep{
		Action:     "permission",
		Effect:     decision.Outcome,
		Name:       "composition",
		RuleType:   decision.RuleType,
		Message:    decision.Message,
		Reason:     decision.Reason,
		Shape:      string(plan.Shape.Kind),
		ShapeFlags: plan.Shape.Flags(),
		Source:     sourcePtr(decision.Source),
	})
	return trace
}

func awsTraceService(cmd commandpkg.Command) string {
	if cmd.AWS == nil {
		return ""
	}
	return cmd.AWS.Service
}

func awsTraceOperation(cmd commandpkg.Command) string {
	if cmd.AWS == nil {
		return ""
	}
	return cmd.AWS.Operation
}

func awsTraceProfile(cmd commandpkg.Command) string {
	if cmd.AWS == nil {
		return ""
	}
	return cmd.AWS.Profile
}

func awsTraceRegion(cmd commandpkg.Command) string {
	if cmd.AWS == nil {
		return ""
	}
	return cmd.AWS.Region
}

func kubectlTraceVerb(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.Verb
}

func kubectlTraceSubverb(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.Subverb
}

func kubectlTraceResourceType(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.ResourceType
}

func kubectlTraceResourceName(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.ResourceName
}

func kubectlTraceNamespace(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.Namespace
}

func kubectlTraceContext(cmd commandpkg.Command) string {
	if cmd.Kubectl == nil {
		return ""
	}
	return cmd.Kubectl.Context
}

func ghTraceArea(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Area
}

func ghTraceVerb(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Verb
}

func ghTraceRepo(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Repo
}

func ghTraceHostname(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Hostname
}

func ghTraceMethod(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Method
}

func ghTraceEndpoint(cmd commandpkg.Command) string {
	if cmd.Gh == nil {
		return ""
	}
	return cmd.Gh.Endpoint
}

func helmfileTraceVerb(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return cmd.Helmfile.Verb
}

func helmfileTraceEnvironment(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return cmd.Helmfile.Environment
}

func helmfileTraceFile(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return firstString(cmd.Helmfile.Files)
}

func helmfileTraceNamespace(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return cmd.Helmfile.Namespace
}

func helmfileTraceKubeContext(cmd commandpkg.Command) string {
	if cmd.Helmfile == nil {
		return ""
	}
	return cmd.Helmfile.KubeContext
}

func helmfileTraceSelectors(cmd commandpkg.Command) []string {
	if cmd.Helmfile == nil {
		return nil
	}
	return append([]string(nil), cmd.Helmfile.Selectors...)
}

func helmfileTraceInteractive(cmd commandpkg.Command) *bool {
	if cmd.Helmfile == nil {
		return nil
	}
	return boolPtr(cmd.Helmfile.Interactive)
}

func argocdTraceVerb(cmd commandpkg.Command) string {
	if cmd.ArgoCD == nil {
		return ""
	}
	return cmd.ArgoCD.Verb
}

func argocdTraceAppName(cmd commandpkg.Command) string {
	if cmd.ArgoCD == nil {
		return ""
	}
	return cmd.ArgoCD.AppName
}

func argocdTraceProject(cmd commandpkg.Command) string {
	if cmd.ArgoCD == nil {
		return ""
	}
	return cmd.ArgoCD.Project
}

func argocdTraceRevision(cmd commandpkg.Command) string {
	if cmd.ArgoCD == nil {
		return ""
	}
	return cmd.ArgoCD.Revision
}

func firstPreparedCommandMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesCommandValue(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedCommandAllowMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesCommandValue(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedCommandPatternMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if rule.Selector.matchesCommandPatternsValue(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func firstPreparedCommandPatternAllowMatch(rules []preparedPermissionRule, cmd commandpkg.Command) (PermissionRuleSpec, bool) {
	for _, rule := range rules {
		if !commandAllowRuleCanMatch(cmd) {
			continue
		}
		if rule.Selector.matchesCommandPatternsValue(cmd) {
			return rule.Spec, true
		}
	}
	return PermissionRuleSpec{}, false
}

func hasUnresolvedSemanticGuard(rules []preparedPermissionRule, cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "" {
		return false
	}
	for _, rule := range rules {
		if !rule.Selector.hasCommandSelector() {
			continue
		}
		if rule.Selector.Command.Semantic != nil && permissionCommandStructuralScopeMatches(rule.Selector.Command, rule.Selector.Env, cmd) {
			return true
		}
	}
	return false
}

func matchRequiresSemantic(match MatchSpec) bool {
	return match.Subcommand != "" || match.Semantic != nil
}

func matchStructuralScopeMatches(match MatchSpec, cmd commandpkg.Command) bool {
	if match.Command != "" && cmd.Program != match.Command {
		return false
	}
	if len(match.CommandIn) > 0 && !containsString(match.CommandIn, cmd.Program) {
		return false
	}
	if match.CommandIsAbsolutePath && !invocation.IsAbsoluteCommand(cmd.ProgramToken) {
		return false
	}
	for _, env := range match.EnvRequires {
		if _, ok := cmd.Env[env]; !ok {
			return false
		}
	}
	for _, env := range match.EnvMissing {
		if _, ok := cmd.Env[env]; ok {
			return false
		}
	}
	return true
}

func permissionCommandStructuralScopeMatches(command PermissionCommandSpec, env PermissionEnvSpec, cmd commandpkg.Command) bool {
	if cmd.Program == "" {
		return false
	}
	if strings.TrimSpace(command.Name) != "" {
		if cmd.Program != strings.TrimSpace(command.Name) {
			return false
		}
		return permissionEnvMatches(env, cmd)
	}
	if len(command.NameIn) == 0 || !containsTrimmedString(command.NameIn, cmd.Program) {
		return false
	}
	return permissionEnvMatches(env, cmd)
}

func permissionEnvMatches(env PermissionEnvSpec, cmd commandpkg.Command) bool {
	for _, name := range env.Requires {
		if _, ok := cmd.Env[name]; !ok {
			return false
		}
	}
	for _, name := range env.Missing {
		if _, ok := cmd.Env[name]; ok {
			return false
		}
	}
	return true
}

func permissionSemanticMatches(command string, semantic SemanticMatchSpec, cmd commandpkg.Command) bool {
	switch strings.TrimSpace(command) {
	case "git":
		return semantic.Git().matches(cmd)
	case "aws":
		return semantic.AWS().matches(cmd)
	case "kubectl":
		return semantic.Kubectl().matches(cmd)
	case "gh":
		return semantic.GH().matches(cmd)
	case "helmfile":
		return semantic.Helmfile().matches(cmd)
	case "argocd":
		return semantic.ArgoCD().matches(cmd)
	default:
		return false
	}
}

func permissionPredicateSummary(rule PermissionRuleSpec) string {
	var groups []string
	if strings.TrimSpace(rule.Command.Name) != "" || len(rule.Command.NameIn) > 0 {
		groups = append(groups, "command")
		if rule.Command.Semantic != nil {
			groups = append(groups, "semantic")
		}
		if permissionCommandUsesShapeFlags(rule.Command) {
			groups = append(groups, "shape_flags")
		}
	}
	if len(rule.Patterns) > 0 {
		groups = append(groups, "patterns")
	}
	if !IsZeroPermissionEnvSpec(rule.Env) {
		groups = append(groups, "env")
	}
	if len(groups) == 0 {
		return "rule"
	}
	return strings.Join(groups, "+")
}

func allowRuleCanMatch(rule PermissionRuleSpec, command string) bool {
	plan := commandpkg.Parse(command)
	if !commandpkg.IsSafeForEvaluation(plan) {
		return false
	}
	if invocation.IsStructuredSafeForAllow(command) {
		return true
	}
	return len(plan.Commands) == 1 && commandAllowRuleCanMatch(plan.Commands[0])
}

func commandAllowRuleCanMatch(cmd commandpkg.Command) bool {
	plan := commandpkg.Parse(cmd.Raw)
	return commandpkg.IsSafeForEvaluation(plan) && invocation.IsStructuredSafeForAllow(cmd.Raw)
}

func (m MatchSpec) MatchMatches(command string) bool {
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return false
	}
	return m.matches(plan.Commands[0])
}

func PermissionRuleMatches(rule PermissionRuleSpec, command string) bool {
	selector := preparePermissionSelector(rule)
	if selector.hasCommandSelector() {
		_, ok := selector.matchesCommand(command)
		return ok
	}
	plan := commandpkg.Parse(command)
	prepared := preparedPermissionRule{Spec: rule, Selector: selector}
	_, _, ok := firstPreparedPatternPermissionMatch([]preparedPermissionRule{prepared}, command, plan)
	return ok
}

func PermissionAllowRuleMatches(rule PermissionRuleSpec, command string) bool {
	selector := preparePermissionSelector(rule)
	if selector.hasCommandSelector() {
		plan := commandpkg.Parse(command)
		if !commandpkg.IsSafeForEvaluation(plan) {
			return false
		}
		if len(plan.Commands) == 0 {
			return false
		}
		for _, cmd := range plan.Commands {
			if !selector.matchesCommandValue(cmd) {
				return false
			}
		}
		return true
	}
	plan := commandpkg.Parse(command)
	prepared := preparedPermissionRule{Spec: rule, Selector: selector}
	_, _, ok := firstPreparedPatternAllowPermissionMatch([]preparedPermissionRule{prepared}, command, plan)
	return ok
}

func selectorMatches(command string, match MatchSpec, pattern string, patterns []string) bool {
	switch {
	case !IsZeroMatchSpec(match):
		return match.MatchMatches(command)
	case strings.TrimSpace(pattern) != "":
		return patternMatches(command, pattern)
	case len(patterns) > 0:
		for _, p := range patterns {
			if patternMatches(command, p) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func (s preparedSelector) matches(command string) bool {
	switch {
	case !IsZeroMatchSpec(s.Match):
		return s.Match.MatchMatches(command)
	case s.HasPattern:
		if s.Pattern == nil {
			return false
		}
		return s.Pattern.MatchString(command)
	case s.HasPatterns:
		for _, re := range s.Patterns {
			if re != nil && re.MatchString(command) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func (s preparedSelector) hasRawSelector() bool {
	return s.HasPattern || s.HasPatterns
}

func (s preparedSelector) hasStructuredSelector() bool {
	return !IsZeroMatchSpec(s.Match)
}

func (s preparedSelector) matchesRaw(command string) bool {
	if !s.hasRawSelector() {
		return false
	}
	if s.HasPattern {
		return s.Pattern != nil && s.Pattern.MatchString(command)
	}
	for _, re := range s.Patterns {
		if re != nil && re.MatchString(command) {
			return true
		}
	}
	return false
}

func (s preparedSelector) matchesStructured(command string) (commandpkg.Command, bool) {
	if !s.hasStructuredSelector() {
		return commandpkg.Command{}, false
	}
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return commandpkg.Command{}, false
	}
	cmd := plan.Commands[0]
	return cmd, s.Match.matches(cmd)
}

func (s preparedSelector) matchesStructuredCommand(cmd commandpkg.Command) bool {
	return s.hasStructuredSelector() && s.Match.matches(cmd)
}

func (s preparedPermissionSelector) hasCommandSelector() bool {
	return strings.TrimSpace(s.Command.Name) != "" || len(s.Command.NameIn) > 0
}

func (s preparedPermissionSelector) matchesCommand(command string) (commandpkg.Command, bool) {
	if !s.hasCommandSelector() {
		return commandpkg.Command{}, false
	}
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return commandpkg.Command{}, false
	}
	cmd := plan.Commands[0]
	return cmd, s.matchesCommandValue(cmd)
}

func (s preparedPermissionSelector) matchesCommandValue(cmd commandpkg.Command) bool {
	if !s.hasCommandSelector() {
		return false
	}
	if !permissionCommandStructuralScopeMatches(s.Command, s.Env, cmd) {
		return false
	}
	if !permissionCommandShapeFlagsMatch(s.Command, cmd.ShapeFlags) {
		return false
	}
	if s.Command.Semantic != nil {
		return permissionSemanticMatches(s.Command.Name, *s.Command.Semantic, cmd)
	}
	return true
}

func permissionCommandUsesShapeFlags(command PermissionCommandSpec) bool {
	return len(command.ShapeFlagsAny) > 0 || len(command.ShapeFlagsAll) > 0 || len(command.ShapeFlagsNone) > 0
}

func permissionCommandShapeFlagsMatch(command PermissionCommandSpec, flags []string) bool {
	if len(command.ShapeFlagsAny) > 0 && !containsAnyString(flags, command.ShapeFlagsAny) {
		return false
	}
	for _, flag := range command.ShapeFlagsAll {
		if !containsString(flags, strings.TrimSpace(flag)) {
			return false
		}
	}
	for _, flag := range command.ShapeFlagsNone {
		if containsString(flags, strings.TrimSpace(flag)) {
			return false
		}
	}
	return true
}

func (s preparedPermissionSelector) matchesPatterns(command string) bool {
	if s.hasCommandSelector() {
		return false
	}
	if !s.HasPatterns {
		return s.matchesEnvOnly(command)
	}
	if !s.patternMatches(command) {
		return false
	}
	if IsZeroPermissionEnvSpec(s.Env) {
		return true
	}
	return s.matchesEnvOnly(command)
}

func (s preparedPermissionSelector) matchesCommandPatternsValue(cmd commandpkg.Command) bool {
	if !s.HasPatterns {
		return false
	}
	if !s.patternMatches(cmd.Raw) {
		return false
	}
	if IsZeroPermissionEnvSpec(s.Env) {
		return true
	}
	return permissionEnvMatches(s.Env, cmd)
}

func (s preparedPermissionSelector) patternMatches(command string) bool {
	for _, re := range s.Patterns {
		if re != nil && re.MatchString(command) {
			return true
		}
	}
	return false
}

func (s preparedPermissionSelector) matchesEnvOnly(command string) bool {
	if IsZeroPermissionEnvSpec(s.Env) {
		return false
	}
	plan := commandpkg.Parse(command)
	if len(plan.Commands) != 1 {
		return false
	}
	return permissionEnvMatches(s.Env, plan.Commands[0])
}

func patternMatches(command string, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(command)
}

func (m MatchSpec) matches(cmd commandpkg.Command) bool {
	if cmd.Program == "" {
		return false
	}
	if m.Command != "" && cmd.Program != m.Command {
		return false
	}
	if len(m.CommandIn) > 0 && !containsString(m.CommandIn, cmd.Program) {
		return false
	}
	if m.CommandIsAbsolutePath && !invocation.IsAbsoluteCommand(cmd.ProgramToken) {
		return false
	}
	if m.Subcommand != "" && commandSubcommand(cmd) != m.Subcommand {
		return false
	}
	args := commandMatchArgs(cmd)
	for _, arg := range m.ArgsContains {
		if !containsString(args, arg) {
			return false
		}
	}
	for _, prefix := range m.ArgsPrefixes {
		if !containsPrefix(args, prefix) {
			return false
		}
	}
	for _, env := range m.EnvRequires {
		if _, ok := cmd.Env[env]; !ok {
			return false
		}
	}
	for _, env := range m.EnvMissing {
		if _, ok := cmd.Env[env]; ok {
			return false
		}
	}
	if m.Semantic != nil {
		switch m.Command {
		case "git":
			if !m.Semantic.Git().matches(cmd) {
				return false
			}
		case "aws":
			if !m.Semantic.AWS().matches(cmd) {
				return false
			}
		case "kubectl":
			if !m.Semantic.Kubectl().matches(cmd) {
				return false
			}
		case "gh":
			if !m.Semantic.GH().matches(cmd) {
				return false
			}
		case "helmfile":
			if !m.Semantic.Helmfile().matches(cmd) {
				return false
			}
		case "argocd":
			if !m.Semantic.ArgoCD().matches(cmd) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s GitSemanticSpec) matches(cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "git" || cmd.Git == nil {
		return false
	}
	git := cmd.Git
	if s.Verb != "" && git.Verb != s.Verb {
		return false
	}
	if len(s.VerbIn) > 0 && !containsString(s.VerbIn, git.Verb) {
		return false
	}
	if s.Remote != "" && git.Remote != s.Remote {
		return false
	}
	if len(s.RemoteIn) > 0 && !containsString(s.RemoteIn, git.Remote) {
		return false
	}
	if s.Branch != "" && git.Branch != s.Branch {
		return false
	}
	if len(s.BranchIn) > 0 && !containsString(s.BranchIn, git.Branch) {
		return false
	}
	if s.Ref != "" && git.Ref != s.Ref {
		return false
	}
	if len(s.RefIn) > 0 && !containsString(s.RefIn, git.Ref) {
		return false
	}
	if s.Force != nil && git.Force != *s.Force {
		return false
	}
	if s.ForceWithLease != nil && git.ForceWithLease != *s.ForceWithLease {
		return false
	}
	if s.ForceIfIncludes != nil && git.ForceIfIncludes != *s.ForceIfIncludes {
		return false
	}
	if s.Hard != nil && git.Hard != *s.Hard {
		return false
	}
	if s.Recursive != nil && git.Recursive != *s.Recursive {
		return false
	}
	if s.IncludeIgnored != nil && git.IncludeIgnored != *s.IncludeIgnored {
		return false
	}
	if s.Cached != nil && git.Cached != *s.Cached {
		return false
	}
	if s.Staged != nil && git.Staged != *s.Staged {
		return false
	}
	for _, flag := range s.FlagsContains {
		if !containsString(git.Flags, flag) {
			return false
		}
	}
	for _, prefix := range s.FlagsPrefixes {
		if !containsPrefix(git.Flags, prefix) {
			return false
		}
	}
	return true
}

func (s AWSSemanticSpec) matches(cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "aws" || cmd.AWS == nil {
		return false
	}
	aws := cmd.AWS
	if s.Service != "" && aws.Service != s.Service {
		return false
	}
	if len(s.ServiceIn) > 0 && !containsString(s.ServiceIn, aws.Service) {
		return false
	}
	if s.Operation != "" && aws.Operation != s.Operation {
		return false
	}
	if len(s.OperationIn) > 0 && !containsString(s.OperationIn, aws.Operation) {
		return false
	}
	if s.Profile != "" && aws.Profile != s.Profile {
		return false
	}
	if len(s.ProfileIn) > 0 && !containsString(s.ProfileIn, aws.Profile) {
		return false
	}
	if s.Region != "" && aws.Region != s.Region {
		return false
	}
	if len(s.RegionIn) > 0 && !containsString(s.RegionIn, aws.Region) {
		return false
	}
	if s.EndpointURL != "" && aws.EndpointURL != s.EndpointURL {
		return false
	}
	if s.EndpointURLPrefix != "" && !strings.HasPrefix(aws.EndpointURL, s.EndpointURLPrefix) {
		return false
	}
	if s.DryRun != nil {
		if aws.DryRun == nil || *aws.DryRun != *s.DryRun {
			return false
		}
	}
	if s.NoCLIPager != nil {
		if aws.NoCLIPager == nil || *aws.NoCLIPager != *s.NoCLIPager {
			return false
		}
	}
	for _, flag := range s.FlagsContains {
		if !containsString(aws.Flags, flag) {
			return false
		}
	}
	for _, prefix := range s.FlagsPrefixes {
		if !containsPrefix(aws.Flags, prefix) {
			return false
		}
	}
	return true
}

func (s KubectlSemanticSpec) matches(cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "kubectl" || cmd.Kubectl == nil {
		return false
	}
	k := cmd.Kubectl
	if s.Verb != "" && k.Verb != s.Verb {
		return false
	}
	if len(s.VerbIn) > 0 && !containsString(s.VerbIn, k.Verb) {
		return false
	}
	if s.Subverb != "" && k.Subverb != s.Subverb {
		return false
	}
	if len(s.SubverbIn) > 0 && !containsString(s.SubverbIn, k.Subverb) {
		return false
	}
	if s.ResourceType != "" && k.ResourceType != s.ResourceType {
		return false
	}
	if len(s.ResourceTypeIn) > 0 && !containsString(s.ResourceTypeIn, k.ResourceType) {
		return false
	}
	if s.ResourceName != "" && k.ResourceName != s.ResourceName {
		return false
	}
	if len(s.ResourceNameIn) > 0 && !containsString(s.ResourceNameIn, k.ResourceName) {
		return false
	}
	if s.Namespace != "" && k.Namespace != s.Namespace {
		return false
	}
	if len(s.NamespaceIn) > 0 && !containsString(s.NamespaceIn, k.Namespace) {
		return false
	}
	if s.NamespaceMissing != nil && (k.Namespace == "") != *s.NamespaceMissing {
		return false
	}
	if s.Context != "" && k.Context != s.Context {
		return false
	}
	if len(s.ContextIn) > 0 && !containsString(s.ContextIn, k.Context) {
		return false
	}
	if s.Kubeconfig != "" && k.Kubeconfig != s.Kubeconfig {
		return false
	}
	if s.AllNamespaces != nil && k.AllNamespaces != *s.AllNamespaces {
		return false
	}
	if s.DryRun != nil {
		if k.DryRun == nil || *k.DryRun != *s.DryRun {
			return false
		}
	}
	if s.Force != nil && k.Force != *s.Force {
		return false
	}
	if s.Recursive != nil && k.Recursive != *s.Recursive {
		return false
	}
	if s.Filename != "" && !containsString(k.Filenames, s.Filename) {
		return false
	}
	if len(s.FilenameIn) > 0 && !containsAnyString(k.Filenames, s.FilenameIn) {
		return false
	}
	if s.FilenamePrefix != "" && !containsPrefix(k.Filenames, s.FilenamePrefix) {
		return false
	}
	if s.Selector != "" && !containsString(k.Selectors, s.Selector) {
		return false
	}
	if len(s.SelectorIn) > 0 && !containsAnyString(k.Selectors, s.SelectorIn) {
		return false
	}
	for _, value := range s.SelectorContains {
		if !containsSubstring(k.Selectors, value) {
			return false
		}
	}
	if s.SelectorMissing != nil && (len(k.Selectors) == 0) != *s.SelectorMissing {
		return false
	}
	if s.Container != "" && k.Container != s.Container {
		return false
	}
	for _, flag := range s.FlagsContains {
		if !containsString(k.Flags, flag) {
			return false
		}
	}
	for _, prefix := range s.FlagsPrefixes {
		if !containsPrefix(k.Flags, prefix) {
			return false
		}
	}
	return true
}

func (s GHSemanticSpec) matches(cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "gh" || cmd.Gh == nil {
		return false
	}
	gh := cmd.Gh
	if s.Area != "" && gh.Area != s.Area {
		return false
	}
	if len(s.AreaIn) > 0 && !containsString(s.AreaIn, gh.Area) {
		return false
	}
	if s.Verb != "" && gh.Verb != s.Verb {
		return false
	}
	if len(s.VerbIn) > 0 && !containsString(s.VerbIn, gh.Verb) {
		return false
	}
	if s.Repo != "" && gh.Repo != s.Repo {
		return false
	}
	if len(s.RepoIn) > 0 && !containsString(s.RepoIn, gh.Repo) {
		return false
	}
	if s.Org != "" && gh.Org != s.Org {
		return false
	}
	if len(s.OrgIn) > 0 && !containsString(s.OrgIn, gh.Org) {
		return false
	}
	if s.EnvName != "" && gh.EnvName != s.EnvName {
		return false
	}
	if len(s.EnvNameIn) > 0 && !containsString(s.EnvNameIn, gh.EnvName) {
		return false
	}
	if s.Hostname != "" && gh.Hostname != s.Hostname {
		return false
	}
	if len(s.HostnameIn) > 0 && !containsString(s.HostnameIn, gh.Hostname) {
		return false
	}
	if s.Web != nil && gh.Web != *s.Web {
		return false
	}
	if s.Method != "" && gh.Method != strings.ToUpper(s.Method) {
		return false
	}
	if len(s.MethodIn) > 0 && !containsStringFoldUpper(s.MethodIn, gh.Method) {
		return false
	}
	if s.Endpoint != "" && gh.Endpoint != s.Endpoint {
		return false
	}
	if s.EndpointPrefix != "" && !strings.HasPrefix(gh.Endpoint, s.EndpointPrefix) {
		return false
	}
	for _, value := range s.EndpointContains {
		if !strings.Contains(gh.Endpoint, value) {
			return false
		}
	}
	if s.Paginate != nil && gh.Paginate != *s.Paginate {
		return false
	}
	if s.Input != nil && gh.Input != *s.Input {
		return false
	}
	if s.Silent != nil && gh.Silent != *s.Silent {
		return false
	}
	if s.IncludeHeaders != nil && gh.IncludeHeaders != *s.IncludeHeaders {
		return false
	}
	for _, key := range s.FieldKeysContains {
		if !containsString(gh.FieldKeys, key) {
			return false
		}
	}
	for _, key := range s.RawFieldKeysContains {
		if !containsString(gh.RawFieldKeys, key) {
			return false
		}
	}
	for _, key := range s.HeaderKeysContains {
		if !containsString(gh.HeaderKeys, strings.ToLower(key)) {
			return false
		}
	}
	if s.PRNumber != "" && gh.PRNumber != s.PRNumber {
		return false
	}
	if s.IssueNumber != "" && gh.IssueNumber != s.IssueNumber {
		return false
	}
	if s.SecretName != "" && gh.SecretName != s.SecretName {
		return false
	}
	if len(s.SecretNameIn) > 0 && !containsString(s.SecretNameIn, gh.SecretName) {
		return false
	}
	if s.Tag != "" && gh.Tag != s.Tag {
		return false
	}
	if s.WorkflowName != "" && gh.WorkflowName != s.WorkflowName {
		return false
	}
	if s.WorkflowID != "" && gh.WorkflowID != s.WorkflowID {
		return false
	}
	if s.SearchType != "" && gh.SearchType != s.SearchType {
		return false
	}
	if len(s.SearchTypeIn) > 0 && !containsString(s.SearchTypeIn, gh.SearchType) {
		return false
	}
	if s.QueryContains != "" && !strings.Contains(gh.Query, s.QueryContains) {
		return false
	}
	if s.Base != "" && gh.Base != s.Base {
		return false
	}
	if s.Head != "" && gh.Head != s.Head {
		return false
	}
	if s.Ref != "" && gh.Ref != s.Ref {
		return false
	}
	if len(s.RefIn) > 0 && !containsString(s.RefIn, gh.Ref) {
		return false
	}
	if s.State != "" && gh.State != s.State {
		return false
	}
	if len(s.StateIn) > 0 && !containsString(s.StateIn, gh.State) {
		return false
	}
	if len(s.LabelIn) > 0 && !containsAnyString(gh.Labels, s.LabelIn) {
		return false
	}
	if len(s.AssigneeIn) > 0 && !containsAnyString(gh.Assignees, s.AssigneeIn) {
		return false
	}
	if s.TitleContains != "" && !strings.Contains(gh.Title, s.TitleContains) {
		return false
	}
	if s.BodyContains != "" && !strings.Contains(gh.Body, s.BodyContains) {
		return false
	}
	if s.Draft != nil && gh.Draft != *s.Draft {
		return false
	}
	if s.Prerelease != nil && gh.Prerelease != *s.Prerelease {
		return false
	}
	if s.Latest != nil && gh.Latest != *s.Latest {
		return false
	}
	if s.Fill != nil && gh.Fill != *s.Fill {
		return false
	}
	if s.Force != nil && gh.Force != *s.Force {
		return false
	}
	if s.Admin != nil && gh.Admin != *s.Admin {
		return false
	}
	if s.Auto != nil && gh.Auto != *s.Auto {
		return false
	}
	if s.DeleteBranch != nil && gh.DeleteBranch != *s.DeleteBranch {
		return false
	}
	if s.MergeStrategy != "" && gh.MergeStrategy != s.MergeStrategy {
		return false
	}
	if len(s.MergeStrategyIn) > 0 && !containsString(s.MergeStrategyIn, gh.MergeStrategy) {
		return false
	}
	if s.RunID != "" && gh.RunID != s.RunID {
		return false
	}
	if s.Failed != nil && gh.Failed != *s.Failed {
		return false
	}
	if s.Job != "" && gh.Job != s.Job {
		return false
	}
	if s.Debug != nil && gh.Debug != *s.Debug {
		return false
	}
	if s.ExitStatus != nil && gh.ExitStatus != *s.ExitStatus {
		return false
	}
	for _, flag := range s.FlagsContains {
		if !containsString(gh.Flags, flag) {
			return false
		}
	}
	for _, prefix := range s.FlagsPrefixes {
		if !containsPrefix(gh.Flags, prefix) {
			return false
		}
	}
	return true
}

func (s ArgoCDSemanticSpec) matches(cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "argocd" || cmd.ArgoCD == nil {
		return false
	}
	a := cmd.ArgoCD
	if s.Verb != "" && a.Verb != s.Verb {
		return false
	}
	if len(s.VerbIn) > 0 && !containsString(s.VerbIn, a.Verb) {
		return false
	}
	if s.AppName != "" && a.AppName != s.AppName {
		return false
	}
	if len(s.AppNameIn) > 0 && !containsString(s.AppNameIn, a.AppName) {
		return false
	}
	if s.Project != "" && a.Project != s.Project {
		return false
	}
	if len(s.ProjectIn) > 0 && !containsString(s.ProjectIn, a.Project) {
		return false
	}
	if s.Revision != "" && a.Revision != s.Revision {
		return false
	}
	for _, flag := range s.FlagsContains {
		if !containsString(a.Flags, flag) {
			return false
		}
	}
	for _, prefix := range s.FlagsPrefixes {
		if !containsPrefix(a.Flags, prefix) {
			return false
		}
	}
	return true
}

func (s HelmfileSemanticSpec) matches(cmd commandpkg.Command) bool {
	if cmd.SemanticParser != "helmfile" || cmd.Helmfile == nil {
		return false
	}
	h := cmd.Helmfile
	if s.Verb != "" && h.Verb != s.Verb {
		return false
	}
	if len(s.VerbIn) > 0 && !containsString(s.VerbIn, h.Verb) {
		return false
	}
	if s.Environment != "" && h.Environment != s.Environment {
		return false
	}
	if len(s.EnvironmentIn) > 0 && !containsString(s.EnvironmentIn, h.Environment) {
		return false
	}
	if s.EnvironmentMissing != nil && (h.Environment == "") != *s.EnvironmentMissing {
		return false
	}
	if s.File != "" && !containsString(h.Files, s.File) {
		return false
	}
	if len(s.FileIn) > 0 && !containsAnyString(h.Files, s.FileIn) {
		return false
	}
	if s.FilePrefix != "" && !containsPrefix(h.Files, s.FilePrefix) {
		return false
	}
	if s.FileMissing != nil && (len(h.Files) == 0) != *s.FileMissing {
		return false
	}
	if s.Namespace != "" && h.Namespace != s.Namespace {
		return false
	}
	if len(s.NamespaceIn) > 0 && !containsString(s.NamespaceIn, h.Namespace) {
		return false
	}
	if s.NamespaceMissing != nil && (h.Namespace == "") != *s.NamespaceMissing {
		return false
	}
	if s.KubeContext != "" && h.KubeContext != s.KubeContext {
		return false
	}
	if len(s.KubeContextIn) > 0 && !containsString(s.KubeContextIn, h.KubeContext) {
		return false
	}
	if s.KubeContextMissing != nil && (h.KubeContext == "") != *s.KubeContextMissing {
		return false
	}
	if s.Selector != "" && !containsString(h.Selectors, s.Selector) {
		return false
	}
	if len(s.SelectorIn) > 0 && !containsAnyString(h.Selectors, s.SelectorIn) {
		return false
	}
	for _, value := range s.SelectorContains {
		if !containsSubstring(h.Selectors, value) {
			return false
		}
	}
	if s.SelectorMissing != nil && (len(h.Selectors) == 0) != *s.SelectorMissing {
		return false
	}
	if s.Interactive != nil && h.Interactive != *s.Interactive {
		return false
	}
	if s.DryRun != nil {
		if h.DryRun == nil || *h.DryRun != *s.DryRun {
			return false
		}
	}
	if s.Wait != nil && h.Wait != *s.Wait {
		return false
	}
	if s.WaitForJobs != nil && h.WaitForJobs != *s.WaitForJobs {
		return false
	}
	if s.SkipDiff != nil && h.SkipDiff != *s.SkipDiff {
		return false
	}
	if s.SkipNeeds != nil && h.SkipNeeds != *s.SkipNeeds {
		return false
	}
	if s.IncludeNeeds != nil && h.IncludeNeeds != *s.IncludeNeeds {
		return false
	}
	if s.IncludeTransitiveNeeds != nil && h.IncludeTransitiveNeeds != *s.IncludeTransitiveNeeds {
		return false
	}
	if s.Purge != nil && h.Purge != *s.Purge {
		return false
	}
	if s.Cascade != "" && h.Cascade != s.Cascade {
		return false
	}
	if len(s.CascadeIn) > 0 && !containsString(s.CascadeIn, h.Cascade) {
		return false
	}
	if s.DeleteWait != nil && h.DeleteWait != *s.DeleteWait {
		return false
	}
	if s.StateValuesFile != "" && !containsString(h.StateValuesFiles, s.StateValuesFile) {
		return false
	}
	if len(s.StateValuesFileIn) > 0 && !containsAnyString(h.StateValuesFiles, s.StateValuesFileIn) {
		return false
	}
	for _, key := range s.StateValuesSetKeysContains {
		if !containsString(h.StateValuesSetKeys, key) {
			return false
		}
	}
	for _, key := range s.StateValuesSetStringKeysContains {
		if !containsString(h.StateValuesSetStringKeys, key) {
			return false
		}
	}
	for _, flag := range s.FlagsContains {
		if !containsString(h.Flags, flag) {
			return false
		}
	}
	for _, prefix := range s.FlagsPrefixes {
		if !containsPrefix(h.Flags, prefix) {
			return false
		}
	}
	return true
}

func (s SemanticMatchSpec) fieldsUsed() []string {
	var fields []string
	if s.Verb != "" {
		fields = append(fields, "verb")
	}
	if len(s.VerbIn) > 0 {
		fields = append(fields, "verb_in")
	}
	if s.Remote != "" {
		fields = append(fields, "remote")
	}
	if len(s.RemoteIn) > 0 {
		fields = append(fields, "remote_in")
	}
	if s.Branch != "" {
		fields = append(fields, "branch")
	}
	if len(s.BranchIn) > 0 {
		fields = append(fields, "branch_in")
	}
	if s.Ref != "" {
		fields = append(fields, "ref")
	}
	if len(s.RefIn) > 0 {
		fields = append(fields, "ref_in")
	}
	if s.Force != nil {
		fields = append(fields, "force")
	}
	if s.ForceWithLease != nil {
		fields = append(fields, "force_with_lease")
	}
	if s.ForceIfIncludes != nil {
		fields = append(fields, "force_if_includes")
	}
	if s.Hard != nil {
		fields = append(fields, "hard")
	}
	if s.Recursive != nil {
		fields = append(fields, "recursive")
	}
	if s.IncludeIgnored != nil {
		fields = append(fields, "include_ignored")
	}
	if s.Cached != nil {
		fields = append(fields, "cached")
	}
	if s.Staged != nil {
		fields = append(fields, "staged")
	}
	if len(s.FlagsContains) > 0 {
		fields = append(fields, "flags_contains")
	}
	if len(s.FlagsPrefixes) > 0 {
		fields = append(fields, "flags_prefixes")
	}
	if s.Service != "" {
		fields = append(fields, "service")
	}
	if len(s.ServiceIn) > 0 {
		fields = append(fields, "service_in")
	}
	if s.Operation != "" {
		fields = append(fields, "operation")
	}
	if len(s.OperationIn) > 0 {
		fields = append(fields, "operation_in")
	}
	if s.Profile != "" {
		fields = append(fields, "profile")
	}
	if len(s.ProfileIn) > 0 {
		fields = append(fields, "profile_in")
	}
	if s.Region != "" {
		fields = append(fields, "region")
	}
	if len(s.RegionIn) > 0 {
		fields = append(fields, "region_in")
	}
	if s.EndpointURL != "" {
		fields = append(fields, "endpoint_url")
	}
	if s.EndpointURLPrefix != "" {
		fields = append(fields, "endpoint_url_prefix")
	}
	if s.DryRun != nil {
		fields = append(fields, "dry_run")
	}
	if s.NoCLIPager != nil {
		fields = append(fields, "no_cli_pager")
	}
	if s.Subverb != "" {
		fields = append(fields, "subverb")
	}
	if len(s.SubverbIn) > 0 {
		fields = append(fields, "subverb_in")
	}
	if s.ResourceType != "" {
		fields = append(fields, "resource_type")
	}
	if len(s.ResourceTypeIn) > 0 {
		fields = append(fields, "resource_type_in")
	}
	if s.ResourceName != "" {
		fields = append(fields, "resource_name")
	}
	if len(s.ResourceNameIn) > 0 {
		fields = append(fields, "resource_name_in")
	}
	if s.Namespace != "" {
		fields = append(fields, "namespace")
	}
	if len(s.NamespaceIn) > 0 {
		fields = append(fields, "namespace_in")
	}
	if s.NamespaceMissing != nil {
		fields = append(fields, "namespace_missing")
	}
	if s.Context != "" {
		fields = append(fields, "context")
	}
	if len(s.ContextIn) > 0 {
		fields = append(fields, "context_in")
	}
	if s.Kubeconfig != "" {
		fields = append(fields, "kubeconfig")
	}
	if s.AllNamespaces != nil {
		fields = append(fields, "all_namespaces")
	}
	if s.Filename != "" {
		fields = append(fields, "filename")
	}
	if len(s.FilenameIn) > 0 {
		fields = append(fields, "filename_in")
	}
	if s.FilenamePrefix != "" {
		fields = append(fields, "filename_prefix")
	}
	if s.Selector != "" {
		fields = append(fields, "selector")
	}
	if len(s.SelectorIn) > 0 {
		fields = append(fields, "selector_in")
	}
	if len(s.SelectorContains) > 0 {
		fields = append(fields, "selector_contains")
	}
	if s.SelectorMissing != nil {
		fields = append(fields, "selector_missing")
	}
	if s.Container != "" {
		fields = append(fields, "container")
	}
	if s.Environment != "" {
		fields = append(fields, "environment")
	}
	if len(s.EnvironmentIn) > 0 {
		fields = append(fields, "environment_in")
	}
	if s.EnvironmentMissing != nil {
		fields = append(fields, "environment_missing")
	}
	if s.File != "" {
		fields = append(fields, "file")
	}
	if len(s.FileIn) > 0 {
		fields = append(fields, "file_in")
	}
	if s.FilePrefix != "" {
		fields = append(fields, "file_prefix")
	}
	if s.FileMissing != nil {
		fields = append(fields, "file_missing")
	}
	if s.KubeContext != "" {
		fields = append(fields, "kube_context")
	}
	if len(s.KubeContextIn) > 0 {
		fields = append(fields, "kube_context_in")
	}
	if s.KubeContextMissing != nil {
		fields = append(fields, "kube_context_missing")
	}
	if s.Interactive != nil {
		fields = append(fields, "interactive")
	}
	if s.Wait != nil {
		fields = append(fields, "wait")
	}
	if s.WaitForJobs != nil {
		fields = append(fields, "wait_for_jobs")
	}
	if s.SkipDiff != nil {
		fields = append(fields, "skip_diff")
	}
	if s.SkipNeeds != nil {
		fields = append(fields, "skip_needs")
	}
	if s.IncludeNeeds != nil {
		fields = append(fields, "include_needs")
	}
	if s.IncludeTransitiveNeeds != nil {
		fields = append(fields, "include_transitive_needs")
	}
	if s.Purge != nil {
		fields = append(fields, "purge")
	}
	if s.Cascade != "" {
		fields = append(fields, "cascade")
	}
	if len(s.CascadeIn) > 0 {
		fields = append(fields, "cascade_in")
	}
	if s.DeleteWait != nil {
		fields = append(fields, "delete_wait")
	}
	if s.StateValuesFile != "" {
		fields = append(fields, "state_values_file")
	}
	if len(s.StateValuesFileIn) > 0 {
		fields = append(fields, "state_values_file_in")
	}
	if len(s.StateValuesSetKeysContains) > 0 {
		fields = append(fields, "state_values_set_keys_contains")
	}
	if len(s.StateValuesSetStringKeysContains) > 0 {
		fields = append(fields, "state_values_set_string_keys_contains")
	}
	if s.Area != "" {
		fields = append(fields, "area")
	}
	if len(s.AreaIn) > 0 {
		fields = append(fields, "area_in")
	}
	if s.Repo != "" {
		fields = append(fields, "repo")
	}
	if len(s.RepoIn) > 0 {
		fields = append(fields, "repo_in")
	}
	if s.Org != "" {
		fields = append(fields, "org")
	}
	if len(s.OrgIn) > 0 {
		fields = append(fields, "org_in")
	}
	if s.EnvName != "" {
		fields = append(fields, "env")
	}
	if len(s.EnvNameIn) > 0 {
		fields = append(fields, "env_in")
	}
	if s.AppName != "" {
		fields = append(fields, "app_name")
	}
	if len(s.AppNameIn) > 0 {
		fields = append(fields, "app_name_in")
	}
	if s.Project != "" {
		fields = append(fields, "project")
	}
	if len(s.ProjectIn) > 0 {
		fields = append(fields, "project_in")
	}
	if s.Revision != "" {
		fields = append(fields, "revision")
	}
	if s.Hostname != "" {
		fields = append(fields, "hostname")
	}
	if len(s.HostnameIn) > 0 {
		fields = append(fields, "hostname_in")
	}
	if s.Web != nil {
		fields = append(fields, "web")
	}
	if s.Method != "" {
		fields = append(fields, "method")
	}
	if len(s.MethodIn) > 0 {
		fields = append(fields, "method_in")
	}
	if s.Endpoint != "" {
		fields = append(fields, "endpoint")
	}
	if s.EndpointPrefix != "" {
		fields = append(fields, "endpoint_prefix")
	}
	if len(s.EndpointContains) > 0 {
		fields = append(fields, "endpoint_contains")
	}
	if s.Paginate != nil {
		fields = append(fields, "paginate")
	}
	if s.Input != nil {
		fields = append(fields, "input")
	}
	if s.Silent != nil {
		fields = append(fields, "silent")
	}
	if s.IncludeHeaders != nil {
		fields = append(fields, "include_headers")
	}
	if len(s.FieldKeysContains) > 0 {
		fields = append(fields, "field_keys_contains")
	}
	if len(s.RawFieldKeysContains) > 0 {
		fields = append(fields, "raw_field_keys_contains")
	}
	if len(s.HeaderKeysContains) > 0 {
		fields = append(fields, "header_keys_contains")
	}
	if s.PRNumber != "" {
		fields = append(fields, "pr_number")
	}
	if s.IssueNumber != "" {
		fields = append(fields, "issue_number")
	}
	if s.SecretName != "" {
		fields = append(fields, "secret_name")
	}
	if len(s.SecretNameIn) > 0 {
		fields = append(fields, "secret_name_in")
	}
	if s.Tag != "" {
		fields = append(fields, "tag")
	}
	if s.WorkflowName != "" {
		fields = append(fields, "workflow_name")
	}
	if s.WorkflowID != "" {
		fields = append(fields, "workflow_id")
	}
	if s.SearchType != "" {
		fields = append(fields, "search_type")
	}
	if len(s.SearchTypeIn) > 0 {
		fields = append(fields, "search_type_in")
	}
	if s.QueryContains != "" {
		fields = append(fields, "query_contains")
	}
	if s.Base != "" {
		fields = append(fields, "base")
	}
	if s.Head != "" {
		fields = append(fields, "head")
	}
	if s.State != "" {
		fields = append(fields, "state")
	}
	if len(s.StateIn) > 0 {
		fields = append(fields, "state_in")
	}
	if len(s.LabelIn) > 0 {
		fields = append(fields, "label_in")
	}
	if len(s.AssigneeIn) > 0 {
		fields = append(fields, "assignee_in")
	}
	if s.TitleContains != "" {
		fields = append(fields, "title_contains")
	}
	if s.BodyContains != "" {
		fields = append(fields, "body_contains")
	}
	if s.Draft != nil {
		fields = append(fields, "draft")
	}
	if s.Prerelease != nil {
		fields = append(fields, "prerelease")
	}
	if s.Latest != nil {
		fields = append(fields, "latest")
	}
	if s.Fill != nil {
		fields = append(fields, "fill")
	}
	if s.Admin != nil {
		fields = append(fields, "admin")
	}
	if s.Auto != nil {
		fields = append(fields, "auto")
	}
	if s.DeleteBranch != nil {
		fields = append(fields, "delete_branch")
	}
	if s.MergeStrategy != "" {
		fields = append(fields, "merge_strategy")
	}
	if len(s.MergeStrategyIn) > 0 {
		fields = append(fields, "merge_strategy_in")
	}
	if s.RunID != "" {
		fields = append(fields, "run_id")
	}
	if s.Failed != nil {
		fields = append(fields, "failed")
	}
	if s.Job != "" {
		fields = append(fields, "job")
	}
	if s.Debug != nil {
		fields = append(fields, "debug")
	}
	if s.ExitStatus != nil {
		fields = append(fields, "exit_status")
	}
	return fields
}

func commandSubcommand(cmd commandpkg.Command) string {
	if len(cmd.ActionPath) == 0 {
		return structuralSubcommand(cmd)
	}
	return cmd.ActionPath[0]
}

func structuralSubcommand(cmd commandpkg.Command) string {
	for _, word := range cmd.RawWords {
		if strings.HasPrefix(word, "-") && word != "-" {
			continue
		}
		return word
	}
	return ""
}

func commandMatchArgs(cmd commandpkg.Command) []string {
	if len(cmd.RawWords) > 0 {
		return cmd.RawWords
	}
	return cmd.Args
}

func ValidatePipeline(spec PipelineSpec) []string {
	var issues []string
	if len(spec.Rewrite) > 0 {
		issues = append(issues, "top-level rewrite is no longer supported; cc-bash-guard policy evaluation no longer rewrites commands. Use permission.command / env / patterns, and rely on parser-backed normalization for evaluation.")
	}
	if IsZeroPermissionSpec(spec.Permission) {
		issues = append(issues, "must set at least one permission entry")
	}
	for i, rule := range spec.Permission.Deny {
		issues = append(issues, ValidatePermissionRule(fmt.Sprintf("permission.deny[%d]", i), rule, "deny")...)
	}
	for i, rule := range spec.Permission.Ask {
		issues = append(issues, ValidatePermissionRule(fmt.Sprintf("permission.ask[%d]", i), rule, "ask")...)
	}
	for i, rule := range spec.Permission.Allow {
		issues = append(issues, ValidatePermissionRule(fmt.Sprintf("permission.allow[%d]", i), rule, "allow")...)
	}
	issues = append(issues, ValidatePipelineTest("test", spec.Test)...)
	return issues
}

func ValidatePermissionRule(prefix string, rule PermissionRuleSpec, effect string) []string {
	var issues []string
	if strings.TrimSpace(rule.Name) == "" && rule.Name != "" {
		issues = append(issues, prefix+".name must be non-empty")
	}
	issues = append(issues, ValidatePermissionPredicates(prefix, rule, effect)...)
	issues = append(issues, ValidatePermissionTest(prefix+".test", rule.Test, effect)...)
	return issues
}

func ValidatePermissionPredicates(prefix string, rule PermissionRuleSpec, effect string) []string {
	var issues []string
	count := 0
	if !IsZeroPermissionCommandSpec(rule.Command) {
		count++
		issues = append(issues, ValidatePermissionCommandSpec(prefix+".command", rule.Command)...)
	}
	if len(rule.Patterns) > 0 {
		count++
		issues = append(issues, validateNonEmptyStrings(prefix+".patterns", rule.Patterns)...)
		for i, p := range rule.Patterns {
			if _, err := regexp.Compile(p); err != nil {
				issues = append(issues, fmt.Sprintf("%s.patterns[%d] must compile: %s", prefix, i, err.Error()))
			}
		}
	}
	if !IsZeroPermissionEnvSpec(rule.Env) {
		issues = append(issues, ValidatePermissionEnvSpec(prefix+".env", rule.Env)...)
	}
	if count == 0 && IsZeroPermissionEnvSpec(rule.Env) {
		issues = append(issues, prefix+" must set one of command, env, or patterns")
	}
	if !IsZeroPermissionCommandSpec(rule.Command) && len(rule.Patterns) > 0 {
		issues = append(issues, prefix+" cannot combine command and patterns")
	}
	return issues
}

func ValidatePermissionCommandSpec(prefix string, command PermissionCommandSpec) []string {
	var issues []string
	if command.Name != "" && len(command.NameIn) > 0 {
		issues = append(issues, prefix+".name and "+prefix+".name_in cannot both be set")
	}
	if strings.TrimSpace(command.Name) == "" {
		if command.Name != "" {
			issues = append(issues, prefix+".name must be non-empty")
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".name_in", command.NameIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".shape_flags_any", command.ShapeFlagsAny)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".shape_flags_all", command.ShapeFlagsAll)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".shape_flags_none", command.ShapeFlagsNone)...)
	if strings.TrimSpace(command.Name) == "" && len(command.NameIn) == 0 {
		issues = append(issues, prefix+".name or "+prefix+".name_in must be set")
	}
	if command.Semantic != nil {
		if len(command.NameIn) > 0 {
			issues = append(issues, prefix+".name_in cannot be used with semantic")
		}
		if strings.TrimSpace(command.Name) == "" {
			issues = append(issues, prefix+".name must be set when semantic is used")
			return issues
		}
		name := strings.TrimSpace(command.Name)
		if _, ok := semanticpkg.Lookup(name); !ok {
			issues = append(issues, unsupportedSemanticCommandIssue(prefix, name))
			return issues
		}
		unsupportedFields := unsupportedSemanticFields(name, *command.Semantic)
		if len(unsupportedFields) > 0 {
			issues = append(issues, prefix+".semantic contains fields not supported for command: "+name)
			for _, field := range unsupportedFields {
				issues = append(issues, unsupportedSemanticFieldIssue(prefix, name, field))
			}
		}
		switch name {
		case "git":
			issues = append(issues, ValidateGitSemanticMatchSpec(prefix+".semantic", *command.Semantic)...)
		case "aws":
			issues = append(issues, ValidateAWSSemanticMatchSpec(prefix+".semantic", *command.Semantic)...)
		case "kubectl":
			issues = append(issues, ValidateKubectlSemanticMatchSpec(prefix+".semantic", *command.Semantic)...)
		case "gh":
			issues = append(issues, ValidateGhSemanticMatchSpec(prefix+".semantic", *command.Semantic)...)
		case "helmfile":
			issues = append(issues, ValidateHelmfileSemanticMatchSpec(prefix+".semantic", *command.Semantic)...)
		case "argocd":
			issues = append(issues, ValidateArgoCDSemanticMatchSpec(prefix+".semantic", *command.Semantic)...)
		}
	}
	return issues
}

func ValidatePermissionEnvSpec(prefix string, env PermissionEnvSpec) []string {
	var issues []string
	issues = append(issues, validateNonEmptyStrings(prefix+".requires", env.Requires)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".missing", env.Missing)...)
	return issues
}

func ValidateSelector(prefix string, match MatchSpec, pattern string, patterns []string, required bool, allowSemantic bool) []string {
	var issues []string
	count := 0
	if !IsZeroMatchSpec(match) {
		count++
		issues = append(issues, validateMatchSpec(prefix+".match", match, allowSemantic)...)
	}
	if strings.TrimSpace(pattern) != "" {
		count++
		if _, err := regexp.Compile(pattern); err != nil {
			issues = append(issues, prefix+".pattern must compile: "+err.Error())
		}
	}
	if len(patterns) > 0 {
		count++
		issues = append(issues, validateNonEmptyStrings(prefix+".patterns", patterns)...)
		for i, p := range patterns {
			if _, err := regexp.Compile(p); err != nil {
				issues = append(issues, fmt.Sprintf("%s.patterns[%d] must compile: %s", prefix, i, err.Error()))
			}
		}
	}
	if required && count == 0 {
		issues = append(issues, prefix+" must set one of match, pattern, or patterns")
	}
	if count > 1 {
		issues = append(issues, prefix+" may set only one of match, pattern, or patterns")
	}
	return issues
}

func ValidateMatchSpec(prefix string, match MatchSpec) []string {
	return validateMatchSpec(prefix, match, true)
}

func validateMatchSpec(prefix string, match MatchSpec, allowSemantic bool) []string {
	var issues []string
	if IsZeroMatchSpec(match) {
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
	if match.Semantic != nil {
		if !allowSemantic {
			issues = append(issues, prefix+".semantic is not supported; semantic match is currently permission-only")
		}
		if strings.TrimSpace(match.Command) == "" {
			issues = append(issues, prefix+".command must be set when semantic is used")
		}
		if len(match.CommandIn) > 0 {
			issues = append(issues, prefix+".command_in cannot be used with semantic")
		}
		if match.Subcommand != "" {
			issues = append(issues, prefix+".subcommand cannot be used with semantic")
		}
		if match.Command != "" {
			if _, ok := semanticpkg.Lookup(match.Command); !ok {
				issues = append(issues, unsupportedSemanticCommandIssue(prefix, match.Command))
				return issues
			}
			unsupportedFields := unsupportedSemanticFields(match.Command, *match.Semantic)
			if len(unsupportedFields) > 0 {
				issues = append(issues, prefix+".semantic contains fields not supported for command: "+match.Command)
			}
			for _, field := range unsupportedFields {
				issues = append(issues, unsupportedSemanticFieldIssue(prefix, match.Command, field))
			}
		}
		switch match.Command {
		case "git":
			issues = append(issues, ValidateGitSemanticMatchSpec(prefix+".semantic", *match.Semantic)...)
		case "aws":
			issues = append(issues, ValidateAWSSemanticMatchSpec(prefix+".semantic", *match.Semantic)...)
		case "kubectl":
			issues = append(issues, ValidateKubectlSemanticMatchSpec(prefix+".semantic", *match.Semantic)...)
		case "gh":
			issues = append(issues, ValidateGhSemanticMatchSpec(prefix+".semantic", *match.Semantic)...)
		case "helmfile":
			issues = append(issues, ValidateHelmfileSemanticMatchSpec(prefix+".semantic", *match.Semantic)...)
		case "argocd":
			issues = append(issues, ValidateArgoCDSemanticMatchSpec(prefix+".semantic", *match.Semantic)...)
		case "":
		}
	}
	return issues
}

func unsupportedSemanticFields(command string, semantic SemanticMatchSpec) []string {
	var unsupported []string
	for _, field := range semantic.fieldsUsed() {
		if !semanticpkg.IsFieldSupported(command, field) {
			unsupported = append(unsupported, field)
		}
	}
	return unsupported
}

func unsupportedSemanticFieldIssue(prefix, command, field string) string {
	return fmt.Sprintf("%s.semantic.%s is not supported for command %s. Supported semantic fields for %s: %s. See cc-bash-guard help semantic %s or docs/user/SEMANTIC_SCHEMAS.md.", prefix, field, command, command, strings.Join(semanticpkg.FieldNames(command), ", "), command)
}

func unsupportedSemanticCommandIssue(prefix, command string) string {
	return fmt.Sprintf("%s.semantic is not available for command %s. Use patterns, or add a semantic schema/parser for %s. Supported semantic commands: %s. See cc-bash-guard help semantic and docs/user/SEMANTIC_SCHEMAS.md.", prefix, command, command, strings.Join(semanticpkg.SupportedCommands(), ", "))
}

func ValidateGitSemanticMatchSpec(prefix string, semantic SemanticMatchSpec) []string {
	return ValidateGitSemanticSpec(prefix, semantic.Git())
}

func ValidateGitSemanticSpec(prefix string, semantic GitSemanticSpec) []string {
	var issues []string
	if IsZeroGitSemanticSpec(semantic) {
		issues = append(issues, prefix+" must not be empty")
	}
	if strings.TrimSpace(semantic.Verb) == "" && semantic.Verb != "" {
		issues = append(issues, prefix+".verb must be non-empty")
	}
	if strings.TrimSpace(semantic.Remote) == "" && semantic.Remote != "" {
		issues = append(issues, prefix+".remote must be non-empty")
	}
	if strings.TrimSpace(semantic.Branch) == "" && semantic.Branch != "" {
		issues = append(issues, prefix+".branch must be non-empty")
	}
	if strings.TrimSpace(semantic.Ref) == "" && semantic.Ref != "" {
		issues = append(issues, prefix+".ref must be non-empty")
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".verb_in", semantic.VerbIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".remote_in", semantic.RemoteIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".branch_in", semantic.BranchIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".ref_in", semantic.RefIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_contains", semantic.FlagsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_prefixes", semantic.FlagsPrefixes)...)
	return issues
}

func ValidateAWSSemanticMatchSpec(prefix string, semantic SemanticMatchSpec) []string {
	return ValidateAWSSemanticSpec(prefix, semantic.AWS())
}

func ValidateAWSSemanticSpec(prefix string, semantic AWSSemanticSpec) []string {
	var issues []string
	if IsZeroAWSSemanticSpec(semantic) {
		issues = append(issues, prefix+" must not be empty")
	}
	if strings.TrimSpace(semantic.Service) == "" && semantic.Service != "" {
		issues = append(issues, prefix+".service must be non-empty")
	}
	if strings.TrimSpace(semantic.Operation) == "" && semantic.Operation != "" {
		issues = append(issues, prefix+".operation must be non-empty")
	}
	if strings.TrimSpace(semantic.Profile) == "" && semantic.Profile != "" {
		issues = append(issues, prefix+".profile must be non-empty")
	}
	if strings.TrimSpace(semantic.Region) == "" && semantic.Region != "" {
		issues = append(issues, prefix+".region must be non-empty")
	}
	if strings.TrimSpace(semantic.EndpointURL) == "" && semantic.EndpointURL != "" {
		issues = append(issues, prefix+".endpoint_url must be non-empty")
	}
	if strings.TrimSpace(semantic.EndpointURLPrefix) == "" && semantic.EndpointURLPrefix != "" {
		issues = append(issues, prefix+".endpoint_url_prefix must be non-empty")
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".service_in", semantic.ServiceIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".operation_in", semantic.OperationIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".profile_in", semantic.ProfileIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".region_in", semantic.RegionIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_contains", semantic.FlagsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_prefixes", semantic.FlagsPrefixes)...)
	return issues
}

func ValidateKubectlSemanticMatchSpec(prefix string, semantic SemanticMatchSpec) []string {
	return ValidateKubectlSemanticSpec(prefix, semantic.Kubectl())
}

func ValidateKubectlSemanticSpec(prefix string, semantic KubectlSemanticSpec) []string {
	var issues []string
	if IsZeroKubectlSemanticSpec(semantic) {
		issues = append(issues, prefix+" must not be empty")
	}
	if strings.TrimSpace(semantic.Verb) == "" && semantic.Verb != "" {
		issues = append(issues, prefix+".verb must be non-empty")
	}
	if strings.TrimSpace(semantic.Subverb) == "" && semantic.Subverb != "" {
		issues = append(issues, prefix+".subverb must be non-empty")
	}
	if strings.TrimSpace(semantic.ResourceType) == "" && semantic.ResourceType != "" {
		issues = append(issues, prefix+".resource_type must be non-empty")
	}
	if strings.TrimSpace(semantic.ResourceName) == "" && semantic.ResourceName != "" {
		issues = append(issues, prefix+".resource_name must be non-empty")
	}
	if strings.TrimSpace(semantic.Namespace) == "" && semantic.Namespace != "" {
		issues = append(issues, prefix+".namespace must be non-empty")
	}
	if strings.TrimSpace(semantic.Context) == "" && semantic.Context != "" {
		issues = append(issues, prefix+".context must be non-empty")
	}
	if strings.TrimSpace(semantic.Kubeconfig) == "" && semantic.Kubeconfig != "" {
		issues = append(issues, prefix+".kubeconfig must be non-empty")
	}
	if strings.TrimSpace(semantic.Filename) == "" && semantic.Filename != "" {
		issues = append(issues, prefix+".filename must be non-empty")
	}
	if strings.TrimSpace(semantic.FilenamePrefix) == "" && semantic.FilenamePrefix != "" {
		issues = append(issues, prefix+".filename_prefix must be non-empty")
	}
	if strings.TrimSpace(semantic.Selector) == "" && semantic.Selector != "" {
		issues = append(issues, prefix+".selector must be non-empty")
	}
	if strings.TrimSpace(semantic.Container) == "" && semantic.Container != "" {
		issues = append(issues, prefix+".container must be non-empty")
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".verb_in", semantic.VerbIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".subverb_in", semantic.SubverbIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".resource_type_in", semantic.ResourceTypeIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".resource_name_in", semantic.ResourceNameIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".namespace_in", semantic.NamespaceIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".context_in", semantic.ContextIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".filename_in", semantic.FilenameIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".selector_contains", semantic.SelectorContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_contains", semantic.FlagsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_prefixes", semantic.FlagsPrefixes)...)
	return issues
}

func ValidateGhSemanticMatchSpec(prefix string, semantic SemanticMatchSpec) []string {
	return ValidateGHSemanticSpec(prefix, semantic.GH())
}

func ValidateGHSemanticSpec(prefix string, semantic GHSemanticSpec) []string {
	var issues []string
	if IsZeroGHSemanticSpec(semantic) {
		issues = append(issues, prefix+" must not be empty")
	}
	for name, value := range map[string]string{
		"area":            semantic.Area,
		"verb":            semantic.Verb,
		"repo":            semantic.Repo,
		"org":             semantic.Org,
		"env":             semantic.EnvName,
		"hostname":        semantic.Hostname,
		"method":          semantic.Method,
		"endpoint":        semantic.Endpoint,
		"endpoint_prefix": semantic.EndpointPrefix,
		"pr_number":       semantic.PRNumber,
		"issue_number":    semantic.IssueNumber,
		"secret_name":     semantic.SecretName,
		"tag":             semantic.Tag,
		"workflow_name":   semantic.WorkflowName,
		"workflow_id":     semantic.WorkflowID,
		"search_type":     semantic.SearchType,
		"query_contains":  semantic.QueryContains,
		"base":            semantic.Base,
		"head":            semantic.Head,
		"ref":             semantic.Ref,
		"state":           semantic.State,
		"title_contains":  semantic.TitleContains,
		"body_contains":   semantic.BodyContains,
		"merge_strategy":  semantic.MergeStrategy,
		"run_id":          semantic.RunID,
		"job":             semantic.Job,
	} {
		if strings.TrimSpace(value) == "" && value != "" {
			issues = append(issues, prefix+"."+name+" must be non-empty")
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".area_in", semantic.AreaIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".verb_in", semantic.VerbIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".repo_in", semantic.RepoIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".org_in", semantic.OrgIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".env_in", semantic.EnvNameIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".hostname_in", semantic.HostnameIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".method_in", semantic.MethodIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".endpoint_contains", semantic.EndpointContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".ref_in", semantic.RefIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".state_in", semantic.StateIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".label_in", semantic.LabelIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".assignee_in", semantic.AssigneeIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".secret_name_in", semantic.SecretNameIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".search_type_in", semantic.SearchTypeIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".field_keys_contains", semantic.FieldKeysContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".raw_field_keys_contains", semantic.RawFieldKeysContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".header_keys_contains", semantic.HeaderKeysContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".merge_strategy_in", semantic.MergeStrategyIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_contains", semantic.FlagsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_prefixes", semantic.FlagsPrefixes)...)
	return issues
}

func ValidateArgoCDSemanticMatchSpec(prefix string, semantic SemanticMatchSpec) []string {
	return ValidateArgoCDSemanticSpec(prefix, semantic.ArgoCD())
}

func ValidateArgoCDSemanticSpec(prefix string, semantic ArgoCDSemanticSpec) []string {
	var issues []string
	if IsZeroArgoCDSemanticSpec(semantic) {
		issues = append(issues, prefix+" must not be empty")
	}
	for name, value := range map[string]string{
		"verb":     semantic.Verb,
		"app_name": semantic.AppName,
		"project":  semantic.Project,
		"revision": semantic.Revision,
	} {
		if strings.TrimSpace(value) == "" && value != "" {
			issues = append(issues, prefix+"."+name+" must be non-empty")
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".verb_in", semantic.VerbIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".app_name_in", semantic.AppNameIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".project_in", semantic.ProjectIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_contains", semantic.FlagsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_prefixes", semantic.FlagsPrefixes)...)
	return issues
}

func ValidateHelmfileSemanticMatchSpec(prefix string, semantic SemanticMatchSpec) []string {
	return ValidateHelmfileSemanticSpec(prefix, semantic.Helmfile())
}

func ValidateHelmfileSemanticSpec(prefix string, semantic HelmfileSemanticSpec) []string {
	var issues []string
	if IsZeroHelmfileSemanticSpec(semantic) {
		issues = append(issues, prefix+" must not be empty")
	}
	for name, value := range map[string]string{
		"verb":              semantic.Verb,
		"environment":       semantic.Environment,
		"file":              semantic.File,
		"file_prefix":       semantic.FilePrefix,
		"namespace":         semantic.Namespace,
		"kube_context":      semantic.KubeContext,
		"selector":          semantic.Selector,
		"cascade":           semantic.Cascade,
		"state_values_file": semantic.StateValuesFile,
	} {
		if strings.TrimSpace(value) == "" && value != "" {
			issues = append(issues, prefix+"."+name+" must be non-empty")
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".verb_in", semantic.VerbIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".environment_in", semantic.EnvironmentIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".file_in", semantic.FileIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".namespace_in", semantic.NamespaceIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".kube_context_in", semantic.KubeContextIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".selector_in", semantic.SelectorIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".selector_contains", semantic.SelectorContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".cascade_in", semantic.CascadeIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".state_values_file_in", semantic.StateValuesFileIn)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".state_values_set_keys_contains", semantic.StateValuesSetKeysContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".state_values_set_string_keys_contains", semantic.StateValuesSetStringKeysContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_contains", semantic.FlagsContains)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".flags_prefixes", semantic.FlagsPrefixes)...)
	return issues
}

func ValidatePermissionTest(prefix string, test PermissionTestSpec, effect string) []string {
	var issues []string
	switch effect {
	case "allow":
		if len(test.Allow) == 0 {
			issues = append(issues, prefix+".allow must be non-empty")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".allow", test.Allow)...)
		if len(test.Ask) > 0 || len(test.Deny) > 0 {
			issues = append(issues, prefix+" may only use allow and abstain")
		}
	case "ask":
		if len(test.Ask) == 0 {
			issues = append(issues, prefix+".ask must be non-empty")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".ask", test.Ask)...)
		if len(test.Allow) > 0 || len(test.Deny) > 0 {
			issues = append(issues, prefix+" may only use ask and abstain")
		}
	case "deny":
		if len(test.Deny) == 0 {
			issues = append(issues, prefix+".deny must be non-empty")
		}
		issues = append(issues, validateNonEmptyStrings(prefix+".deny", test.Deny)...)
		if len(test.Allow) > 0 || len(test.Ask) > 0 {
			issues = append(issues, prefix+" may only use deny and abstain")
		}
	}
	issues = append(issues, validateNonEmptyStrings(prefix+".abstain", test.Abstain)...)
	issues = append(issues, validateNonEmptyStrings(prefix+".pass", test.Pass)...)
	if len(test.Abstain) == 0 && len(test.Pass) == 0 {
		issues = append(issues, prefix+".abstain must be non-empty")
	}
	return issues
}

func ValidatePipelineTest(prefix string, test PipelineTestSpec) []string {
	var issues []string
	if len(test) == 0 {
		issues = append(issues, prefix+" must be non-empty")
	}
	for i, c := range test {
		if strings.TrimSpace(c.In) == "" {
			issues = append(issues, fmt.Sprintf("%s[%d].in must be non-empty", prefix, i))
		}
		if strings.TrimSpace(c.Rewritten) != "" {
			issues = append(issues, fmt.Sprintf("%s[%d].rewritten is no longer supported; cc-bash-guard policy evaluation does not rewrite commands", prefix, i))
		}
		switch c.Decision {
		case "allow", "ask", "deny":
			if c.AssertPolicyOutcome {
				issues = append(issues, fmt.Sprintf("%s[%d].decision cannot use policy-outcome assertion for %s", prefix, i, c.Decision))
			}
		case "abstain":
			if !c.AssertPolicyOutcome {
				issues = append(issues, fmt.Sprintf("%s[%d].decision abstain is only valid in bucketed test.abstain; final hook decisions are deny, ask, or allow", prefix, i))
			}
		default:
			issues = append(issues, fmt.Sprintf("%s[%d].decision must be one of allow, ask, deny", prefix, i))
		}
	}
	return issues
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

func IsZeroPermissionSpec(spec PermissionSpec) bool {
	return len(spec.Deny) == 0 && len(spec.Ask) == 0 && len(spec.Allow) == 0
}

func IsZeroPermissionCommandSpec(command PermissionCommandSpec) bool {
	return command.Name == "" &&
		len(command.NameIn) == 0 &&
		len(command.ShapeFlagsAny) == 0 &&
		len(command.ShapeFlagsAll) == 0 &&
		len(command.ShapeFlagsNone) == 0 &&
		command.Semantic == nil
}

func IsZeroPermissionEnvSpec(env PermissionEnvSpec) bool {
	return len(env.Requires) == 0 && len(env.Missing) == 0
}

func IsZeroMatchSpec(match MatchSpec) bool {
	return match.Command == "" &&
		len(match.CommandIn) == 0 &&
		!match.CommandIsAbsolutePath &&
		match.Subcommand == "" &&
		len(match.ArgsContains) == 0 &&
		len(match.ArgsPrefixes) == 0 &&
		len(match.EnvRequires) == 0 &&
		len(match.EnvMissing) == 0 &&
		match.Semantic == nil
}

func IsZeroSemanticMatchSpec(semantic SemanticMatchSpec) bool {
	return !hasGitSemanticFields(semantic) && !hasAWSSemanticFields(semantic) && !hasKubectlSemanticFields(semantic) && !hasGhSemanticFields(semantic) && !hasHelmfileSemanticFields(semantic) && !hasArgoCDSemanticFields(semantic) &&
		len(semantic.FlagsContains) == 0 &&
		len(semantic.FlagsPrefixes) == 0
}

func IsZeroGitSemanticSpec(semantic GitSemanticSpec) bool {
	return semantic.Verb == "" && len(semantic.VerbIn) == 0 &&
		semantic.Remote == "" && len(semantic.RemoteIn) == 0 &&
		semantic.Branch == "" && len(semantic.BranchIn) == 0 &&
		semantic.Ref == "" && len(semantic.RefIn) == 0 &&
		semantic.Force == nil && semantic.ForceWithLease == nil && semantic.ForceIfIncludes == nil &&
		semantic.Hard == nil && semantic.Recursive == nil && semantic.IncludeIgnored == nil &&
		semantic.Cached == nil && semantic.Staged == nil &&
		len(semantic.FlagsContains) == 0 && len(semantic.FlagsPrefixes) == 0
}

func IsZeroAWSSemanticSpec(semantic AWSSemanticSpec) bool {
	return semantic.Service == "" && len(semantic.ServiceIn) == 0 &&
		semantic.Operation == "" && len(semantic.OperationIn) == 0 &&
		semantic.Profile == "" && len(semantic.ProfileIn) == 0 &&
		semantic.Region == "" && len(semantic.RegionIn) == 0 &&
		semantic.EndpointURL == "" && semantic.EndpointURLPrefix == "" &&
		semantic.DryRun == nil && semantic.NoCLIPager == nil &&
		len(semantic.FlagsContains) == 0 && len(semantic.FlagsPrefixes) == 0
}

func IsZeroKubectlSemanticSpec(semantic KubectlSemanticSpec) bool {
	return semantic.Verb == "" && len(semantic.VerbIn) == 0 &&
		semantic.Subverb == "" && len(semantic.SubverbIn) == 0 &&
		semantic.ResourceType == "" && len(semantic.ResourceTypeIn) == 0 &&
		semantic.ResourceName == "" && len(semantic.ResourceNameIn) == 0 &&
		semantic.Namespace == "" && len(semantic.NamespaceIn) == 0 && semantic.NamespaceMissing == nil &&
		semantic.Context == "" && len(semantic.ContextIn) == 0 &&
		semantic.Kubeconfig == "" && semantic.AllNamespaces == nil &&
		semantic.Filename == "" && len(semantic.FilenameIn) == 0 && semantic.FilenamePrefix == "" &&
		semantic.Selector == "" && len(semantic.SelectorIn) == 0 && len(semantic.SelectorContains) == 0 &&
		semantic.SelectorMissing == nil && semantic.Container == "" &&
		semantic.DryRun == nil && semantic.Force == nil && semantic.Recursive == nil &&
		len(semantic.FlagsContains) == 0 && len(semantic.FlagsPrefixes) == 0
}

func IsZeroGHSemanticSpec(semantic GHSemanticSpec) bool {
	return semantic.Area == "" && len(semantic.AreaIn) == 0 &&
		semantic.Verb == "" && len(semantic.VerbIn) == 0 &&
		semantic.Repo == "" && len(semantic.RepoIn) == 0 &&
		semantic.Org == "" && len(semantic.OrgIn) == 0 &&
		semantic.EnvName == "" && len(semantic.EnvNameIn) == 0 &&
		semantic.Hostname == "" && len(semantic.HostnameIn) == 0 &&
		semantic.Web == nil && semantic.Method == "" && len(semantic.MethodIn) == 0 &&
		semantic.Endpoint == "" && semantic.EndpointPrefix == "" && len(semantic.EndpointContains) == 0 &&
		semantic.Paginate == nil && semantic.Input == nil && semantic.Silent == nil && semantic.IncludeHeaders == nil &&
		len(semantic.FieldKeysContains) == 0 && len(semantic.RawFieldKeysContains) == 0 && len(semantic.HeaderKeysContains) == 0 &&
		semantic.PRNumber == "" && semantic.IssueNumber == "" && semantic.SecretName == "" && len(semantic.SecretNameIn) == 0 &&
		semantic.Tag == "" && semantic.WorkflowName == "" && semantic.WorkflowID == "" &&
		semantic.SearchType == "" && len(semantic.SearchTypeIn) == 0 && semantic.QueryContains == "" &&
		semantic.Base == "" && semantic.Head == "" && semantic.Ref == "" && len(semantic.RefIn) == 0 &&
		semantic.State == "" && len(semantic.StateIn) == 0 && len(semantic.LabelIn) == 0 && len(semantic.AssigneeIn) == 0 &&
		semantic.TitleContains == "" && semantic.BodyContains == "" &&
		semantic.Draft == nil && semantic.Prerelease == nil && semantic.Latest == nil && semantic.Fill == nil &&
		semantic.Force == nil && semantic.Admin == nil && semantic.Auto == nil && semantic.DeleteBranch == nil &&
		semantic.MergeStrategy == "" && len(semantic.MergeStrategyIn) == 0 &&
		semantic.RunID == "" && semantic.Failed == nil && semantic.Job == "" && semantic.Debug == nil && semantic.ExitStatus == nil &&
		len(semantic.FlagsContains) == 0 && len(semantic.FlagsPrefixes) == 0
}

func IsZeroHelmfileSemanticSpec(semantic HelmfileSemanticSpec) bool {
	return semantic.Verb == "" && len(semantic.VerbIn) == 0 &&
		semantic.Environment == "" && len(semantic.EnvironmentIn) == 0 && semantic.EnvironmentMissing == nil &&
		semantic.File == "" && len(semantic.FileIn) == 0 && semantic.FilePrefix == "" && semantic.FileMissing == nil &&
		semantic.Namespace == "" && len(semantic.NamespaceIn) == 0 && semantic.NamespaceMissing == nil &&
		semantic.KubeContext == "" && len(semantic.KubeContextIn) == 0 && semantic.KubeContextMissing == nil &&
		semantic.Selector == "" && len(semantic.SelectorIn) == 0 && len(semantic.SelectorContains) == 0 && semantic.SelectorMissing == nil &&
		semantic.Interactive == nil && semantic.DryRun == nil && semantic.Wait == nil && semantic.WaitForJobs == nil &&
		semantic.SkipDiff == nil && semantic.SkipNeeds == nil && semantic.IncludeNeeds == nil && semantic.IncludeTransitiveNeeds == nil &&
		semantic.Purge == nil && semantic.Cascade == "" && len(semantic.CascadeIn) == 0 && semantic.DeleteWait == nil &&
		semantic.StateValuesFile == "" && len(semantic.StateValuesFileIn) == 0 &&
		len(semantic.StateValuesSetKeysContains) == 0 && len(semantic.StateValuesSetStringKeysContains) == 0 &&
		len(semantic.FlagsContains) == 0 && len(semantic.FlagsPrefixes) == 0
}

func IsZeroArgoCDSemanticSpec(semantic ArgoCDSemanticSpec) bool {
	return semantic.Verb == "" && len(semantic.VerbIn) == 0 &&
		semantic.AppName == "" && len(semantic.AppNameIn) == 0 &&
		semantic.Project == "" && len(semantic.ProjectIn) == 0 &&
		semantic.Revision == "" &&
		len(semantic.FlagsContains) == 0 && len(semantic.FlagsPrefixes) == 0
}

func hasGitSemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Verb != "" ||
		len(semantic.VerbIn) > 0 ||
		hasGitOnlySemanticFields(semantic) ||
		semantic.Force != nil ||
		semantic.ForceWithLease != nil ||
		semantic.ForceIfIncludes != nil ||
		semantic.Recursive != nil
}

func hasGitOnlySemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Remote != "" ||
		len(semantic.RemoteIn) > 0 ||
		semantic.Branch != "" ||
		len(semantic.BranchIn) > 0 ||
		semantic.Ref != "" ||
		len(semantic.RefIn) > 0 ||
		semantic.Hard != nil ||
		semantic.IncludeIgnored != nil ||
		semantic.Cached != nil ||
		semantic.Staged != nil
}

func hasAWSSemanticFields(semantic SemanticMatchSpec) bool {
	return hasAWSOnlySemanticFields(semantic) ||
		semantic.DryRun != nil
}

func hasAWSOnlySemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Service != "" ||
		len(semantic.ServiceIn) > 0 ||
		semantic.Operation != "" ||
		len(semantic.OperationIn) > 0 ||
		semantic.Profile != "" ||
		len(semantic.ProfileIn) > 0 ||
		semantic.Region != "" ||
		len(semantic.RegionIn) > 0 ||
		semantic.EndpointURL != "" ||
		semantic.EndpointURLPrefix != "" ||
		semantic.NoCLIPager != nil
}

func hasKubectlSemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Verb != "" ||
		len(semantic.VerbIn) > 0 ||
		semantic.Force != nil ||
		semantic.Recursive != nil ||
		semantic.DryRun != nil ||
		hasKubectlOnlySemanticFields(semantic)
}

func hasKubectlOnlySemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Subverb != "" ||
		len(semantic.SubverbIn) > 0 ||
		semantic.ResourceType != "" ||
		len(semantic.ResourceTypeIn) > 0 ||
		semantic.ResourceName != "" ||
		len(semantic.ResourceNameIn) > 0 ||
		semantic.Namespace != "" ||
		len(semantic.NamespaceIn) > 0 ||
		semantic.Context != "" ||
		len(semantic.ContextIn) > 0 ||
		semantic.Kubeconfig != "" ||
		semantic.AllNamespaces != nil ||
		semantic.Filename != "" ||
		len(semantic.FilenameIn) > 0 ||
		semantic.FilenamePrefix != "" ||
		semantic.Selector != "" ||
		len(semantic.SelectorContains) > 0 ||
		semantic.Container != ""
}

func hasKubectlOnlySemanticFieldsForHelmfile(semantic SemanticMatchSpec) bool {
	return semantic.Subverb != "" ||
		len(semantic.SubverbIn) > 0 ||
		semantic.ResourceType != "" ||
		len(semantic.ResourceTypeIn) > 0 ||
		semantic.ResourceName != "" ||
		len(semantic.ResourceNameIn) > 0 ||
		semantic.Context != "" ||
		len(semantic.ContextIn) > 0 ||
		semantic.Kubeconfig != "" ||
		semantic.AllNamespaces != nil ||
		semantic.Filename != "" ||
		len(semantic.FilenameIn) > 0 ||
		semantic.FilenamePrefix != "" ||
		semantic.Container != ""
}

func hasGhSemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Area != "" ||
		len(semantic.AreaIn) > 0 ||
		semantic.Verb != "" ||
		len(semantic.VerbIn) > 0 ||
		semantic.Repo != "" ||
		len(semantic.RepoIn) > 0 ||
		semantic.Hostname != "" ||
		len(semantic.HostnameIn) > 0 ||
		semantic.Web != nil ||
		semantic.Force != nil ||
		hasGhOnlySemanticFields(semantic)
}

func hasGhOnlySemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Method != "" ||
		len(semantic.MethodIn) > 0 ||
		semantic.Endpoint != "" ||
		semantic.EndpointPrefix != "" ||
		len(semantic.EndpointContains) > 0 ||
		semantic.Paginate != nil ||
		semantic.Input != nil ||
		semantic.Silent != nil ||
		semantic.IncludeHeaders != nil ||
		len(semantic.FieldKeysContains) > 0 ||
		len(semantic.RawFieldKeysContains) > 0 ||
		len(semantic.HeaderKeysContains) > 0 ||
		semantic.Org != "" ||
		len(semantic.OrgIn) > 0 ||
		semantic.EnvName != "" ||
		len(semantic.EnvNameIn) > 0 ||
		semantic.PRNumber != "" ||
		semantic.IssueNumber != "" ||
		semantic.SecretName != "" ||
		len(semantic.SecretNameIn) > 0 ||
		semantic.Tag != "" ||
		semantic.WorkflowName != "" ||
		semantic.WorkflowID != "" ||
		semantic.SearchType != "" ||
		len(semantic.SearchTypeIn) > 0 ||
		semantic.QueryContains != "" ||
		semantic.Base != "" ||
		semantic.Head != "" ||
		semantic.State != "" ||
		len(semantic.StateIn) > 0 ||
		len(semantic.LabelIn) > 0 ||
		len(semantic.AssigneeIn) > 0 ||
		semantic.TitleContains != "" ||
		semantic.BodyContains != "" ||
		semantic.Draft != nil ||
		semantic.Prerelease != nil ||
		semantic.Latest != nil ||
		semantic.Fill != nil ||
		semantic.Admin != nil ||
		semantic.Auto != nil ||
		semantic.DeleteBranch != nil ||
		semantic.MergeStrategy != "" ||
		len(semantic.MergeStrategyIn) > 0 ||
		semantic.RunID != "" ||
		semantic.Failed != nil ||
		semantic.Job != "" ||
		semantic.Debug != nil ||
		semantic.ExitStatus != nil
}

func hasGhNonSharedSemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Area != "" ||
		len(semantic.AreaIn) > 0 ||
		semantic.Repo != "" ||
		len(semantic.RepoIn) > 0 ||
		semantic.Hostname != "" ||
		len(semantic.HostnameIn) > 0 ||
		semantic.Web != nil ||
		hasGhOnlySemanticFields(semantic)
}

func hasHelmfileSemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Verb != "" ||
		len(semantic.VerbIn) > 0 ||
		semantic.Namespace != "" ||
		len(semantic.NamespaceIn) > 0 ||
		semantic.NamespaceMissing != nil ||
		semantic.Selector != "" ||
		len(semantic.SelectorIn) > 0 ||
		len(semantic.SelectorContains) > 0 ||
		semantic.SelectorMissing != nil ||
		semantic.DryRun != nil ||
		hasHelmfileOnlySemanticFields(semantic)
}

func hasHelmfileOnlySemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Environment != "" ||
		len(semantic.EnvironmentIn) > 0 ||
		semantic.EnvironmentMissing != nil ||
		semantic.NamespaceMissing != nil ||
		semantic.File != "" ||
		len(semantic.FileIn) > 0 ||
		semantic.FilePrefix != "" ||
		semantic.FileMissing != nil ||
		semantic.KubeContext != "" ||
		len(semantic.KubeContextIn) > 0 ||
		semantic.KubeContextMissing != nil ||
		len(semantic.SelectorIn) > 0 ||
		semantic.SelectorMissing != nil ||
		semantic.Interactive != nil ||
		semantic.Wait != nil ||
		semantic.WaitForJobs != nil ||
		semantic.SkipDiff != nil ||
		semantic.SkipNeeds != nil ||
		semantic.IncludeNeeds != nil ||
		semantic.IncludeTransitiveNeeds != nil ||
		semantic.Purge != nil ||
		semantic.Cascade != "" ||
		len(semantic.CascadeIn) > 0 ||
		semantic.DeleteWait != nil ||
		semantic.StateValuesFile != "" ||
		len(semantic.StateValuesFileIn) > 0 ||
		len(semantic.StateValuesSetKeysContains) > 0 ||
		len(semantic.StateValuesSetStringKeysContains) > 0
}

func hasArgoCDSemanticFields(semantic SemanticMatchSpec) bool {
	return semantic.Verb != "" ||
		len(semantic.VerbIn) > 0 ||
		semantic.AppName != "" ||
		len(semantic.AppNameIn) > 0 ||
		semantic.Project != "" ||
		len(semantic.ProjectIn) > 0 ||
		semantic.Revision != ""
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsTrimmedString(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func containsStringFoldUpper(values []string, want string) bool {
	for _, value := range values {
		if strings.ToUpper(value) == want {
			return true
		}
	}
	return false
}

func containsAnyString(values []string, wants []string) bool {
	for _, want := range wants {
		if containsString(values, want) {
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

func containsSubstring(values []string, substr string) bool {
	for _, value := range values {
		if strings.Contains(value, substr) {
			return true
		}
	}
	return false
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
