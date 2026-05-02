package policy

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
	Release                          string   `yaml:"release" json:"release,omitempty"`
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
	Chart                            string   `yaml:"chart" json:"chart,omitempty"`
	ChartIn                          []string `yaml:"chart_in" json:"chart_in,omitempty"`
	Install                          *bool    `yaml:"install" json:"install,omitempty"`
	ReuseValues                      *bool    `yaml:"reuse_values" json:"reuse_values,omitempty"`
	ResetValues                      *bool    `yaml:"reset_values" json:"reset_values,omitempty"`
	ResetThenReuseValues             *bool    `yaml:"reset_then_reuse_values" json:"reset_then_reuse_values,omitempty"`
	Atomic                           *bool    `yaml:"atomic" json:"atomic,omitempty"`
	CleanupOnFail                    *bool    `yaml:"cleanup_on_fail" json:"cleanup_on_fail,omitempty"`
	CreateNamespace                  *bool    `yaml:"create_namespace" json:"create_namespace,omitempty"`
	DependencyUpdate                 *bool    `yaml:"dependency_update" json:"dependency_update,omitempty"`
	Devel                            *bool    `yaml:"devel" json:"devel,omitempty"`
	KeepHistory                      *bool    `yaml:"keep_history" json:"keep_history,omitempty"`
	ValuesFile                       string   `yaml:"values_file" json:"values_file,omitempty"`
	ValuesFileIn                     []string `yaml:"values_file_in" json:"values_file_in,omitempty"`
	ValuesFilesContains              []string `yaml:"values_files" json:"values_files,omitempty"`
	SetKeysContains                  []string `yaml:"set_keys_contains" json:"set_keys_contains,omitempty"`
	SetStringKeysContains            []string `yaml:"set_string_keys_contains" json:"set_string_keys_contains,omitempty"`
	SetFileKeysContains              []string `yaml:"set_file_keys_contains" json:"set_file_keys_contains,omitempty"`
	RepoName                         string   `yaml:"repo_name" json:"repo_name,omitempty"`
	RepoURL                          string   `yaml:"repo_url" json:"repo_url,omitempty"`
	Registry                         string   `yaml:"registry" json:"registry,omitempty"`
	PluginName                       string   `yaml:"plugin_name" json:"plugin_name,omitempty"`
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
	ResourcePath                     []string `yaml:"resource_path" json:"resource_path,omitempty"`
	ResourcePathContains             []string `yaml:"resource_path_contains" json:"resource_path_contains,omitempty"`
	Helper                           *bool    `yaml:"helper" json:"helper,omitempty"`
	Mutating                         *bool    `yaml:"mutating" json:"mutating,omitempty"`
	Destructive                      *bool    `yaml:"destructive" json:"destructive,omitempty"`
	ReadOnly                         *bool    `yaml:"read_only" json:"read_only,omitempty"`
	PageAll                          *bool    `yaml:"page_all" json:"page_all,omitempty"`
	Upload                           *bool    `yaml:"upload" json:"upload,omitempty"`
	Sanitize                         *bool    `yaml:"sanitize" json:"sanitize,omitempty"`
	Params                           *bool    `yaml:"params" json:"params,omitempty"`
	JSONBody                         *bool    `yaml:"json_body" json:"json_body,omitempty"`
	Unmasked                         *bool    `yaml:"unmasked" json:"unmasked,omitempty"`
	Scopes                           []string `yaml:"scopes" json:"scopes,omitempty"`
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
	Subcommand                       string   `yaml:"subcommand" json:"subcommand,omitempty"`
	SubcommandIn                     []string `yaml:"subcommand_in" json:"subcommand_in,omitempty"`
	GlobalChdir                      string   `yaml:"global_chdir" json:"global_chdir,omitempty"`
	WorkspaceSubcommand              string   `yaml:"workspace_subcommand" json:"workspace_subcommand,omitempty"`
	WorkspaceSubcommandIn            []string `yaml:"workspace_subcommand_in" json:"workspace_subcommand_in,omitempty"`
	StateSubcommand                  string   `yaml:"state_subcommand" json:"state_subcommand,omitempty"`
	StateSubcommandIn                []string `yaml:"state_subcommand_in" json:"state_subcommand_in,omitempty"`
	Target                           *bool    `yaml:"target" json:"target,omitempty"`
	TargetsContains                  []string `yaml:"targets_contains" json:"targets_contains,omitempty"`
	Replace                          *bool    `yaml:"replace" json:"replace,omitempty"`
	ReplacesContains                 []string `yaml:"replaces_contains" json:"replaces_contains,omitempty"`
	Destroy                          *bool    `yaml:"destroy" json:"destroy,omitempty"`
	AutoApprove                      *bool    `yaml:"auto_approve" json:"auto_approve,omitempty"`
	Lock                             *bool    `yaml:"lock" json:"lock,omitempty"`
	Refresh                          *bool    `yaml:"refresh" json:"refresh,omitempty"`
	RefreshOnly                      *bool    `yaml:"refresh_only" json:"refresh_only,omitempty"`
	Out                              string   `yaml:"out" json:"out,omitempty"`
	PlanFile                         string   `yaml:"plan_file" json:"plan_file,omitempty"`
	VarFilesContains                 []string `yaml:"var_files_contains" json:"var_files_contains,omitempty"`
	Vars                             *bool    `yaml:"vars" json:"vars,omitempty"`
	Backend                          *bool    `yaml:"backend" json:"backend,omitempty"`
	Upgrade                          *bool    `yaml:"upgrade" json:"upgrade,omitempty"`
	Reconfigure                      *bool    `yaml:"reconfigure" json:"reconfigure,omitempty"`
	MigrateState                     *bool    `yaml:"migrate_state" json:"migrate_state,omitempty"`
	Check                            *bool    `yaml:"check" json:"check,omitempty"`
	JSON                             *bool    `yaml:"json" json:"json,omitempty"`
	ComposeCommand                   string   `yaml:"compose_command" json:"compose_command,omitempty"`
	ComposeCommandIn                 []string `yaml:"compose_command_in" json:"compose_command_in,omitempty"`
	Image                            string   `yaml:"image" json:"image,omitempty"`
	ImageIn                          []string `yaml:"image_in" json:"image_in,omitempty"`
	Host                             string   `yaml:"host" json:"host,omitempty"`
	HostPrefix                       string   `yaml:"host_prefix" json:"host_prefix,omitempty"`
	ProjectName                      string   `yaml:"project_name" json:"project_name,omitempty"`
	ProjectNameIn                    []string `yaml:"project_name_in" json:"project_name_in,omitempty"`
	Detach                           *bool    `yaml:"detach" json:"detach,omitempty"`
	RM                               *bool    `yaml:"rm" json:"rm,omitempty"`
	Privileged                       *bool    `yaml:"privileged" json:"privileged,omitempty"`
	Tty                              *bool    `yaml:"tty" json:"tty,omitempty"`
	User                             string   `yaml:"user" json:"user,omitempty"`
	Workdir                          string   `yaml:"workdir" json:"workdir,omitempty"`
	Entrypoint                       string   `yaml:"entrypoint" json:"entrypoint,omitempty"`
	Network                          string   `yaml:"network" json:"network,omitempty"`
	NetworkHost                      *bool    `yaml:"network_host" json:"network_host,omitempty"`
	PID                              string   `yaml:"pid" json:"pid,omitempty"`
	PIDHost                          *bool    `yaml:"pid_host" json:"pid_host,omitempty"`
	IPC                              string   `yaml:"ipc" json:"ipc,omitempty"`
	IPCHost                          *bool    `yaml:"ipc_host" json:"ipc_host,omitempty"`
	UTS                              string   `yaml:"uts" json:"uts,omitempty"`
	UTSHost                          *bool    `yaml:"uts_host" json:"uts_host,omitempty"`
	CapAddContains                   []string `yaml:"cap_add_contains" json:"cap_add_contains,omitempty"`
	CapDropContains                  []string `yaml:"cap_drop_contains" json:"cap_drop_contains,omitempty"`
	SecurityOptContains              []string `yaml:"security_opt_contains" json:"security_opt_contains,omitempty"`
	Device                           *bool    `yaml:"device" json:"device,omitempty"`
	DevicesContains                  []string `yaml:"devices_contains" json:"devices_contains,omitempty"`
	MountsContains                   []string `yaml:"mounts_contains" json:"mounts_contains,omitempty"`
	VolumesContains                  []string `yaml:"volumes_contains" json:"volumes_contains,omitempty"`
	HostMount                        *bool    `yaml:"host_mount" json:"host_mount,omitempty"`
	RootMount                        *bool    `yaml:"root_mount" json:"root_mount,omitempty"`
	DockerSocketMount                *bool    `yaml:"docker_socket_mount" json:"docker_socket_mount,omitempty"`
	EnvFilesContains                 []string `yaml:"env_files_contains" json:"env_files_contains,omitempty"`
	EnvKeysContains                  []string `yaml:"env_keys_contains" json:"env_keys_contains,omitempty"`
	PortsContains                    []string `yaml:"ports_contains" json:"ports_contains,omitempty"`
	PublishAll                       *bool    `yaml:"publish_all" json:"publish_all,omitempty"`
	Pull                             string   `yaml:"pull" json:"pull,omitempty"`
	NoCache                          *bool    `yaml:"no_cache" json:"no_cache,omitempty"`
	BuildArgKeysContains             []string `yaml:"build_arg_keys_contains" json:"build_arg_keys_contains,omitempty"`
	Platform                         string   `yaml:"platform" json:"platform,omitempty"`
	All                              *bool    `yaml:"all" json:"all,omitempty"`
	VolumesFlag                      *bool    `yaml:"volumes_flag" json:"volumes_flag,omitempty"`
	Prune                            *bool    `yaml:"prune" json:"prune,omitempty"`
	AllResources                     *bool    `yaml:"all_resources" json:"all_resources,omitempty"`
	RemoveOrphans                    *bool    `yaml:"remove_orphans" json:"remove_orphans,omitempty"`
	InnerCommand                     string   `yaml:"inner_command" json:"inner_command,omitempty"`
	InnerCommandIn                   []string `yaml:"inner_command_in" json:"inner_command_in,omitempty"`
	InnerArgsContains                []string `yaml:"inner_args_contains" json:"inner_args_contains,omitempty"`
	NullSeparated                    *bool    `yaml:"null_separated" json:"null_separated,omitempty"`
	NoRunIfEmpty                     *bool    `yaml:"no_run_if_empty" json:"no_run_if_empty,omitempty"`
	ReplaceMode                      *bool    `yaml:"replace_mode" json:"replace_mode,omitempty"`
	Parallel                         *bool    `yaml:"parallel" json:"parallel,omitempty"`
	MaxArgs                          string   `yaml:"max_args" json:"max_args,omitempty"`
	DynamicArgs                      *bool    `yaml:"dynamic_args" json:"dynamic_args,omitempty"`
	ImplicitEcho                     *bool    `yaml:"implicit_echo" json:"implicit_echo,omitempty"`
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

type GwsSemanticSpec struct {
	Service              string
	ServiceIn            []string
	ResourcePath         []string
	ResourcePathContains []string
	Method               string
	MethodIn             []string
	Helper               *bool
	Mutating             *bool
	Destructive          *bool
	ReadOnly             *bool
	DryRun               *bool
	PageAll              *bool
	Upload               *bool
	Sanitize             *bool
	Params               *bool
	JSONBody             *bool
	Unmasked             *bool
	Scopes               []string
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

type HelmSemanticSpec struct {
	Verb                  string
	VerbIn                []string
	Subverb               string
	SubverbIn             []string
	Release               string
	Chart                 string
	ChartIn               []string
	Namespace             string
	NamespaceIn           []string
	NamespaceMissing      *bool
	KubeContext           string
	KubeContextIn         []string
	KubeContextMissing    *bool
	Kubeconfig            string
	DryRun                *bool
	Force                 *bool
	Atomic                *bool
	Wait                  *bool
	WaitForJobs           *bool
	Install               *bool
	ReuseValues           *bool
	ResetValues           *bool
	ResetThenReuseValues  *bool
	CleanupOnFail         *bool
	CreateNamespace       *bool
	DependencyUpdate      *bool
	Devel                 *bool
	KeepHistory           *bool
	Cascade               string
	CascadeIn             []string
	ValuesFile            string
	ValuesFileIn          []string
	ValuesFilesContains   []string
	SetKeysContains       []string
	SetStringKeysContains []string
	SetFileKeysContains   []string
	RepoName              string
	RepoURL               string
	Registry              string
	PluginName            string
	FlagsContains         []string
	FlagsPrefixes         []string
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

type DockerSemanticSpec struct {
	Verb                 string
	VerbIn               []string
	Subverb              string
	SubverbIn            []string
	ComposeCommand       string
	ComposeCommandIn     []string
	Image                string
	ImageIn              []string
	Container            string
	Service              string
	Context              string
	ContextIn            []string
	Host                 string
	HostPrefix           string
	File                 string
	FileIn               []string
	FilePrefix           string
	ProjectName          string
	ProjectNameIn        []string
	Profile              string
	ProfileIn            []string
	DryRun               *bool
	Detach               *bool
	Interactive          *bool
	Tty                  *bool
	RM                   *bool
	Force                *bool
	Privileged           *bool
	User                 string
	Workdir              string
	Entrypoint           string
	Network              string
	NetworkHost          *bool
	PID                  string
	PIDHost              *bool
	IPC                  string
	IPCHost              *bool
	UTS                  string
	UTSHost              *bool
	CapAddContains       []string
	CapDropContains      []string
	SecurityOptContains  []string
	Device               *bool
	DevicesContains      []string
	MountsContains       []string
	VolumesContains      []string
	HostMount            *bool
	RootMount            *bool
	DockerSocketMount    *bool
	EnvFilesContains     []string
	EnvKeysContains      []string
	PortsContains        []string
	PublishAll           *bool
	Pull                 string
	NoCache              *bool
	BuildArgKeysContains []string
	Platform             string
	All                  *bool
	VolumesFlag          *bool
	Prune                *bool
	AllResources         *bool
	RemoveOrphans        *bool
	FlagsContains        []string
	FlagsPrefixes        []string
}

type TerraformSemanticSpec struct {
	Subcommand            string
	SubcommandIn          []string
	GlobalChdir           string
	WorkspaceSubcommand   string
	WorkspaceSubcommandIn []string
	StateSubcommand       string
	StateSubcommandIn     []string
	Target                *bool
	TargetsContains       []string
	Replace               *bool
	ReplacesContains      []string
	Destroy               *bool
	AutoApprove           *bool
	Input                 *bool
	Lock                  *bool
	Refresh               *bool
	RefreshOnly           *bool
	Out                   string
	PlanFile              string
	VarFilesContains      []string
	Vars                  *bool
	Backend               *bool
	Upgrade               *bool
	Reconfigure           *bool
	MigrateState          *bool
	Recursive             *bool
	Check                 *bool
	JSON                  *bool
	Force                 *bool
	FlagsContains         []string
	FlagsPrefixes         []string
}

type XargsSemanticSpec struct {
	InnerCommand      string
	InnerCommandIn    []string
	InnerArgsContains []string
	NullSeparated     *bool
	NoRunIfEmpty      *bool
	ReplaceMode       *bool
	Parallel          *bool
	MaxArgs           string
	DynamicArgs       *bool
	ImplicitEcho      *bool
	FlagsContains     []string
	FlagsPrefixes     []string
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

func (s SemanticMatchSpec) Gws() GwsSemanticSpec {
	return GwsSemanticSpec{
		Service: s.Service, ServiceIn: s.ServiceIn, ResourcePath: s.ResourcePath,
		ResourcePathContains: s.ResourcePathContains, Method: s.Method, MethodIn: s.MethodIn,
		Helper: s.Helper, Mutating: s.Mutating, Destructive: s.Destructive, ReadOnly: s.ReadOnly,
		DryRun: s.DryRun, PageAll: s.PageAll, Upload: s.Upload, Sanitize: s.Sanitize,
		Params: s.Params, JSONBody: s.JSONBody, Unmasked: s.Unmasked, Scopes: s.Scopes,
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

func (s SemanticMatchSpec) Helm() HelmSemanticSpec {
	return HelmSemanticSpec{
		Verb: s.Verb, VerbIn: s.VerbIn, Subverb: s.Subverb, SubverbIn: s.SubverbIn,
		Release: s.Release, Chart: s.Chart, ChartIn: s.ChartIn,
		Namespace: s.Namespace, NamespaceIn: s.NamespaceIn, NamespaceMissing: s.NamespaceMissing,
		KubeContext: s.KubeContext, KubeContextIn: s.KubeContextIn, KubeContextMissing: s.KubeContextMissing,
		Kubeconfig: s.Kubeconfig, DryRun: s.DryRun, Force: s.Force, Atomic: s.Atomic,
		Wait: s.Wait, WaitForJobs: s.WaitForJobs, Install: s.Install, ReuseValues: s.ReuseValues,
		ResetValues: s.ResetValues, ResetThenReuseValues: s.ResetThenReuseValues,
		CleanupOnFail: s.CleanupOnFail, CreateNamespace: s.CreateNamespace,
		DependencyUpdate: s.DependencyUpdate, Devel: s.Devel, KeepHistory: s.KeepHistory,
		Cascade: s.Cascade, CascadeIn: s.CascadeIn, ValuesFile: s.ValuesFile, ValuesFileIn: s.ValuesFileIn,
		ValuesFilesContains: s.ValuesFilesContains, SetKeysContains: s.SetKeysContains,
		SetStringKeysContains: s.SetStringKeysContains, SetFileKeysContains: s.SetFileKeysContains,
		RepoName: s.RepoName, RepoURL: s.RepoURL, Registry: s.Registry, PluginName: s.PluginName,
		FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) ArgoCD() ArgoCDSemanticSpec {
	return ArgoCDSemanticSpec{
		Verb: s.Verb, VerbIn: s.VerbIn, AppName: s.AppName, AppNameIn: s.AppNameIn,
		Project: s.Project, ProjectIn: s.ProjectIn, Revision: s.Revision,
		FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) Docker() DockerSemanticSpec {
	return DockerSemanticSpec{
		Verb: s.Verb, VerbIn: s.VerbIn, Subverb: s.Subverb, SubverbIn: s.SubverbIn,
		ComposeCommand: s.ComposeCommand, ComposeCommandIn: s.ComposeCommandIn,
		Image: s.Image, ImageIn: s.ImageIn, Container: s.Container, Service: s.Service,
		Context: s.Context, ContextIn: s.ContextIn, Host: s.Host, HostPrefix: s.HostPrefix,
		File: s.File, FileIn: s.FileIn, FilePrefix: s.FilePrefix,
		ProjectName: s.ProjectName, ProjectNameIn: s.ProjectNameIn, Profile: s.Profile, ProfileIn: s.ProfileIn,
		DryRun: s.DryRun, Detach: s.Detach, Interactive: s.Interactive, Tty: s.Tty,
		RM: s.RM, Force: s.Force, Privileged: s.Privileged, User: s.User, Workdir: s.Workdir,
		Entrypoint: s.Entrypoint, Network: s.Network, NetworkHost: s.NetworkHost, PID: s.PID,
		PIDHost: s.PIDHost, IPC: s.IPC, IPCHost: s.IPCHost, UTS: s.UTS, UTSHost: s.UTSHost,
		CapAddContains: s.CapAddContains, CapDropContains: s.CapDropContains, SecurityOptContains: s.SecurityOptContains,
		Device: s.Device, DevicesContains: s.DevicesContains, MountsContains: s.MountsContains,
		VolumesContains: s.VolumesContains, HostMount: s.HostMount, RootMount: s.RootMount,
		DockerSocketMount: s.DockerSocketMount, EnvFilesContains: s.EnvFilesContains,
		EnvKeysContains: s.EnvKeysContains, PortsContains: s.PortsContains, PublishAll: s.PublishAll,
		Pull: s.Pull, NoCache: s.NoCache, BuildArgKeysContains: s.BuildArgKeysContains,
		Platform: s.Platform, All: s.All, VolumesFlag: s.VolumesFlag,
		Prune: s.Prune, AllResources: s.AllResources, RemoveOrphans: s.RemoveOrphans,
		FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) Terraform() TerraformSemanticSpec {
	return TerraformSemanticSpec{
		Subcommand: s.Subcommand, SubcommandIn: s.SubcommandIn, GlobalChdir: s.GlobalChdir,
		WorkspaceSubcommand: s.WorkspaceSubcommand, WorkspaceSubcommandIn: s.WorkspaceSubcommandIn,
		StateSubcommand: s.StateSubcommand, StateSubcommandIn: s.StateSubcommandIn,
		Target: s.Target, TargetsContains: s.TargetsContains, Replace: s.Replace,
		ReplacesContains: s.ReplacesContains, Destroy: s.Destroy, AutoApprove: s.AutoApprove,
		Input: s.Input, Lock: s.Lock, Refresh: s.Refresh, RefreshOnly: s.RefreshOnly,
		Out: s.Out, PlanFile: s.PlanFile, VarFilesContains: s.VarFilesContains, Vars: s.Vars,
		Backend: s.Backend, Upgrade: s.Upgrade, Reconfigure: s.Reconfigure,
		MigrateState: s.MigrateState, Recursive: s.Recursive, Check: s.Check, JSON: s.JSON,
		Force: s.Force, FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}

func (s SemanticMatchSpec) Xargs() XargsSemanticSpec {
	return XargsSemanticSpec{
		InnerCommand: s.InnerCommand, InnerCommandIn: s.InnerCommandIn,
		InnerArgsContains: s.InnerArgsContains, NullSeparated: s.NullSeparated,
		NoRunIfEmpty: s.NoRunIfEmpty, ReplaceMode: s.ReplaceMode, Parallel: s.Parallel,
		MaxArgs: s.MaxArgs, DynamicArgs: s.DynamicArgs, ImplicitEcho: s.ImplicitEcho,
		FlagsContains: s.FlagsContains, FlagsPrefixes: s.FlagsPrefixes,
	}
}
