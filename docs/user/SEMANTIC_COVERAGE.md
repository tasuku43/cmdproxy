# Semantic Parser Coverage

This page is the user-facing coverage matrix for semantic command parsing.
Semantic parsing is finite and syntactic: it exposes selected command-line
fields for policy matching, but it does not prove that a command is safe at
runtime. An allowed command still keeps the normal filesystem, network,
credential, plugin, subprocess, and tool-specific capabilities of that command.

Use this page with the installed schema registry:

```sh
cc-bash-guard explain "git status"
cc-bash-guard semantic-schema --format json
cc-bash-guard help semantic git
```

`cc-bash-guard explain "<command>"` is the recommended way to inspect the actual
parser output before writing a semantic rule. The authoritative field list for
the installed binary is `cc-bash-guard semantic-schema --format json`; this page
is a generated coverage guide for humans.

## Summary Matrix

| Command | Semantic fields | Read-only examples | Mutating/destructive examples | Recommended allow posture | Known limitations |
| --- | --- | --- | --- | --- | --- |
| `git` | `verb`, `remote`, `branch`, `ref`, force/reset/clean/diff booleans, parser-recognized flags | `git status`, `git diff`, `git log` | `git push --force`, `git reset --hard`, `git clean -fdx` | Allow narrow read-only verbs; deny force-like push/reset/clean; ask for broad git. | Does not inspect hooks, aliases, remote server policy, or repository contents. |
| `aws` | `service`, `operation`, `profile`, `region`, `endpoint_url`, dry-run/pager booleans, parser-recognized flags | `aws sts get-caller-identity` | `aws iam delete-user`, `aws cloudformation deploy`, `aws s3 rm` | Allow exact low-risk service/operation/profile combinations; ask or deny write-capable services. | Does not model AWS IAM authorization, resource ARNs, request bodies, or service-specific side effects. |
| `kubectl` | `verb`, `subverb`, resource, namespace, context, file, selector, container, dry-run/force booleans, parser-recognized flags | `kubectl get pods`, `kubectl describe pod app` | `kubectl apply -f file.yaml`, `kubectl delete pod app`, `kubectl rollout restart deployment/app` | Allow read-only verbs in known contexts/namespaces; ask for apply/exec/rollout; deny deletes where needed. | Does not inspect manifests, cluster admission, RBAC, kubeconfig contents, or object state. |
| `gh` | `area`, `verb`, repo/org/env/host, `api` method/endpoint/fields, PR/issue/release/secret/run fields, merge/rerun booleans, parser-recognized flags | `gh pr view`, `gh issue view`, `gh repo view` | `gh pr merge`, `gh issue close`, `gh release delete`, `gh secret set` | Allow narrow read-only areas; deny mutating `gh api` methods; ask for broad gh. | `gh api` method and endpoint parsing is syntactic; GraphQL body contents and server authorization are not inspected. |
| `gws` | `service`, `resource_path`, `method`, helper/read-only/mutating/destructive/dry-run booleans, scopes, parser-recognized flags | service/resource/method-specific list/get forms | helper sends/uploads, update/patch/delete-style methods | Allow explicit service/resource/method rules; use inferred booleans only as conservative aids. | Google Discovery surfaces are dynamic; mutation classification is method-name inference, not an API contract. |
| `helm` | `verb`, `subverb`, release/chart, namespace/context, values/set fields, repo/registry/plugin fields, safety booleans, parser-recognized flags | `helm list`, `helm status`, `helm get values` | `helm upgrade --install`, `helm uninstall`, `helm rollback` | Allow inspection verbs; ask for install/upgrade/rollback/uninstall/plugin changes. | Does not inspect charts, values files, templates, plugins, kube credentials, or cluster effects. |
| `helmfile` | `verb`, environment/file/namespace/context/selector, dry-run/wait/diff/delete booleans, state values fields, parser-recognized flags | `helmfile diff` | `helmfile apply`, `helmfile sync`, `helmfile destroy` | Allow review commands only with expected environment/file/context; ask for apply/sync/destroy. | Does not inspect helmfile state, releases, nested helm behavior, values files, or cluster effects. |
| `argocd` | `verb`, `app_name`, `project`, `revision`, parser-recognized flags | `argocd app get my-app`, `argocd app list` | `argocd app sync my-app`, `argocd app delete my-app` | Allow read-only app verbs for known apps/projects; ask for sync/rollback/delete. | Does not inspect Argo CD RBAC, app manifests, sync waves, hooks, or server-side effects. |
| `terraform` | `subcommand`, workspace/state subcommands, `global_chdir`, target/replace/destroy/apply/init/fmt booleans, plan/var fields, parser-recognized flags | `terraform plan`, `terraform show`, `terraform validate` | `terraform apply`, `terraform destroy`, `terraform state rm`, workspace changes | Allow review/read-only subcommands narrowly; ask for apply/import/state/workspace writes; deny auto-approved destroy. | Does not inspect providers, modules, plans, state contents, backend credentials, or provisioner effects. |
| `docker` | `verb`, `subverb`, compose/image/container/service, context/host/file/project/profile, runtime risk fields, prune/build/publish booleans, parser-recognized flags | `docker ps`, `docker images`, `docker inspect` | `docker run --privileged`, host/socket mounts, `docker system prune -a --volumes`, `docker compose up` | Allow inspection verbs; deny privileged/socket/root mounts and destructive prune; ask for run/compose/build. | Does not inspect images, Dockerfiles, Compose files, daemon state, container entrypoints, or mounted file contents. |

## Policy Guidance

Prefer `permission.allow.command.semantic` for supported commands. Keep broad
command namespace behavior in `permission.ask`, not `permission.allow`, and add
explicit `permission.deny` rules for known dangerous operations. Use raw
`patterns` only for unsupported commands or gaps in semantic support.

Raw patterns should be narrow, anchored, and test-backed. Broad
`allow.patterns` such as `^aws\s+`, `^terraform\s+`, or `.*` are risky,
especially for commands with semantic parser support, because they can make a
narrow semantic rule misleading.

Before changing policy:

```sh
cc-bash-guard explain "kubectl get pods -n prod"
cc-bash-guard verify
```

Add rule-local tests and top-level tests for important allow, ask, and deny
behavior. Unsupported or ambiguous behavior should fall back to `ask` or `deny`,
not broad `allow`. After upgrading `cc-bash-guard`, run `cc-bash-guard verify`
to catch schema, parser, or policy drift before trusting existing semantic
allow rules.

<!-- BEGIN GENERATED SEMANTIC FIELD REFERENCE -->
<!-- Generated by: go generate ./internal/domain/semantic -->
<!-- Source: internal/domain/semantic/schema_*.go -->

## Field Reference

The field names below are generated from the semantic schema registry.
Field meanings come from the current schema source.

### git

Git operations such as push, clean, reset, diff, checkout, switch, and status.

**Common safe/read-only examples:**

- `git status`
- `git diff`
- `git log`

**Common mutating/destructive examples:**

- `git push --force`
- `git reset --hard`
- `git clean -fdx`

**Suggested policy style:** Allow narrow read-only verbs; deny force-like push/reset/clean; keep broad git behavior in ask.

**Known limitations / conservative fallback cases:**

- `git aliases`
- `hooks`
- `remote server policy`
- `repository contents`

Inspect parser output:

```sh
cc-bash-guard explain "git push --force origin main"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: git read-only
      command:
        name: git
        semantic:
          verb_in: [status, diff, log, show]
  deny:
    - name: git force push
      command:
        name: git
        semantic:
          verb: push
          force: true
```

| Field | Type | Meaning |
| --- | --- | --- |
| `verb` | `string` | Git verb parsed after global git options. |
| `verb_in` | `[]string` | Allowed Git verbs. |
| `remote` | `string` | Remote positional for commands such as git push. |
| `remote_in` | `[]string` | Allowed remotes. |
| `branch` | `string` | Branch positional for push, checkout, or switch. |
| `branch_in` | `[]string` | Allowed branches. |
| `ref` | `string` | Ref positional for push, reset, checkout, or switch. |
| `ref_in` | `[]string` | Allowed refs. |
| `force` | `bool` | For git push, true only when --force or -f is present. For git clean, true when -f or --force is present. |
| `force_with_lease` | `bool` | For git push, true when --force-with-lease is present. |
| `force_if_includes` | `bool` | For git push, true when --force-if-includes is present. |
| `hard` | `bool` | True for git reset --hard. |
| `recursive` | `bool` | True for git clean -d. |
| `include_ignored` | `bool` | True for git clean -x or --ignored. |
| `cached` | `bool` | True for git diff --cached or --staged. |
| `staged` | `bool` | True for git diff --cached or --staged. |
| `flags_contains` | `[]string` | Parser-recognized git option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized git option tokens that must start with these prefixes; this depends on the git parser. |

Notes:

- `force`, `force_with_lease`, and `force_if_includes` are separate git push fields; use all three when a policy should cover every force-like push syntax.
- `flags_contains` and `flags_prefixes` inspect parser-recognized option tokens, not raw argv words. GenericParser fallback never satisfies semantic flags.

### aws

AWS CLI service, operation, profile, region, endpoint, and dry-run matching.

**Common safe/read-only examples:**

- `aws sts get-caller-identity`

**Common mutating/destructive examples:**

- `aws iam delete-user`
- `aws cloudformation deploy`
- `aws s3 rm`

**Suggested policy style:** Allow exact low-risk service/operation/profile combinations; ask or deny write-capable services and operations.

**Known limitations / conservative fallback cases:**

- `AWS IAM authorization`
- `resource ARNs`
- `request bodies`
- `service-specific side effects`

Inspect parser output:

```sh
cc-bash-guard explain "aws sts get-caller-identity --profile dev"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: AWS identity
      command:
        name: aws
        semantic:
          service: sts
          operation: get-caller-identity
  ask:
    - name: AWS IAM changes
      command:
        name: aws
        semantic:
          service: iam
```

| Field | Type | Meaning |
| --- | --- | --- |
| `service` | `string` | AWS service name such as s3 or iam. |
| `service_in` | `[]string` | Allowed AWS services. |
| `operation` | `string` | AWS operation name. |
| `operation_in` | `[]string` | Allowed AWS operations. |
| `profile` | `string` | AWS profile selected by --profile or AWS_PROFILE. |
| `profile_in` | `[]string` | Allowed AWS profiles. |
| `region` | `string` | AWS region selected by --region or environment. |
| `region_in` | `[]string` | Allowed AWS regions. |
| `endpoint_url` | `string` | Exact --endpoint-url value. |
| `endpoint_url_prefix` | `string` | --endpoint-url prefix. |
| `dry_run` | `bool` | True when --dry-run is present, false when --no-dry-run is present, and unset when neither form is recognized. |
| `no_cli_pager` | `bool` | True when --no-cli-pager is present. |
| `flags_contains` | `[]string` | Parser-recognized AWS option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized AWS option tokens that must start with these prefixes; this depends on the AWS parser. |

### kubectl

Kubernetes verb, resource, namespace, context, filename, selector, and container matching.

**Common safe/read-only examples:**

- `kubectl get pods`
- `kubectl describe pod app`

**Common mutating/destructive examples:**

- `kubectl apply -f file.yaml`
- `kubectl delete pod app`
- `kubectl rollout restart deployment/app`

**Suggested policy style:** Allow read-only verbs in known contexts/namespaces; ask for apply/exec/rollout; deny deletes where needed.

**Known limitations / conservative fallback cases:**

- `manifest contents`
- `cluster admission`
- `RBAC`
- `kubeconfig contents`
- `object state`

Inspect parser output:

```sh
cc-bash-guard explain "kubectl get pods -n prod"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: kubectl read-only prod
      command:
        name: kubectl
        semantic:
          verb_in: [get, describe]
          namespace: prod
  deny:
    - name: kubectl prod delete
      command:
        name: kubectl
        semantic:
          verb: delete
          namespace: prod
```

| Field | Type | Meaning |
| --- | --- | --- |
| `verb` | `string` | kubectl verb such as get, apply, delete, or exec. |
| `verb_in` | `[]string` | Allowed kubectl verbs. |
| `subverb` | `string` | Secondary action for compound kubectl commands. |
| `subverb_in` | `[]string` | Allowed kubectl subverbs. |
| `resource_type` | `string` | Kubernetes resource type. |
| `resource_type_in` | `[]string` | Allowed resource types. |
| `resource_name` | `string` | Kubernetes resource name. |
| `resource_name_in` | `[]string` | Allowed resource names. |
| `namespace` | `string` | Namespace selected by -n or --namespace. |
| `namespace_in` | `[]string` | Allowed namespaces. |
| `namespace_missing` | `bool` | True when no namespace was selected. |
| `context` | `string` | Context selected by --context. |
| `context_in` | `[]string` | Allowed contexts. |
| `kubeconfig` | `string` | Kubeconfig path selected by --kubeconfig. |
| `all_namespaces` | `bool` | True when -A or --all-namespaces is present. |
| `filename` | `string` | Filename selected by -f or --filename. |
| `filename_in` | `[]string` | Allowed filenames. |
| `filename_prefix` | `string` | Filename prefix selected by -f or --filename. |
| `selector` | `string` | Selector selected by -l or --selector. |
| `selector_in` | `[]string` | Allowed selectors. |
| `selector_contains` | `[]string` | Selectors that must be present. |
| `selector_missing` | `bool` | True when no selector was selected. |
| `container` | `string` | Container selected by -c or --container. |
| `dry_run` | `bool` | True when --dry-run or a --dry-run value other than none is present; false when --dry-run=none is present; unset when absent. |
| `force` | `bool` | True when --force is present. |
| `recursive` | `bool` | True when -R or --recursive is present. |
| `flags_contains` | `[]string` | Parser-recognized kubectl option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized kubectl option tokens that must start with these prefixes; this depends on the kubectl parser. |

### gh

GitHub CLI api, pr, issue, repo, release, secret, search, workflow, auth, and run operations.

**Common safe/read-only examples:**

- `gh pr view`
- `gh issue view`
- `gh repo view`

**Common mutating/destructive examples:**

- `gh pr merge`
- `gh issue close`
- `gh release delete`
- `gh secret set`

**Suggested policy style:** Allow narrow read-only areas; deny mutating gh api methods; keep broad gh behavior in ask.

**Known limitations / conservative fallback cases:**

- `gh api request body contents`
- `GraphQL mutation details`
- `server authorization`
- `extension behavior`

Inspect parser output:

```sh
cc-bash-guard explain "gh api repos/OWNER/REPO --method GET"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: gh read-only
      command:
        name: gh
        semantic:
          area_in: [pr, issue, repo]
          verb_in: [view, list]
  deny:
    - name: gh mutating api
      command:
        name: gh
        semantic:
          area: api
          method_in: [POST, PATCH, PUT, DELETE]
```

| Field | Type | Meaning |
| --- | --- | --- |
| `area` | `string` | Top-level gh area such as api, pr, issue, repo, release, secret, search, workflow, auth, or run. |
| `area_in` | `[]string` | Allowed gh areas. |
| `verb` | `string` | gh subcommand verb inside the selected area. |
| `verb_in` | `[]string` | Allowed gh verbs. |
| `repo` | `string` | Repository selected by -R or --repo, or the target repository positional for gh repo commands. |
| `repo_in` | `[]string` | Allowed repositories. |
| `org` | `string` | Organization selected by -o or --org. |
| `org_in` | `[]string` | Allowed organizations. |
| `env` | `string` | Environment selected by -e/--env or --env-name. |
| `env_in` | `[]string` | Allowed environments. |
| `hostname` | `string` | Hostname selected by --hostname. |
| `hostname_in` | `[]string` | Allowed hostnames. |
| `web` | `bool` | True when -w or --web is present. |
| `method` | `string` | HTTP method for gh api. |
| `method_in` | `[]string` | Allowed gh api HTTP methods. |
| `endpoint` | `string` | Normalized gh api endpoint. |
| `endpoint_prefix` | `string` | Normalized gh api endpoint prefix. |
| `endpoint_contains` | `[]string` | Endpoint substrings that must be present. |
| `paginate` | `bool` | True when gh api --paginate is present. |
| `input` | `bool` | True when gh api --input is present. |
| `silent` | `bool` | True when gh api --silent is present. |
| `include_headers` | `bool` | True when gh api -i or --include is present. |
| `field_keys_contains` | `[]string` | gh api -F/--field keys that must be present. |
| `raw_field_keys_contains` | `[]string` | gh api -f/--raw-field keys that must be present. |
| `header_keys_contains` | `[]string` | gh api -H/--header keys that must be present. |
| `pr_number` | `string` | Pull request number positional for gh pr commands. |
| `issue_number` | `string` | Issue number positional for gh issue commands. |
| `secret_name` | `string` | Secret name positional for gh secret commands. |
| `secret_name_in` | `[]string` | Allowed gh secret names. |
| `tag` | `string` | Release tag positional for gh release commands. |
| `workflow_name` | `string` | Workflow name positional for gh workflow commands. |
| `workflow_id` | `string` | Workflow ID positional for gh workflow commands. |
| `search_type` | `string` | Search type for gh search commands, such as code, commits, issues, prs, or repos. |
| `search_type_in` | `[]string` | Allowed gh search types. |
| `query_contains` | `string` | Substring that must be present in the gh search query. |
| `base` | `string` | Base branch selected by --base. |
| `head` | `string` | Head branch selected by --head. |
| `ref` | `string` | Ref selected by --ref. |
| `ref_in` | `[]string` | Allowed refs selected by --ref. |
| `state` | `string` | Issue state selected by --state. |
| `state_in` | `[]string` | Allowed issue states. |
| `label_in` | `[]string` | Issue labels selected by -l or --label; at least one listed label must be present. |
| `assignee_in` | `[]string` | Issue assignees selected by -a or --assignee; at least one listed assignee must be present. |
| `title_contains` | `string` | Substring that must be present in the issue title selected by -t or --title. |
| `body_contains` | `string` | Substring that must be present in the issue body selected by -b or --body. |
| `draft` | `bool` | True when gh pr create --draft is present. |
| `prerelease` | `bool` | True when gh release create/edit --prerelease is present. |
| `latest` | `bool` | True when gh release create/view --latest is present. |
| `fill` | `bool` | True when gh pr create --fill is present. |
| `force` | `bool` | True for gh pr checkout --force or -f, and gh run rerun --force. |
| `admin` | `bool` | True when gh pr merge --admin is present. |
| `auto` | `bool` | True when gh pr merge --auto is present. |
| `delete_branch` | `bool` | True when gh pr merge --delete-branch is present. |
| `merge_strategy` | `string` | Merge strategy selected by gh pr merge. |
| `merge_strategy_in` | `[]string` | Allowed merge strategies. |
| `run_id` | `string` | Run ID positional for gh run commands. |
| `failed` | `bool` | True when gh run rerun --failed is present. |
| `job` | `string` | Job selected by gh run rerun --job. |
| `debug` | `bool` | True when gh run rerun --debug is present. |
| `exit_status` | `bool` | True when gh run view --exit-status is present. |
| `flags_contains` | `[]string` | Parser-recognized gh option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized gh option tokens that must start with these prefixes; this depends on the gh parser. |

### argocd

Argo CD app operations such as app get, list, diff, sync, rollback, and delete.

**Common safe/read-only examples:**

- `argocd app get my-app`
- `argocd app list`

**Common mutating/destructive examples:**

- `argocd app sync my-app`
- `argocd app delete my-app`

**Suggested policy style:** Allow read-only app verbs for known apps/projects; ask for sync/rollback/delete.

**Known limitations / conservative fallback cases:**

- `Argo CD RBAC`
- `app manifests`
- `sync waves`
- `hooks`
- `server-side effects`

Inspect parser output:

```sh
cc-bash-guard explain "argocd app get my-app"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: argocd app read
      command:
        name: argocd
        semantic:
          verb_in: ["app get", "app list", "app diff"]
  ask:
    - name: argocd app sync
      command:
        name: argocd
        semantic:
          verb: app sync
```

| Field | Type | Meaning |
| --- | --- | --- |
| `verb` | `string` | Argo CD action path such as app sync or app rollback. |
| `verb_in` | `[]string` | Allowed Argo CD action paths. |
| `app_name` | `string` | Application name positional for argocd app commands. |
| `app_name_in` | `[]string` | Allowed Argo CD application names. |
| `project` | `string` | Project selected by --project. |
| `project_in` | `[]string` | Allowed Argo CD projects. |
| `revision` | `string` | Revision selected by --revision, or rollback revision positional. |
| `flags_contains` | `[]string` | Parser-recognized argocd option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized argocd option tokens that must start with these prefixes; this depends on the argocd parser. |

### gws

Google Workspace CLI dynamic Discovery and helper commands.

**Common safe/read-only examples:**

- `gws drive files list`

**Common mutating/destructive examples:**

- `gws gmail messages +send`
- `gws drive files delete`

**Suggested policy style:** Allow explicit service/resource_path/method rules; use inferred booleans only as conservative aids.

**Known limitations / conservative fallback cases:**

- `dynamic Google Discovery surfaces`
- `method-name mutation inference`
- `request bodies`
- `server authorization`

Inspect parser output:

```sh
cc-bash-guard explain "gws drive files list"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: gws drive file list
      command:
        name: gws
        semantic:
          service: drive
          resource_path: [files]
          method: list
  ask:
    - name: gws mutating methods
      command:
        name: gws
        semantic:
          mutating: true
```

| Field | Type | Meaning |
| --- | --- | --- |
| `service` | `string` | First non-global gws action token, such as drive, gmail, calendar, sheets, docs, chat, auth, schema, events, workflow, modelarmor, or script. |
| `service_in` | `[]string` | Allowed gws services. |
| `resource_path` | `[]string` | Exact resource path tokens between service and method, such as [files] or [spreadsheets, values]. |
| `resource_path_contains` | `[]string` | Resource path tokens that must be present. |
| `method` | `string` | Final Discovery method or helper command name, such as list, get, create, delete, update, patch, export, login, +send, or +upload. |
| `method_in` | `[]string` | Allowed gws methods or helper names. |
| `helper` | `bool` | True when the parsed method starts with +. |
| `mutating` | `bool` | True for methods inferred to write or change server state. |
| `destructive` | `bool` | True for methods inferred to delete, clear, trash, or remove data. |
| `read_only` | `bool` | True for methods inferred to read without mutation. |
| `dry_run` | `bool` | True when --dry-run is present. |
| `page_all` | `bool` | True when --page-all is present. |
| `upload` | `bool` | True when --upload is present. |
| `sanitize` | `bool` | True when --sanitize is present. |
| `params` | `bool` | True when --params is present. |
| `json_body` | `bool` | True when --json is present. |
| `unmasked` | `bool` | True when --unmasked is present. |
| `scopes` | `[]string` | Scopes selected by --scopes or -s, split on commas and spaces. |
| `flags_contains` | `[]string` | Parser-recognized gws option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized gws option tokens that must start with these prefixes; this depends on the gws parser. |

Notes:

- `gws` dynamically builds much of its command surface from Google Discovery Service, so this schema exposes generic service/resource_path/method fields instead of a closed list of API methods.
- `mutating`, `destructive`, and `read_only` are conservative method-name inferences; use explicit service, resource_path, and method fields for tighter policies.

### helmfile

Helmfile apply, sync, destroy, diff, environment, file, selector, namespace, and values matching.

**Common safe/read-only examples:**

- `helmfile diff`

**Common mutating/destructive examples:**

- `helmfile apply`
- `helmfile sync`
- `helmfile destroy`

**Suggested policy style:** Allow review commands only with expected environment/file/context; ask for apply/sync/destroy.

**Known limitations / conservative fallback cases:**

- `helmfile state`
- `nested helm behavior`
- `values files`
- `release state`
- `cluster effects`

Inspect parser output:

```sh
cc-bash-guard explain "helmfile -e prod diff"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: helmfile prod diff
      command:
        name: helmfile
        semantic:
          verb: diff
          environment: prod
  ask:
    - name: helmfile prod changes
      command:
        name: helmfile
        semantic:
          verb_in: [apply, sync, destroy]
          environment: prod
```

| Field | Type | Meaning |
| --- | --- | --- |
| `verb` | `string` | helmfile verb such as apply, sync, destroy, or diff. |
| `verb_in` | `[]string` | Allowed helmfile verbs. |
| `environment` | `string` | Environment selected by -e or --environment. |
| `environment_in` | `[]string` | Allowed environments. |
| `environment_missing` | `bool` | True when no environment was selected. |
| `file` | `string` | State file selected by -f or --file. |
| `file_in` | `[]string` | Allowed state files. |
| `file_prefix` | `string` | State file prefix. |
| `file_missing` | `bool` | True when no state file was selected. |
| `namespace` | `string` | Namespace selected by --namespace. |
| `namespace_in` | `[]string` | Allowed namespaces. |
| `namespace_missing` | `bool` | True when no namespace was selected. |
| `kube_context` | `string` | Kube context selected by --kube-context. |
| `kube_context_in` | `[]string` | Allowed kube contexts. |
| `kube_context_missing` | `bool` | True when no kube context was selected. |
| `selector` | `string` | Selector selected by -l or --selector. |
| `selector_in` | `[]string` | Allowed selectors. |
| `selector_contains` | `[]string` | Selectors that must be present. |
| `selector_missing` | `bool` | True when no selector was selected. |
| `interactive` | `bool` | True when --interactive is present. |
| `dry_run` | `bool` | True when --dry-run is present. |
| `wait` | `bool` | True when --wait is present. |
| `wait_for_jobs` | `bool` | True when --wait-for-jobs is present. |
| `skip_diff` | `bool` | True when --skip-diff is present. |
| `skip_needs` | `bool` | True when --skip-needs is present. |
| `include_needs` | `bool` | True when --include-needs is present. |
| `include_transitive_needs` | `bool` | True when --include-transitive-needs is present. |
| `purge` | `bool` | True when --purge is present. |
| `cascade` | `string` | Cascade value selected by --cascade. |
| `cascade_in` | `[]string` | Allowed cascade values. |
| `delete_wait` | `bool` | True when --delete-wait is present. |
| `state_values_file` | `string` | State values file selected by --state-values-file. |
| `state_values_file_in` | `[]string` | Allowed state values files. |
| `state_values_set_keys_contains` | `[]string` | Keys selected by --state-values-set that must be present. |
| `state_values_set_string_keys_contains` | `[]string` | Keys selected by --state-values-set-string that must be present. |
| `flags_contains` | `[]string` | Parser-recognized helmfile option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized helmfile option tokens that must start with these prefixes; this depends on the helmfile parser. |

### helm

Helm verb, subverb, release, chart, namespace, kube context, values, set keys, and safety flag matching.

**Common safe/read-only examples:**

- `helm list`
- `helm status`
- `helm get values`

**Common mutating/destructive examples:**

- `helm upgrade --install`
- `helm uninstall`
- `helm rollback`

**Suggested policy style:** Allow inspection verbs; ask for install/upgrade/rollback/uninstall/plugin changes.

**Known limitations / conservative fallback cases:**

- `chart contents`
- `values files`
- `templates`
- `plugins`
- `kube credentials`
- `cluster effects`

Inspect parser output:

```sh
cc-bash-guard explain "helm status my-release -n prod"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: helm inspection
      command:
        name: helm
        semantic:
          verb_in: [list, status, history, get, show, search, template, lint]
  ask:
    - name: helm changes
      command:
        name: helm
        semantic:
          verb_in: [install, upgrade, rollback, uninstall]
```

| Field | Type | Meaning |
| --- | --- | --- |
| `verb` | `string` | Top-level Helm command such as install, upgrade, uninstall, status, get, repo, registry, plugin, dependency, package, pull, or push. |
| `verb_in` | `[]string` | Allowed top-level Helm commands. |
| `subverb` | `string` | Second action token for grouped commands such as repo add, registry login, plugin install, dependency update, get values, or show chart. |
| `subverb_in` | `[]string` | Allowed Helm grouped command subverbs. |
| `release` | `string` | Release name for release-oriented commands when it can be identified. |
| `chart` | `string` | Chart argument for install, upgrade, template, package, pull, push, verify, and lint when it can be identified. |
| `chart_in` | `[]string` | Allowed chart arguments. |
| `namespace` | `string` | Namespace selected by -n or --namespace. |
| `namespace_in` | `[]string` | Allowed namespaces. |
| `namespace_missing` | `bool` | True when no namespace was selected. |
| `kube_context` | `string` | Kube context selected by --kube-context. |
| `kube_context_in` | `[]string` | Allowed kube contexts. |
| `kube_context_missing` | `bool` | True when no kube context was selected. |
| `kubeconfig` | `string` | Kubeconfig selected by --kubeconfig. |
| `dry_run` | `bool` | True when --dry-run is present. |
| `force` | `bool` | True when --force is present. |
| `atomic` | `bool` | True when --atomic is present. |
| `wait` | `bool` | True when --wait is present. |
| `wait_for_jobs` | `bool` | True when --wait-for-jobs is present. |
| `install` | `bool` | True when helm upgrade uses --install or -i. |
| `reuse_values` | `bool` | True when --reuse-values is present. |
| `reset_values` | `bool` | True when --reset-values is present. |
| `reset_then_reuse_values` | `bool` | True when --reset-then-reuse-values is present. |
| `cleanup_on_fail` | `bool` | True when --cleanup-on-fail is present. |
| `create_namespace` | `bool` | True when --create-namespace is present. |
| `dependency_update` | `bool` | True when --dependency-update is present. |
| `devel` | `bool` | True when --devel is present. |
| `keep_history` | `bool` | True when uninstall --keep-history is present. |
| `cascade` | `string` | Cascade value selected by --cascade. |
| `cascade_in` | `[]string` | Allowed cascade values. |
| `values_file` | `string` | Values file selected by -f or --values. |
| `values_file_in` | `[]string` | Allowed values files. |
| `values_files` | `[]string` | Values files that must be present. |
| `set_keys_contains` | `[]string` | Keys selected by --set that must be present. |
| `set_string_keys_contains` | `[]string` | Keys selected by --set-string that must be present. |
| `set_file_keys_contains` | `[]string` | Keys selected by --set-file that must be present. |
| `repo_name` | `string` | Repository name for helm repo add/remove. |
| `repo_url` | `string` | Repository URL for helm repo add. |
| `registry` | `string` | Registry host or URL for helm registry login/logout. |
| `plugin_name` | `string` | Plugin argument for helm plugin install/update/uninstall/list when straightforward. |
| `flags_contains` | `[]string` | Parser-recognized Helm option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized Helm option tokens that must start with these prefixes; this depends on the Helm parser. |

### terraform

Terraform subcommands, workspace/state subcommands, and high-risk infrastructure flags.

**Common safe/read-only examples:**

- `terraform plan`
- `terraform show`
- `terraform validate`

**Common mutating/destructive examples:**

- `terraform apply`
- `terraform destroy`
- `terraform state rm`
- `terraform workspace delete`

**Suggested policy style:** Allow review/read-only subcommands narrowly; ask for apply/import/state/workspace writes; deny auto-approved destroy.

**Known limitations / conservative fallback cases:**

- `providers`
- `modules`
- `plan contents`
- `state contents`
- `backend credentials`
- `provisioner effects`

Inspect parser output:

```sh
cc-bash-guard explain "terraform plan -out=tfplan"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: terraform review
      command:
        name: terraform
        semantic:
          subcommand_in: [validate, plan, show, output]
  deny:
    - name: terraform auto destroy
      command:
        name: terraform
        semantic:
          subcommand: destroy
          auto_approve: true
```

| Field | Type | Meaning |
| --- | --- | --- |
| `subcommand` | `string` | Terraform subcommand such as init, validate, plan, apply, destroy, state, or workspace. |
| `subcommand_in` | `[]string` | Allowed Terraform subcommands. |
| `global_chdir` | `string` | Directory selected by global -chdir. |
| `workspace_subcommand` | `string` | Workspace subcommand such as list, show, select, new, or delete. |
| `workspace_subcommand_in` | `[]string` | Allowed workspace subcommands. |
| `state_subcommand` | `string` | State subcommand such as list, show, mv, rm, pull, push, or replace-provider. |
| `state_subcommand_in` | `[]string` | Allowed state subcommands. |
| `target` | `bool` | True when -target is present. |
| `targets_contains` | `[]string` | Targets selected by -target that must be present. |
| `replace` | `bool` | True when -replace is present. |
| `replaces_contains` | `[]string` | Replace addresses selected by -replace that must be present. |
| `destroy` | `bool` | True for terraform destroy or plan -destroy. |
| `auto_approve` | `bool` | True when -auto-approve is present. |
| `input` | `bool` | Value selected by -input=true/false. |
| `lock` | `bool` | Value selected by -lock=true/false. |
| `refresh` | `bool` | Value selected by -refresh=true/false. |
| `refresh_only` | `bool` | True when -refresh-only is present. |
| `out` | `string` | Plan output selected by -out. |
| `plan_file` | `string` | Plan file argument used by terraform apply <planfile>. |
| `var_files_contains` | `[]string` | Variable files selected by -var-file that must be present. |
| `vars` | `bool` | True when -var is present. |
| `backend` | `bool` | Value selected by terraform init -backend=true/false. |
| `upgrade` | `bool` | True when terraform init -upgrade is present. |
| `reconfigure` | `bool` | True when terraform init -reconfigure is present. |
| `migrate_state` | `bool` | True when terraform init -migrate-state is present. |
| `recursive` | `bool` | True when terraform fmt -recursive is present. |
| `check` | `bool` | True when terraform fmt -check is present. |
| `json` | `bool` | True when -json is present. |
| `force` | `bool` | True when a known -force flag is present. |
| `flags_contains` | `[]string` | Parser-recognized terraform option tokens that must be present; this does not scan raw argv words. |
| `flags_prefixes` | `[]string` | Parser-recognized terraform option tokens that must start with these prefixes; this depends on the terraform parser. |

### docker

Docker CLI and docker compose commands with high-risk flag detection.

**Common safe/read-only examples:**

- `docker ps`
- `docker images`
- `docker inspect`

**Common mutating/destructive examples:**

- `docker run --privileged`
- `docker system prune -a --volumes`
- `docker compose up`

**Suggested policy style:** Allow inspection verbs; deny privileged/socket/root mounts and destructive prune; ask for run/compose/build.

**Known limitations / conservative fallback cases:**

- `images`
- `Dockerfiles`
- `Compose files`
- `daemon state`
- `container entrypoints`
- `mounted file contents`

Inspect parser output:

```sh
cc-bash-guard explain "docker run --privileged alpine"
```

Example rule snippet:

```yaml
permission:
  allow:
    - name: docker inspection
      command:
        name: docker
        semantic:
          verb_in: [ps, images, inspect, logs, version, info]
  deny:
    - name: docker socket mount
      command:
        name: docker
        semantic:
          docker_socket_mount: true
```

| Field | Type | Meaning |
| --- | --- | --- |
| `verb` | `string` | Top-level docker command, such as run, exec, ps, images, system, or compose. |
| `verb_in` | `[]string` | Allowed docker verbs. |
| `subverb` | `string` | Second action token for command groups such as system prune or compose down. |
| `subverb_in` | `[]string` | Allowed docker subverbs. |
| `compose_command` | `string` | Command after docker compose, such as up, down, run, exec, logs, ps, or config. |
| `compose_command_in` | `[]string` | Allowed docker compose commands. |
| `image` | `string` | Image name for docker run, pull, push, or build -t when straightforward. |
| `image_in` | `[]string` | Allowed Docker images. |
| `container` | `string` | Container name or id for commands such as exec, logs, inspect, rm, and stop when straightforward. |
| `service` | `string` | Compose service for docker compose run or exec when straightforward. |
| `context` | `string` | Docker context from --context or -c before the verb. |
| `context_in` | `[]string` | Allowed Docker contexts. |
| `host` | `string` | Docker daemon host from -H or --host before the verb. |
| `host_prefix` | `string` | Required prefix for Docker daemon host. |
| `file` | `string` | Compose file or Dockerfile flag value when straightforward. |
| `file_in` | `[]string` | Allowed file values. |
| `file_prefix` | `string` | Required file path prefix. |
| `project_name` | `string` | Compose project name from -p or --project-name. |
| `project_name_in` | `[]string` | Allowed compose project names. |
| `profile` | `string` | Compose profile from --profile. |
| `profile_in` | `[]string` | Allowed compose profiles. |
| `dry_run` | `bool` | True for docker compose --dry-run. |
| `detach` | `bool` | True when -d or --detach is present. |
| `interactive` | `bool` | True when -i, --interactive, or -it is present. |
| `tty` | `bool` | True when -t, --tty, or -it is present. |
| `rm` | `bool` | True when --rm is present. |
| `force` | `bool` | True when -f or --force is present. |
| `privileged` | `bool` | True when --privileged is present. |
| `user` | `string` | User from -u or --user. |
| `workdir` | `string` | Working directory from -w or --workdir. |
| `entrypoint` | `string` | Entrypoint from --entrypoint. |
| `network` | `string` | Network mode from --network or --net. |
| `network_host` | `bool` | True when network mode is host. |
| `pid` | `string` | PID namespace from --pid. |
| `pid_host` | `bool` | True when --pid=host is present. |
| `ipc` | `string` | IPC namespace from --ipc. |
| `ipc_host` | `bool` | True when --ipc=host is present. |
| `uts` | `string` | UTS namespace from --uts. |
| `uts_host` | `bool` | True when --uts=host is present. |
| `cap_add_contains` | `[]string` | Required values from --cap-add. |
| `cap_drop_contains` | `[]string` | Required values from --cap-drop. |
| `security_opt_contains` | `[]string` | Required values from --security-opt. |
| `device` | `bool` | True when --device is present. |
| `devices_contains` | `[]string` | Required --device values. |
| `mounts_contains` | `[]string` | Required --mount values. |
| `volumes_contains` | `[]string` | Required -v or --volume values. |
| `host_mount` | `bool` | True when a bind mount source is an absolute host path. |
| `root_mount` | `bool` | True when a bind mount source is /. |
| `docker_socket_mount` | `bool` | True when a mount references common Docker socket paths. |
| `env_files_contains` | `[]string` | Required --env-file values. |
| `env_keys_contains` | `[]string` | Required keys from -e/--env KEY=VALUE. |
| `ports_contains` | `[]string` | Required -p/--publish values. |
| `publish_all` | `bool` | True when -P or --publish-all is present. |
| `pull` | `string` | Value from --pull. |
| `no_cache` | `bool` | True when --no-cache is present. |
| `build_arg_keys_contains` | `[]string` | Required keys from --build-arg KEY=VALUE. |
| `platform` | `string` | Platform from --platform. |
| `all` | `bool` | True when -a or --all is present. |
| `volumes_flag` | `bool` | True when --volumes is present. |
| `prune` | `bool` | True for docker system/image/volume/builder prune forms. |
| `all_resources` | `bool` | True for prune -a/--all or compose --all-resources. |
| `remove_orphans` | `bool` | True when --remove-orphans is present. |
| `flags_contains` | `[]string` | Parser-recognized docker option tokens that must be present. |
| `flags_prefixes` | `[]string` | Parser-recognized docker option tokens that must start with these prefixes. |

Notes:

- Docker semantics are syntactic only; the parser does not inspect images, Dockerfiles, compose files, containers, or daemon state.
- `host_mount`, `root_mount`, and `docker_socket_mount` are best-effort checks over command-line mount flags.

<!-- END GENERATED SEMANTIC FIELD REFERENCE -->
