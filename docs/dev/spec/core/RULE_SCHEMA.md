---
title: "Pipeline Schema"
status: implemented
date: 2026-04-25
---

# Pipeline Schema

## 1. Scope

This document defines the current YAML schema for `cc-bash-proxy`.

## 2. Top-Level Shape

The configuration file contains one optional top-level setting and three
top-level sections:

```yaml
claude_permission_merge_mode: strict

rewrite:
  - match:
      command: aws
      args_contains:
        - "--profile"
    move_flag_to_env:
      flag: "--profile"
      env: "AWS_PROFILE"
    continue: true
    strict: true
    test:
      - in: "aws --profile prod s3 ls"
        out: "AWS_PROFILE=prod aws s3 ls"
      - pass: "AWS_PROFILE=prod aws s3 ls"

permission:
  deny:
    - match:
        env_requires:
          - "AWS_PROFILE"
        args_contains:
          - "--delete"
      message: "delete is blocked"
      test:
        deny:
          - "AWS_PROFILE=prod aws s3 rm s3://example --delete"
        pass:
          - "AWS_PROFILE=prod aws sts get-caller-identity"

  ask:
    - match:
        command: aws
        subcommand: s3
      message: "s3 operations require confirmation"
      test:
        ask:
          - "AWS_PROFILE=prod aws s3 ls"
        pass:
          - "AWS_PROFILE=prod aws sts get-caller-identity"

  allow:
    - match:
        command: aws
        subcommand: sts
        env_requires:
          - "AWS_PROFILE"
      test:
        allow:
          - "AWS_PROFILE=prod aws sts get-caller-identity"
        pass:
          - "AWS_PROFILE=prod aws s3 ls"

test:
  - in: "aws --profile prod sts get-caller-identity"
    rewritten: "AWS_PROFILE=prod aws sts get-caller-identity"
    decision: allow
```

Unknown top-level keys are invalid.

`claude_permission_merge_mode` is optional. Supported values are:

- `migration_compat`
- `strict`
- `cc_bash_proxy_authoritative`

When omitted, the effective mode is `strict`. `migration_compat` is a legacy
mode and is used only when explicitly configured.

Permission merging uses four internal verdict states: `deny`, `ask`, `allow`,
and `abstain`. `abstain` means no matching permission rule exists on that side.
The final fallback to `ask` is applied only after merging and only when both
`cc-bash-proxy` and Claude settings abstain. In `strict` mode, Claude `allow`
does not override an explicit `cc-bash-proxy` `ask`, but it does apply when
`cc-bash-proxy` abstains.

## 3. Rewrite Section

`rewrite` is an ordered array of rewrite steps.

Each rewrite step may contain:

- optional selector: exactly one of `match`, `pattern`, or `patterns`
- exactly one rewrite primitive
- optional `continue`
- optional `strict`
- required `test`

Currently implemented rewrite primitives:

- `move_flag_to_env`
- `move_env_to_flag`
- `unwrap_shell_dash_c`
- `unwrap_wrapper`
- `strip_command_path`

### Rewrite selector

Each rewrite step may define one selector:

- `match`
- `pattern`
- `patterns`

The selector is optional for rewrite steps. If omitted, the step is considered
for every command.

Supported fields:

- `command`
- `command_in`
- `command_is_absolute_path`
- `subcommand`
- `args_contains`
- `args_prefixes`
- `env_requires`
- `env_missing`

Rewrite selectors must not use `semantic`. Semantic matchers are currently
permission-only because rewrite changes command shape before permission
evaluation.

`args_contains` and `args_prefixes` are legacy raw-word matchers. They inspect
the command words after the executable token, before command-specific semantic
argument parsing. This preserves compatibility for commands such as
`git -C repo status`, where `args_contains: ["-C"]` must continue to match even
if `Command.Args` later contains only semantic positional arguments. New
semantic argument matchers should use separate field names.

`subcommand` is semantic when a command-specific parser is available. Without a
semantic parser it uses only the first non-option raw word as a limited
structural fallback; it does not infer option value arity. If a same-scope
`deny` or `ask` rule needs semantic fields and no semantic parser is available,
permission evaluation falls back to `ask` instead of allowing a broader rule.

- `pattern` matches the raw command string using one RE2 expression
- `patterns` matches the raw command string when any RE2 expression matches
- `pattern` and `patterns` are alternatives to structured `match`

### Rewrite `test`

```yaml
test:
  - in: "aws --profile prod s3 ls"
    out: "AWS_PROFILE=prod aws s3 ls"
  - pass: "AWS_PROFILE=prod aws s3 ls"
```

- each case is either `{in, out}` or `{pass}`
- `pass` is sugar for `in == out`

## 4. Permission Section

`permission` contains three effect buckets:

- `deny`
- `ask`
- `allow`

Each bucket contains an array of permission rules.

Each permission rule may contain:

- required selector: exactly one of `match`, `pattern`, or `patterns`
- optional `message`
- optional `allow_unsafe_shell` for raw `allow` rules that intentionally allow
  a supported full shell expression after it passes the fail-closed evaluation
  safety gate; when true, `message` is required
- required `test`

### Permission rule example

```yaml
allow:
  - match:
      command: aws
      subcommand: sts
      env_requires:
        - "AWS_PROFILE"
    test:
      expect:
        - "AWS_PROFILE=prod aws sts get-caller-identity"
      pass:
        - "AWS_PROFILE=prod aws s3 ls"
```

Regular-expression selectors are also allowed:

```yaml
deny:
  - patterns:
      - '^\s*git\s+diff\s+.*\.\.\.'
      - '^\s*cd\s+[^&;|]+\s*(&&|;|\|)'
    message: "blocked by command-shape policy"
    test:
      deny:
        - "git diff main...HEAD"
      pass:
        - "git diff HEAD~1"
```

### Permission semantic match

Structured permission `match` may include `semantic` only when `match.command`
is an exact command discriminator. `command_in` plus `semantic` is invalid
because the semantic schema would be ambiguous. `semantic` is an internal member
of `match`; it cannot be combined with top-level `pattern` or `patterns`.
Do not nest another command key under `semantic`: `semantic.service` is valid
for AWS rules and `semantic.verb` is valid for kubectl rules, while
`semantic.aws.service`, `semantic.kubectl.verb`, `semantic.gh.area`, or
`semantic.helmfile.verb` is invalid.

For `command: git`, the Git semantic schema is:

- string selectors: `verb`, `remote`, `branch`, `ref`
- string-list selectors: `verb_in`, `remote_in`, `branch_in`, `ref_in`
- boolean selectors: `force`, `hard`, `recursive`, `include_ignored`,
  `cached`, `staged`
- flag selectors: `flags_contains`, `flags_prefixes`

Example:

```yaml
deny:
  - match:
      command: git
      semantic:
        verb: clean
        force: true
        recursive: true
        include_ignored: true
    message: "destructive git clean is blocked"
```

Git semantic parsing is best-effort static parsing of the command argv. It
does not query repository state; ambiguous operands are left conservative or
classified by common CLI convention. `GenericParser` never satisfies
`match.semantic`, so a command-specific parser must provide semantic data.

For `command: aws`, the AWS semantic schema is:

- string selectors: `service`, `operation`, `profile`, `region`,
  `endpoint_url`, `endpoint_url_prefix`
- string-list selectors: `service_in`, `operation_in`, `profile_in`,
  `region_in`
- boolean selectors: `dry_run`, `no_cli_pager`
- flag selectors: `flags_contains`, `flags_prefixes`

Example:

```yaml
deny:
  - match:
      command: aws
      semantic:
        service: s3
        operation_in:
          - rm
          - rb
          - delete-object
          - delete-bucket
    message: "destructive S3 operation is blocked"
```

AWS semantic parsing statically reads commands shaped as
`aws [global options] <service> <operation> [operation options / args]`. Global
options are parsed before the service. `--profile` overrides `AWS_PROFILE`.
`--region` overrides `AWS_REGION`, and `AWS_REGION` overrides
`AWS_DEFAULT_REGION`. `--dry-run` sets `dry_run` to true; `--no-dry-run` sets it
to false. If neither flag is present, `dry_run` is unknown, and `dry_run: false`
does not match that unknown state.

For `command: kubectl`, the kubectl semantic schema is:

- string selectors: `verb`, `subverb`, `resource_type`, `resource_name`,
  `namespace`, `context`, `kubeconfig`, `filename`, `filename_prefix`,
  `selector`, `container`
- string-list selectors: `verb_in`, `subverb_in`, `resource_type_in`,
  `resource_name_in`, `namespace_in`, `context_in`, `filename_in`,
  `selector_contains`
- boolean selectors: `all_namespaces`, `dry_run`, `force`, `recursive`
- flag selectors: `flags_contains`, `flags_prefixes`

Example:

```yaml
deny:
  - match:
      command: kubectl
      semantic:
        verb: delete
        resource_type_in:
          - pod
          - deployment
          - namespace
        namespace_in:
          - prod
          - production
    message: "deleting production Kubernetes resources is blocked"
```

Kubectl semantic parsing statically reads commands shaped as
`kubectl [global options] <verb> [resource_type[/resource_name] | resource_type resource_name] [flags]`.
Options may appear before or after the verb. `-n`, `--namespace`, and
`--namespace=...` set `namespace`; `--context` and `--context=...` set
`context`; `--kubeconfig` and `--kubeconfig=...` set `kubeconfig`. `-A` and
`--all-namespaces` set `all_namespaces` to true. `--dry-run`,
`--dry-run=server`, and `--dry-run=client` set `dry_run` to true. `--force`
sets `force` to true. `-R` and `--recursive` set `recursive` to true. `-f`,
`--filename`, and `--filename=...` populate filename selectors. `-l`,
`--selector`, and `--selector=...` populate selector selectors. `-c`,
`--container`, and `--container=...` set `container`. `rollout restart` is
represented as `verb: rollout` and `subverb: restart`. Manifest files are not
read; only static CLI argv is parsed.

For `command: gh`, the GitHub CLI semantic schema is:

- common string selectors: `area`, `verb`, `repo`, `hostname`
- common string-list selectors: `area_in`, `verb_in`, `repo_in`,
  `hostname_in`
- common boolean selector: `web`
- `gh api` string selectors: `method`, `endpoint`, `endpoint_prefix`
- `gh api` string-list selectors: `method_in`, `endpoint_contains`,
  `field_keys_contains`, `raw_field_keys_contains`, `header_keys_contains`
- `gh api` boolean selectors: `paginate`, `input`, `silent`,
  `include_headers`
- `gh pr` string selectors: `pr_number`, `base`, `head`, `merge_strategy`
- `gh pr` string-list selector: `merge_strategy_in`
- `gh pr` boolean selectors: `draft`, `fill`, `force`, `admin`, `auto`,
  `delete_branch`
- `gh run` string selectors: `run_id`, `job`
- `gh run` boolean selectors: `failed`, `debug`, `force`, `exit_status`
- flag selectors: `flags_contains`, `flags_prefixes`

Example:

```yaml
permission:
  deny:
    - match:
        command: gh
        semantic:
          area: api
          method_in:
            - POST
            - PUT
            - PATCH
            - DELETE
          endpoint_prefix: /repos/
      message: "GitHub API mutation requires explicit policy"

  ask:
    - match:
        command: gh
        semantic:
          area: pr
          verb_in:
            - create
            - merge
            - close
            - reopen
            - review
            - ready
            - update-branch
      message: "PR mutation requires confirmation"

  allow:
    - match:
        command: gh
        semantic:
          area: run
          verb_in:
            - view
            - list
            - watch
```

Gh semantic parsing statically reads commands shaped as
`gh [global flags] <area> [verb] [args] [flags]`. Initial deep support covers
`api`, `pr`, and `run`; other areas expose only `area` and `verb`.
`-R`, `--repo`, and `--repo=...` set `repo`; no git remote is read.
`--hostname` overrides `GH_HOST`. `--web` and `-w` set `web` to true.

For `gh api`, the first positional after `api` is normalized as `endpoint` by
adding a leading `/` when absent. `-X`, `--method`, and `--method=...` set an
uppercased `method`; otherwise the parser defaults to `GET`. Body-like flags
do not implicitly change the method in this parser: `-F` / `--field`,
`-f` / `--raw-field`, and `--input` are represented through their own semantic
fields. Header keys from `-H` / `--header` are lowercased.

For `gh pr`, `verb` is the subcommand after `pr`. `view`, `list`, `diff`,
`status`, and `checks` are typical read-only verbs. `create`, `merge`, `close`,
`reopen`, `review`, `ready`, and `update-branch` usually mutate PR state.
Merge strategy maps `--merge` / `-m` to `merge`, `--squash` / `-s` to
`squash`, and `--rebase` / `-r` to `rebase`. `-f` is treated as `force` only
for `gh pr checkout`.

For `gh run`, `verb` is the subcommand after `run`. `view`, `list`, and
`watch` are typical read-only verbs. `cancel`, `delete`, and `rerun` change
GitHub Actions state.

For `command: helmfile`, the helmfile semantic schema is:

- string selectors: `verb`, `environment`, `file`, `file_prefix`,
  `namespace`, `kube_context`, `selector`, `cascade`, `state_values_file`
- string-list selectors: `verb_in`, `environment_in`, `file_in`,
  `namespace_in`, `kube_context_in`, `selector_in`, `selector_contains`,
  `cascade_in`, `state_values_file_in`,
  `state_values_set_keys_contains`, `state_values_set_string_keys_contains`
- missing selectors: `environment_missing`, `file_missing`,
  `namespace_missing`, `kube_context_missing`, `selector_missing`
- boolean selectors: `interactive`, `dry_run`, `wait`, `wait_for_jobs`,
  `skip_diff`, `skip_needs`, `include_needs`,
  `include_transitive_needs`, `purge`, `delete_wait`
- flag selectors: `flags_contains`, `flags_prefixes`

Example:

```yaml
permission:
  deny:
    - match:
        command: helmfile
        semantic:
          verb_in:
            - sync
            - apply
            - destroy
            - delete
          environment_in:
            - prod
            - production
          interactive: false
      message: "non-interactive helmfile mutation in production is blocked"

  ask:
    - match:
        command: helmfile
        semantic:
          verb: sync
          selector_missing: true
      message: "helmfile sync without selector requires confirmation"

  allow:
    - match:
        command: helmfile
        semantic:
          verb_in:
            - diff
            - template
            - build
            - list
            - lint
            - status
```

Helmfile semantic parsing statically reads `helmfile` argv only; it does not
read `helmfile.yaml` and does not infer hook or plugin side effects. Options
may appear before or after the verb. The first non-flag token after consuming
known flag values is `verb`. `-e`, `--environment`, and `--environment=...`
set `environment`; explicit CLI values override `HELMFILE_ENVIRONMENT`.
If no environment is provided, `environment` is unknown and is not treated as
`default`. `-f` / `--file` populate file selectors. `-n` / `--namespace`
sets `namespace`. `--kube-context` sets `kube_context`. `-l` / `--selector`
populates selector selectors and may appear multiple times.

`-i` / `--interactive` sets `interactive` to true; otherwise `interactive` is
false for policy matching. `--dry-run` sets `dry_run` to true; otherwise
`dry_run` is unknown and `dry_run: true` does not match. `--wait`,
`--wait-for-jobs`, `--skip-diff`, `--skip-needs`, `--include-needs`,
`--include-transitive-needs`, `--purge`, `--cascade`, and `--delete-wait`
populate their matching fields. `--state-values-file`,
`--state-values-set`, and `--state-values-set-string` populate the state value
selectors; set-style selectors compare extracted keys before `=`.

`sync`, `apply`, `destroy`, and deprecated `delete` are mutation-oriented
verbs and typically require `ask` or `deny` in sensitive environments.
`diff`, `template`, `build`, `list`, `lint`, and `status` are typical
read-only or dry-run-oriented verbs, but static parsing cannot prove that
hooks or plugins are side-effect free.

Unsupported semantic fields, unsupported value types, `semantic` without exact
`command`, `command_in` with `semantic`, `subcommand` with `semantic`, command
and semantic schema mismatches, and rewrite selectors with `semantic` are
validation errors. Generic parser fallback never satisfies semantic match.

For `permission.allow`, `pattern` and `patterns` fail closed to `ask` unless
the command is safe for evaluation. Syntax parse errors, diagnostics, unknown
shapes, redirects, subshells, background execution, process substitution, and
unsafe AST forms never reach allow matching. Set `allow_unsafe_shell: true`
only for intentionally trusted full-command raw matches that still pass that
safety gate, and include a `message` explaining that trust boundary.

Compound commands are evaluated through `CommandPlan.Commands` plus
`CommandPlan.Shape`, not by matching the raw command string across shell
operators. For `and_list`, `sequence`, `or_list`, and `pipeline`, every
extracted command must be individually allowed for the whole command to be
allowed; any denied extracted command denies the whole command; otherwise the
whole command asks. This includes pipelines by design for Claude Code
compatibility. `background`, `redirect`, `subshell`, and unknown shapes cannot
be allowed automatically and ask by default unless an extracted command is
denied.

Process substitution is treated as an unknown shape for allow purposes, while
commands inside `<(...)` and `>(...)` are still extracted for deny evaluation.
For example, `cat <(rm -rf /tmp/x)` is denied by a deny rule matching
`rm -rf /tmp/x`, and `echo >(sh)` is denied by a deny rule matching `sh`.

### Permission `test`

```yaml
test:
  allow:
    - "AWS_PROFILE=prod aws sts get-caller-identity"
  pass:
    - "AWS_PROFILE=prod aws s3 ls"
```

- `allow`, `ask`, or `deny`: exactly one effect key depending on the bucket
- `pass`: required non-empty string array

## 5. Top-Level E2E Test

`test` at the top level is for end-to-end expectations after the rewrite phase
and the permission phase have both completed.

```yaml
test:
  - in: "aws --profile prod sts get-caller-identity"
    rewritten: "AWS_PROFILE=prod aws sts get-caller-identity"
    decision: allow
```

- `test`: required non-empty array
- each case requires `in`
- each case requires `decision`
- `rewritten` is optional but recommended

Top-level `test.pass` is not part of the schema.

## 6. Validation Model

Validation is strict and aggregate.

- invalid matcher payloads are validation errors
- invalid rewrite payloads are validation errors
- invalid permission payloads are validation errors
- unsupported built-in rewrite contracts are validation errors
- missing local tests are validation errors
- missing top-level E2E tests are validation errors

## 7. Out Of Scope

The following remain out of scope for the current model:

- arbitrary shell templating
- user-defined rewrite plugins
- remote includes or hosted policy packs
- tool-specific settings as the primary permission source of truth
