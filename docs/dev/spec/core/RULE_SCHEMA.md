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
Unsupported semantic fields, unsupported value types, `semantic` without
`command`, non-Git commands using Git fields, and rewrite selectors with
`semantic` are validation errors. Future commands such as `kubectl`, `aws`, or
`gh` must add their own command-specific semantic schema and verification.

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
