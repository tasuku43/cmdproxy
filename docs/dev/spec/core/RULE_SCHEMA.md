---
title: "Pipeline Schema"
status: proposed
date: 2026-04-22
---

# Pipeline Schema

## 1. Scope

This document defines the current YAML schema for `cc-bash-proxy`.

## 2. Top-Level Shape

The configuration file contains three top-level sections:

```yaml
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
