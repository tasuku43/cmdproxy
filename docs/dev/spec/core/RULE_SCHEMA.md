---
title: "Rule Schema"
status: proposed
date: 2026-04-19
---

# Rule Schema

## 1. Scope

This document defines the directive-based YAML schema for `cmdproxy`.

## 2. Top-Level Shape

The current target configuration shape is:

```yaml
rules:
  - id: aws-profile-to-env
    match:
      command: aws
      args_contains:
        - "--profile"
    rewrite:
      move_flag_to_env:
        flag: "--profile"
        env: "AWS_PROFILE"
      continue: true
      test:
        expect:
          - in: "aws --profile prod s3 ls"
            out: "AWS_PROFILE=prod aws s3 ls"
        pass:
          - "AWS_PROFILE=prod aws s3 ls"

  - id: no-shell-dash-c
    match:
      command_in: ["bash", "sh", "zsh", "dash", "ksh"]
      args_contains: ["-c"]
    reject:
      message: "shell -c must not pass through unchanged."
      test:
        expect:
          - "bash -c 'git status && git diff'"
        pass:
          - "bash script.sh"
```

## 3. Top-Level Fields

- `rules`: required non-empty array of rule objects

Unknown top-level keys are invalid.

## 4. Rule Fields

Each rule object must contain:

- `id`: required string
- exactly one of `match` or `pattern`
- exactly one of `rewrite` or `reject`

Unknown rule-level keys are invalid.

## 5. Matcher Fields

### `match`

`match` is the preferred matcher model.

Supported fields:

- `command`
- `command_in`
- `subcommand`
- `args_contains`
- `args_prefixes`
- `env_requires`
- `env_missing`

The matcher operates on `cmdproxy`'s internal normalized invocation model.

### `pattern`

`pattern` remains available as an escape hatch for invocation shapes that are
not yet well represented by structured matchers.

- Must compile as Go RE2
- Matches against the raw command string
- Should be used sparingly where structured matching is insufficient

## 6. Directive Fields

### `rewrite`

`rewrite` contains exactly one typed rewrite primitive plus a required `test`
section.

Currently implemented primitives:

- `move_flag_to_env`
- `move_env_to_flag`
- `unwrap_shell_dash_c`
- `unwrap_wrapper`

`rewrite` may also set:

- `continue`: optional boolean, restart evaluation from the beginning after a
  successful rewrite

Free-form string templates are out of scope.

### `reject`

`reject` contains:

- `message`: required string
- `test`: required object

## 7. Directive Tests

Directive tests are mandatory and live under the directive itself.

### `rewrite.test`

```yaml
rewrite:
  move_flag_to_env:
    flag: "--profile"
    env: "AWS_PROFILE"
  continue: true
  test:
    expect:
      - in: "aws --profile prod s3 ls"
        out: "AWS_PROFILE=prod aws s3 ls"
    pass:
      - "AWS_PROFILE=prod aws s3 ls"
```

- `expect`: required non-empty array of `{in, out}`
- `pass`: required non-empty string array

### `reject.test`

```yaml
reject:
  message: "shell -c must not pass through unchanged."
  test:
    expect:
      - "bash -c 'git status && git diff'"
    pass:
      - "bash script.sh"
```

- `expect`: required non-empty string array
- `pass`: required non-empty string array

## 8. Validation Model

Validation is strict and aggregate.

- parsing should report all discovered schema issues in one run
- invalid matcher combinations are validation errors
- invalid directive payloads are validation errors
- missing tests are validation errors
- empty or ambiguous rules are validation errors

## 9. Out Of Scope

The following remain out of scope for the current model:

- arbitrary shell templating
- user-defined rewrite plugins
- implicit multi-step rewrite pipelines within one rule
- remote includes or hosted policy packs
