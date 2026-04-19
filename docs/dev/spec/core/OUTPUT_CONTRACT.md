---
title: "Output Contract"
status: proposed
date: 2026-04-19
---

# Output Contract

## 1. Scope

This document defines the target output contract for the main hook entrypoint of
`cmdproxy`.

The command name is `hook claude`, and the contract below is for the
directive-driven model.

## 2. Runtime Outcomes

The target runtime outcomes are:

- `pass`: original invocation forwarded unchanged
- `rewrite`: transformed invocation forwarded
- `reject`: invocation blocked
- `error`: invalid input, invalid config, or internal failure

## 3. Default Output Mode

The default human-readable mode should remain concise.

- `pass`: normally no output
- `rewrite`: optional concise trace or no output, depending on caller needs
- `reject`: explanation to `stderr`
- `error`: explanation to `stderr`

## 4. Structured Output Mode

The structured output mode should expose the directive result explicitly.

Target JSON shape:

### Pass payload

```json
{
  "decision": "pass",
  "command": "git status"
}
```

### Rewrite payload

```json
{
  "decision": "rewrite",
  "rule_id": "aws-profile-to-env",
  "command": "AWS_PROFILE=prod aws s3 ls",
  "original_command": "aws --profile prod s3 ls",
  "source": {
    "layer": "user",
    "path": "/home/alice/.config/cmdproxy/cmdproxy.yml"
  }
}
```

### Reject payload

```json
{
  "decision": "reject",
  "rule_id": "no-shell-dash-c",
  "message": "shell -c must not pass through unchanged.",
  "command": "bash -c 'git status && git diff'",
  "source": {
    "layer": "user",
    "path": "/home/alice/.config/cmdproxy/cmdproxy.yml"
  }
}
```

### Error payload

```json
{
  "decision": "error",
  "error": {
    "code": "invalid_input",
    "message": "action must be exec"
  }
}
```

## 5. Exit Codes

The target exit-code model should distinguish runtime errors from policy
results, but it should not force `rewrite` to look like a hard deny.

The currently implemented mapping is:

- `pass`: exit `0`
- `rewrite`: exit `0`
- `reject`: exit `2`
- `error`: exit `1`

The longer-term semantics remain:

- success path for `pass`
- success path for `rewrite`
- distinct non-success path for `reject`
- distinct non-success path for `error`

If caller integrations constrain this shape, the wrapper contract may need an
adapter-specific encoding.

## 6. Integration Note

The central design goal is that downstream systems such as Claude Code can
evaluate permissions against the canonicalized invocation, not only against the
original malformed one.
