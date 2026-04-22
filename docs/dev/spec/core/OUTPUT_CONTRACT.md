---
title: "Output Contract"
status: proposed
date: 2026-04-22
---

# Output Contract

## 1. Scope

This document defines the target output contract for the main hook entrypoint of
`cmdproxy`.

The command name is `hook claude`, and the contract below is for the current
rewrite-plus-permission model.

## 2. Runtime Outcomes

The target runtime outcomes are:

- `allow`: invocation may proceed automatically
- `ask`: invocation should prompt the user
- `deny`: invocation is blocked
- `error`: invalid input, invalid config, or internal failure

## 3. Default Output Mode

The default human-readable mode should remain concise.

- `allow`: optional concise trace or no output
- `ask`: optional concise trace or no output
- `deny`: explanation to `stderr`
- `error`: explanation to `stderr`

## 4. Structured Output Mode

The structured output mode should expose the final pipeline result explicitly.

Target JSON shape:

### Allow payload

```json
{
  "decision": "allow",
  "command": "AWS_PROFILE=prod aws sts get-caller-identity",
  "original_command": "aws --profile prod sts get-caller-identity",
  "message": "",
  "trace": []
}
```

### Ask payload

```json
{
  "decision": "ask",
  "command": "AWS_PROFILE=prod aws s3 ls",
  "original_command": "aws --profile prod s3 ls",
  "message": "s3 operations require confirmation",
  "trace": []
}
```

### Deny payload

```json
{
  "decision": "deny",
  "command": "AWS_PROFILE=prod aws s3 rm s3://example --delete",
  "original_command": "aws --profile prod s3 rm s3://example --delete",
  "message": "delete is blocked",
  "trace": []
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

The current mapping is:

- `allow`: exit `0`
- `ask`: exit `0`
- `deny`: exit `2`
- `error`: exit `1`

The important distinction is:

- success path for `allow`
- success path for `ask`
- distinct non-success path for `deny`
- distinct non-success path for `error`

## 6. Integration Note

The central design goal is that `cmdproxy` itself becomes the primary
permission authority for shell commands, after the rewrite pipeline has already
produced the canonical command shape.
