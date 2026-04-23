---
title: "Input Model"
status: implemented
date: 2026-04-18
---

# Input Model

## 1. Scope

This document defines the supported stdin payloads for `cc-bash-proxy hook` and
the normalization step that turns them into a command-string evaluation request.

## 2. Canonical Execution Request

Internally, `cc-bash-proxy hook` should normalize supported inputs into a canonical
execution request equivalent to:

```json
{
  "action": "exec",
  "command": "git status"
}
```

The evaluation engine should consume this canonical model rather than being
coupled directly to any external caller schema.

## 3. Supported External Input Shapes

### Generic shape

```json
{
  "action": "exec",
  "command": "git status"
}
```

Requirements:

- `action` must equal `"exec"`
- `command` must be a non-empty string

### Claude Code adapter shape

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "git status"
  }
}
```

Requirements:

- `tool_name` must equal `"Bash"`
- `tool_input.command` must be a non-empty string

## 4. Unsupported Input

The following are invalid in v1:

- unknown `action` values
- empty command strings
- missing required fields
- unsupported tool payloads
- malformed JSON

Invalid input must produce an error result rather than an implicit allow.

## 5. Forward Compatibility

v1 is intentionally strict at the envelope level and permissive only inside
recognized objects.

- Additional unknown fields inside a recognized payload may be ignored
- Unknown top-level payload shapes must still fail

This preserves fail-closed behavior while leaving room for future adapter
metadata.
