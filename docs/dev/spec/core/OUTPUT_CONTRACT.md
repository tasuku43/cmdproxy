---
title: "Output Contract"
status: implemented
date: 2026-04-27
---

# Output Contract

## 1. Scope

This document defines the output contract for the main hook entrypoint of
`cc-bash-guard`.

The command name is `hook`, and the contract below is for Claude Code
`PreToolUse` Bash hook integration.

## 2. Runtime Outcomes

The runtime outcomes are:

- `allow`: invocation may proceed automatically
- `ask`: invocation should prompt the user
- `deny`: invocation is blocked
- `error`: invalid input, invalid config, stale or missing verified artifact,
  incompatible verified artifact, or internal failure

## 3. Hook JSON Output

`cc-bash-guard hook` writes a Claude Code hook JSON object to stdout.

### Allow

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "cc-bash-guard permission evaluated"
  },
  "cc-bash-guard": {
    "outcome": "allow",
    "explicit": true,
    "reason": "rule_match",
    "trace": []
  }
}
```

### Ask

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "s3 operations require confirmation"
  },
  "cc-bash-guard": {
    "outcome": "ask",
    "explicit": true,
    "reason": "rule_match",
    "trace": []
  }
}
```

### Deny

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "delete is blocked"
  },
  "cc-bash-guard": {
    "outcome": "deny",
    "explicit": true,
    "reason": "rule_match",
    "trace": []
  }
}
```

### Fail-Closed Error

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "cc-bash-guard claude invalid_input: action must be exec"
  }
}
```

`permissionDecisionReason` uses a matched rule `message` when configured. For
`deny`, Claude Code feeds the reason back to Claude. For `allow` and `ask`, the
reason is user-facing.

`updatedInput.command` is emitted only for the explicit `--rtk` integration when
external RTK returns a different command after a non-`deny` decision.
cc-bash-guard policy evaluation and the default hook do not rewrite commands.

## 4. Exit Codes

Claude Code command hooks parse stdout JSON only when the hook process exits
`0`. For that reason, the hook process exits `0` for every successfully produced
JSON payload:

- `allow`: exit `0`
- `ask`: exit `0`
- `deny`: exit `0`
- fail-closed error JSON: exit `0`

This includes invalid input and missing, stale, or incompatible verified
artifacts. Those cases communicate failure by returning
`permissionDecision: "deny"` and a precise `permissionDecisionReason`, not by a
non-zero process exit.

Process exit `1` is reserved for CLI usage errors before hook JSON is produced,
such as unknown `hook` flags. The hook does not use exit `2` for policy denies
because Claude Code would ignore stdout JSON on exit `2`.

## 5. Integration Note

The central design goal is that `cc-bash-guard` itself becomes the primary
permission authority for shell commands without changing the command string
that will be executed.
