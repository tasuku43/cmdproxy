---
title: "cc-bash-guard hook"
status: implemented
date: 2026-04-27
---

# cc-bash-guard hook

`cc-bash-guard hook` is the Claude Code hook entrypoint. It reads the Claude
hook payload from stdin, evaluates permission policy, and emits hook JSON on
stdout.

Runtime flow:

1. parse Claude Code `PreToolUse` Bash payload
2. load the verified effective policy artifact
3. parse the original command string into a `CommandPlan`
4. evaluate `cc-bash-guard` permission policy
5. merge `cc-bash-guard` policy with Claude settings as permission sources
   using `deny > ask > allow > abstain`
6. when `--rtk` is enabled and the merged decision is not `deny`, invoke
   external `rtk rewrite` once and emit `updatedInput.command` only when RTK
   returns a different command
7. emit Claude Code `PreToolUse` hook JSON for `allow`, `ask`, `deny`, or
   fail-closed error output

`abstain` means a source had no matching rule. The final fallback is `ask` only
when all sources abstain.

`cc-bash-guard` does not emit `updatedInput.command` for policy evaluation.
Parser-backed normalization is evaluation-only. The default hook does not emit
`updatedInput`.

`cc-bash-guard hook` does not rewrite commands itself. `--rtk` is an explicit
integration path for installations that use RTK rewriting: cc-bash-guard
evaluates permissions first, then delegates rewriting to external RTK in the
same hook invocation. `deny` never invokes RTK.

## Claude Code Output Protocol

The hook always uses Claude Code's structured JSON protocol for permission
decisions. The JSON object is written to stdout and the process exits `0` when
the JSON was produced successfully.

The decision is nested under `hookSpecificOutput`:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "cc-bash-guard permission evaluated"
  }
}
```

- `hookEventName` is always `PreToolUse`.
- `permissionDecision` is `allow`, `ask`, or `deny`.
- `permissionDecisionReason` is the matched rule `message` when configured;
  otherwise it is a cc-bash-guard fallback reason.
- `cc-bash-guard` is an additional diagnostic object containing the final
  outcome, explicit/default status, internal reason, and trace.

For `allow`, Claude Code skips the permission prompt. For `ask`, Claude Code
prompts the user. For `deny`, Claude Code blocks the Bash tool call and feeds
the reason back to Claude.

`deny` intentionally exits `0` when emitted as structured JSON. Claude Code only
parses stdout JSON on successful hook process exit. If the hook exited non-zero,
Claude Code would ignore the JSON payload and handle the result as an
exit-code-based hook error instead. That would lose the structured
`permissionDecision` and `permissionDecisionReason`.

Invalid input, invalid config, missing verified artifacts, stale verified
artifacts, and incompatible verified artifacts fail closed by returning
`permissionDecision: "deny"` with a reason that names the error. These cases
also exit `0` after producing valid hook JSON so Claude Code can process the
deny decision.
