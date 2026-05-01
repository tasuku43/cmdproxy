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
2. allow safe, single-command `cc-bash-guard ...` invocations without loading
   the verified artifact, so setup commands such as `cc-bash-guard verify` do
   not deadlock while the hook is installed
3. load the verified effective policy artifact; if it is missing or stale,
   return `ask` with a warning instead of evaluating stale policy
4. parse the original command string into a `CommandPlan`
5. evaluate `cc-bash-guard` permission policy
6. merge `cc-bash-guard` policy with Claude settings as permission sources
   using `deny > ask > allow > abstain`
7. when `--rtk` is enabled and the merged decision is not `deny`, invoke
   external `rtk rewrite` once and emit `updatedInput` only when RTK returns a
   different command. For Claude Code Bash payloads, `updatedInput` preserves
   the original `tool_input` object and replaces only `command`
8. emit Claude Code `PreToolUse` hook JSON for `allow`, `ask`, `deny`, or
   fail-closed error output

`abstain` means a source had no matching rule. The final fallback is `ask` only
when all sources abstain.

The self-command bypass applies only when the shell input is a safe single
command and the resolved program name is `cc-bash-guard`. Compound commands,
redirects, pipelines, subshells, command substitutions, background execution,
and unknown shell shapes continue through normal policy evaluation and fail
closed when the verified artifact is unavailable.

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

Invalid input, invalid config, and incompatible verified artifacts fail closed
by returning `permissionDecision: "deny"` with a reason that names the error.
Missing or stale verified artifacts return `permissionDecision: "ask"` with a
warning `systemMessage` and `hookSpecificOutput.additionalContext`, so Claude
Code can continue through its normal confirmation flow without trusting stale
cc-bash-guard policy, while Claude can still see that verification needs to be
rerun. These cases exit `0` after producing valid hook JSON so Claude Code can
process the structured decision.
