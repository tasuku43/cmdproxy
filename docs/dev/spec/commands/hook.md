---
title: "cc-bash-proxy hook"
status: proposed
date: 2026-04-23
---

# cc-bash-proxy hook

## Purpose

`cc-bash-proxy hook` is the current Claude Code hook entrypoint. It reads the
Claude hook payload from stdin, applies the configured rewrite and permission
pipeline, and emits hook JSON on stdout.

## Input Sources

`cc-bash-proxy hook` supports:

- Claude Code `PreToolUse` Bash payloads

Unsupported or malformed input is converted into a deny response for the hook
caller.

## Runtime Behavior

The current flow is:

1. Read stdin fully
2. Parse Claude Code hook JSON
3. Normalize the Bash command into an invocation request
4. Resolve global and project-local `cc-bash-proxy` policy for the tool
5. Resolve global and project-local tool settings for the tool
6. Load the verified artifact for the effective merged state
7. Evaluate the rewrite pipeline
8. Evaluate `cc-bash-proxy` permissions on the rewritten command
9. Evaluate tool-native permissions for migration and coexistence
10. Combine both permission sources with:
   - deny if either side denies
   - ask if either side explicitly asks
   - allow if either side allows
   - ask if both sides abstain
11. Emit tool hook JSON:
   - `allow`: `permissionDecision: "allow"`
   - `ask`: no `permissionDecision`, so Claude prompts
   - `deny`: `permissionDecision: "deny"`
   - `error`: deny response

## Implemented Rewrite Support

The current implementation already supports rewrite outcomes for:

- `move_flag_to_env`
- `move_env_to_flag`
- `unwrap_shell_dash_c`
- `unwrap_wrapper`
- `strip_command_path`

If a rewrite primitive matches but cannot safely rewrite the invocation,
evaluation continues with the current command.

## Permission Coexistence

`cc-bash-proxy` and tool-native settings coexist during evaluation.

`cc-bash-proxy` is responsible for:

- rewrite
- flexible additional permission rules
- end-to-end policy tests

Tool-native settings remain part of the effective runtime verdict during
evaluation and verification.

During migration, tool-native settings are treated as four-state inputs:

- `deny`
- `ask`
- `allow`
- `abstain` (no matching rule)

## RTK Integration

When `cc-bash-proxy hook --rtk` is used, the runtime order is:

1. evaluate `cc-bash-proxy` rewrite pipeline
2. evaluate `cc-bash-proxy` permission pipeline
3. evaluate Claude settings permission
4. combine both verdicts
5. if not denied, apply the final `rtk` rewrite
6. emit the final `updatedInput.command`

This keeps permission decisions stable even when external Bash hooks are not
executed serially, and it ensures permission checks happen before `rtk`
rewrites the visible command.
