---
title: "cmdproxy hook"
status: proposed
date: 2026-04-23
---

# cmdproxy hook

## Purpose

`cmdproxy hook <tool>` is the tool-specific hook entrypoint. In the current
implementation, `claude` is the supported tool. It reads the tool hook payload
from stdin, applies the configured rewrite and permission pipeline, and emits
tool-specific hook JSON on stdout.

## Input Sources

`cmdproxy hook claude` supports:

- Claude Code `PreToolUse` Bash payloads

Unsupported or malformed input is converted into a deny response for the hook
caller.

## Runtime Behavior

The current flow is:

1. Read stdin fully
2. Parse Claude Code hook JSON
3. Normalize the Bash command into an invocation request
4. Resolve global and project-local `cmdproxy` policy for the tool
5. Resolve global and project-local tool settings for the tool
6. Load the verified artifact for the effective merged state
7. Evaluate the rewrite pipeline
8. Evaluate `cmdproxy` permissions on the rewritten command
9. Evaluate tool-native permissions for migration and coexistence
10. Combine both permission sources with:
   - deny if either side denies
   - allow if either side allows
   - ask otherwise
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

`cmdproxy` and tool-native settings coexist during evaluation.

`cmdproxy` is responsible for:

- rewrite
- flexible additional permission rules
- end-to-end policy tests

Tool-native settings remain part of the effective runtime verdict during
evaluation and verification.

## RTK Integration

When `cmdproxy hook claude --rtk` is used, the runtime order is:

1. evaluate `cmdproxy` rewrite pipeline
2. evaluate `cmdproxy` permission pipeline
3. evaluate Claude settings permission
4. combine both verdicts
5. if not denied, apply the final `rtk` rewrite
6. emit the final `updatedInput.command`

This keeps permission decisions stable even when external Bash hooks are not
executed serially, and it ensures permission checks happen before `rtk`
rewrites the visible command.
