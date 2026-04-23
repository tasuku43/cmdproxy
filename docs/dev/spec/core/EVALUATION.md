---
title: "Evaluation Model"
status: proposed
date: 2026-04-22
---

# Evaluation Model

## 1. Scope

This document defines the current evaluation model for `cc-bash-proxy`.

`cc-bash-proxy` evaluates a requested CLI invocation in two phases:

1. rewrite the command through an ordered rewrite pipeline
2. evaluate permissions on the rewritten command

## 2. Caller Contract

`cc-bash-proxy` keeps caller input intentionally simple.

- the caller provides a requested command invocation
- the primary external form is still a raw command string for `exec`
- internal parsing and normalization complexity stays inside `cc-bash-proxy`

The caller should not need to understand the internal matcher model.

## 3. Internal Normalization

Inside `cc-bash-proxy`, the raw command string is normalized into a parsed
invocation model that may include:

- environment assignments
- executable basename
- argument vector
- subcommand
- a limited set of launcher-style wrappers

Wrapper unwrapping is heuristic and intentionally limited. It is not a full
shell AST.

## 4. Configuration Source

The current target config location is a single user-wide file:

- `$XDG_CONFIG_HOME/cc-bash-proxy/cc-bash-proxy.yml`
- `~/.config/cc-bash-proxy/cc-bash-proxy.yml` when `XDG_CONFIG_HOME` is not set

## 5. Rewrite Phase

Rewrite evaluation order is fixed and deterministic.

1. Preserve rewrite step order from the file
2. For each rewrite step:
   - if the step has `match`, require it to match
   - attempt the single configured rewrite primitive
3. If the rewrite succeeds:
   - record a rewrite trace step
   - if `continue: true`, continue evaluating later rewrite steps against the rewritten command
   - otherwise stop the rewrite phase early

If a rewrite step is considered but cannot safely rewrite the invocation, it is
a no-op and evaluation continues.

Rewrite is policy-preserving canonicalization, not arbitrary transformation.

Examples:

- move a flag value into a sanctioned environment variable
- unwrap `bash -c 'single command'` into the direct command form
- remove a wrapper that obscures the effective executable
- normalize `/bin/ls` into `ls`

## 6. Permission Phase

After the rewrite phase finishes, `cc-bash-proxy` evaluates permission rules against
the resulting command.

Permission buckets are evaluated in this fixed order:

1. `deny`
2. `ask`
3. `allow`

Within each bucket, source order is preserved.

The first matching permission rule in the current bucket wins. If a bucket does
not match, evaluation moves to the next bucket.

If nothing matches, the default outcome is `ask`.

This yields three runtime outcomes:

- `deny`: the command is blocked
- `ask`: the user should be prompted
- `allow`: the command may proceed automatically

## 7. Hook Behavior

`cc-bash-proxy hook` maps the final permission outcome into Claude hook JSON:

- `allow`: emit `permissionDecision: "allow"`
- `ask`: omit `permissionDecision` so Claude prompts
- `deny`: emit `permissionDecision: "deny"`

If `--rtk` is enabled, the `rtk` rewrite runs only after `cc-bash-proxy` has
already decided the permission outcome.

## 8. Testing Model

The schema has three testing layers:

- rewrite-step-local tests
- permission-rule-local tests
- top-level end-to-end tests

Top-level E2E tests assert:

- the input command
- optionally the rewritten command
- the final decision

## 9. Consequences Of This Model

Because the contract is pipeline-based:

- rewrite order is meaningful
- permission order is meaningful within each effect bucket
- `deny -> ask -> allow` is part of the public behavior
- tests can deterministically assert both rewrite shape and final permission
  outcome
