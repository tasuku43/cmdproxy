---
title: "cc-bash-proxy check"
status: proposed
date: 2026-04-19
---

# cc-bash-proxy check

## Purpose

`cc-bash-proxy check` evaluates a single invocation interactively without requiring
stdin JSON from an external hook.

## Relationship To `hook`

`cc-bash-proxy check` is the interactive convenience wrapper over the same directive
application logic used by `cc-bash-proxy hook`.

- it accepts a command string as CLI input
- it constructs the canonical execution request internally
- it applies the same parse, match, and directive flow
- it emits the same pass / rewrite / reject / error outcomes

## Use Cases

- ad-hoc debugging while authoring rules
- checking whether a command would be rewritten
- confirming whether a command would be rejected
- observing the canonicalized form before relying on Claude Code hooks
