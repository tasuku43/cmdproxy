---
title: "cc-bash-proxy init"
status: proposed
date: 2026-04-19
---

# cc-bash-proxy init

## Purpose

`cc-bash-proxy init` bootstraps a local `cc-bash-proxy` setup without destructively
modifying existing user configuration.

## Target Responsibilities

`cc-bash-proxy init` should:

- create a starter user-wide config when one does not exist
- explain where the user-wide config lives
- detect compatible Claude Code settings files
- print the hook snippet needed to register `cc-bash-proxy hook`

## Starter Config Goal

The starter config should reflect the new product identity.

It should:

- use the current schema shape without requiring an in-file version field
- demonstrate at least one structured matcher
- demonstrate a directive, preferably `rewrite` or `reject`
- include examples that show the intended rule effect
- be valid under `cc-bash-proxy verify`

## Safety Principle

`init` should remain conservative and idempotent.

- never overwrite an existing user config silently
- prefer showing status and next steps over mutating non-trivial caller config
- keep the generated starter config small and explanatory
