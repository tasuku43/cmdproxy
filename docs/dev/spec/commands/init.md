---
title: "cmdproxy init"
status: proposed
date: 2026-04-19
---

# cmdproxy init

## Purpose

`cmdproxy init` bootstraps a local `cmdproxy` setup without destructively
modifying existing user configuration.

## Target Responsibilities

`cmdproxy init` should:

- create a starter user-wide config when one does not exist
- explain where the user-wide config lives
- detect compatible Claude Code settings files
- print the hook snippet needed to register `cmdproxy hook claude`

## Starter Config Goal

The starter config should reflect the new product identity.

It should:

- use the current target schema version
- demonstrate at least one structured matcher
- demonstrate a directive, preferably `rewrite` or `reject`
- include examples that show the intended rule effect
- be valid under `cmdproxy test`

## Safety Principle

`init` should remain conservative and idempotent.

- never overwrite an existing user config silently
- prefer showing status and next steps over mutating non-trivial caller config
- keep the generated starter config small and explanatory
