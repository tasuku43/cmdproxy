---
title: "cc-bash-proxy doctor"
status: proposed
date: 2026-04-19
---

# cc-bash-proxy doctor

## Purpose

`cc-bash-proxy doctor` reports the health of the current `cc-bash-proxy` setup,
configuration, and integration posture.

## Categories

Target doctor checks should be grouped into:

- `config`: config presence, parseability, schema validity
- `rules`: matcher validity, directive validity, examples present, examples pass
- `diagnostics`: likely shadowing, broad regex escape hatches, risky rule order
- `install`: binary presence, build metadata visibility, and supported hook integration checks

## Role During The Transition

As the project moves from deny-only rules to directive-based policy, `doctor`
should make the transition visible by flagging:

- legacy patterns that should become structured matchers
- rules that still rely on broad regex escape hatches
- config that cannot express rewrite behavior yet

Warnings remain non-fatal. Hard failures should be reserved for broken config or
invalid rule definitions.

## Security-oriented Checks

`doctor` should also help users inspect their local trust boundary.

Useful install checks include:

- whether `cc-bash-proxy` is on `PATH`
- which executable path is currently running
- whether the binary exposes build metadata such as VCS revision
- whether Claude Code is wired to `cc-bash-proxy hook`
