---
title: "cmdproxy specs"
status: proposed
date: 2026-04-19
---

# cmdproxy specs

This directory contains the proposed implementation contracts for the next
`cmdproxy` model.

The repository currently contains an earlier deny-only implementation. The
documents in this directory are being rewritten to define the target
directive-driven architecture.

## Metadata rules

- Required: `title`, `status`
- Optional: `date`, `pending`

### `status` values

- `planned`: the topic is identified but behavior is not yet selected
- `proposed`: the target behavior is selected but not fully implemented
- `implemented`: the documented behavior is implemented and current

## Target priorities

The next `cmdproxy` contract prioritizes:

1. Invocation canonicalization before permission evaluation
2. A directive model based on `rewrite` and `reject`
3. Simple caller input, rich internal normalization
4. Deterministic first-match rule application
5. Reviewable, testable policy authoring

## Index

- Core
  - `core/COMPATIBILITY.md`: versioning and compatibility stance
  - `core/INPUT_MODEL.md`: supported stdin payloads and normalized invocation model
  - `core/RULE_SCHEMA.md`: directive-based YAML schema
  - `core/CONFIG.md`: config locations and invalid-state handling
  - `core/EVALUATION.md`: parse, match, directive application, and pass-through behavior
  - `core/OUTPUT_CONTRACT.md`: output contract for pass, rewrite, reject, and error
- Commands
  - `commands/hook.md`: Claude Code hook entrypoint and hook-specific output contract
  - `commands/check.md`: interactive single-command evaluation
  - `commands/init.md`: setup and starter config behavior
  - `commands/test.md`: rule example verification behavior
  - `commands/doctor.md`: setup and rule health diagnostics

## Source Of Truth

During this transition, these specs define the intended target model. Where
implementation and spec differ, treat the spec as the redesign target and note
the gap explicitly.
