---
title: "cc-bash-proxy specs"
status: proposed
date: 2026-04-22
---

# cc-bash-proxy specs

This directory contains the proposed implementation contracts for the current
`cc-bash-proxy` model.

The repository is moving from a directive-oriented redesign into a pipeline
model with:

1. rewrite
2. permission
3. end-to-end testing

## Metadata rules

- Required: `title`, `status`
- Optional: `date`, `pending`

### `status` values

- `planned`: the topic is identified but behavior is not yet selected
- `proposed`: the target behavior is selected but not fully implemented
- `implemented`: the documented behavior is implemented and current

## Target priorities

The current `cc-bash-proxy` contract prioritizes:

1. Invocation canonicalization before permission evaluation
2. `cc-bash-proxy`-owned permission decisions
3. Simple caller input, rich internal normalization
4. Deterministic rewrite ordering and deterministic permission bucket ordering
5. Reviewable, testable policy authoring

## Index

- Core
  - `core/COMPATIBILITY.md`: versioning and compatibility stance
  - `core/INPUT_MODEL.md`: supported stdin payloads and normalized invocation model
  - `core/PARSER_MODEL.md`: command parser layers and match stability rules
  - `core/RULE_SCHEMA.md`: YAML schema for `rewrite`, `permission`, and `test`
  - `core/CONFIG.md`: config locations and invalid-state handling
  - `core/EVALUATION.md`: rewrite phase plus permission phase
  - `core/OUTPUT_CONTRACT.md`: output contract for allow, ask, deny, and error
- Commands
  - `commands/hook.md`: Claude Code hook entrypoint and hook-specific output contract
  - `commands/init.md`: setup and starter config behavior
  - `commands/doctor.md`: setup and pipeline health diagnostics
  - `commands/verify.md`: trust-oriented local verification
  - `commands/version.md`: binary build metadata and provenance visibility

## Source Of Truth

During this transition, these specs define the intended target model. Where
implementation and spec differ, treat the spec as the redesign target and note
the gap explicitly.
