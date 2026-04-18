---
title: "cmdguard specs"
status: implemented
date: 2026-04-18
---

# cmdguard specs

This directory contains the implementation contracts for `cmdguard`.
Implementation should follow these specs. When behavior changes, update the
relevant spec first.

## Metadata rules

- Required: `title`, `status`
- Optional: `date`, `pending`

### `status` values

- `planned`: the topic is identified but behavior is not yet selected
- `proposed`: the target behavior is selected for implementation
- `implemented`: the documented behavior is implemented and current

## v1 contract priorities

`cmdguard` v1 prioritizes deterministic runtime behavior over expressive rule
features. The core CLI contract is:

1. Deny-only rule model
2. Deterministic evaluation order
3. Fail-closed handling for malformed or unknown execution input
4. Stable human-readable and machine-readable deny output

## Index

- Core
  - `core/COMPATIBILITY.md`: schema stability and distribution stance
  - `core/INPUT_MODEL.md`: supported stdin payloads and normalization rules
  - `core/RULE_SCHEMA.md`: YAML rule file schema and field validation
  - `core/CONFIG.md`: config locations, layer model, and invalid-state handling
  - `core/EVALUATION.md`: rule model, evaluation order, and match selection
  - `core/OUTPUT_CONTRACT.md`: exit codes and output payloads
- Commands
  - `commands/eval.md`: hook entrypoint behavior
  - `commands/check.md`: single-command evaluation without hook JSON
  - `commands/init.md`: safe setup and starter config behavior
  - `commands/test.md`: rule example verification behavior
  - `commands/doctor.md`: setup and rule health diagnostics

## Source of truth

The files under `docs/dev/spec/` define the implementation contracts that
should drive code and tests.
