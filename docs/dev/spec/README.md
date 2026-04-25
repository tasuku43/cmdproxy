---
title: "cc-bash-proxy specs"
status: implemented
date: 2026-04-25
---

# cc-bash-proxy specs

This directory contains the implementation contracts for `cc-bash-proxy`.
Each spec file declares its own status. Only `status: implemented` documents
behavior that should be treated as current contract.

`status: proposed` and `status: planned` documents may describe target behavior,
but coding agents and contributors must not treat those documents as shipped
behavior.

The repository uses a pipeline model with:

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

### Core

| Spec | Status | Scope |
|---|---|---|
| `core/COMPATIBILITY.md` | implemented | versioning and compatibility stance |
| `core/CONFIG.md` | implemented | config locations, merge order, and invalid-state handling |
| `core/EVALUATION.md` | implemented | rewrite phase, permission phase, compound command evaluation, raw allow, and fail-closed behavior |
| `core/INPUT_MODEL.md` | implemented | supported stdin payloads and normalized invocation model |
| `core/PARSER_MODEL.md` | implemented | command parser layers and match stability rules |
| `core/RULE_SCHEMA.md` | implemented | YAML schema for `rewrite`, `permission`, and `test` |
| `core/OUTPUT_CONTRACT.md` | proposed | output contract for allow, ask, deny, and error |
| `core/VERIFY_ARTIFACT.md` | proposed | trust-oriented verified policy artifact details |

### Commands

| Spec | Status | Scope |
|---|---|---|
| `commands/doctor.md` | proposed | setup and pipeline health diagnostics |
| `commands/hook.md` | proposed | Claude Code hook entrypoint and hook-specific output contract |
| `commands/init.md` | proposed | setup and starter config behavior |
| `commands/verify.md` | proposed | trust-oriented local verification |
| `commands/version.md` | proposed | binary build metadata and provenance visibility |

## Source Of Truth

- User-facing current behavior: `README.md`
- Implementation contract: `docs/dev/spec/*` entries with `status: implemented`
- Actual behavior: tests plus `internal/domain/*`

If README, spec, tests, and implementation disagree, do not silently pick one.
For permission behavior, preserve security-first behavior and fail closed for
ambiguity. Document the gap, update tests for the chosen behavior, and update
README/spec together with code when behavior changes.

## Known Gaps

- Command-level specs under `docs/dev/spec/commands/*` are still marked
  `proposed`; use CLI tests and implementation as the current behavior until
  those specs are promoted to `implemented`.
- `core/OUTPUT_CONTRACT.md` and `core/VERIFY_ARTIFACT.md` are still marked
  `proposed`; do not treat all details there as current contract.
