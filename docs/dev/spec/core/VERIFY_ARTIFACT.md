---
title: "Verified Hook Artifact"
status: proposed
date: 2026-04-21
---

# Verified Hook Artifact

## Purpose

`cc-bash-guard` should not execute hook-time policy directly from the human-edited
YAML source config.

Instead, `cc-bash-guard verify` compiles the current effective config into a
machine-only JSON artifact. `cc-bash-guard hook` reads only that artifact.

## Required Fields

The runtime artifact must carry at least:

- `version`
- `tool`
- `fingerprint`
- `source_paths`
- `settings_paths`
- `cmdproxy_version`
- `evaluation_semantics_version`
- `verified_at`
- `pipeline`

## Runtime Gate

`cc-bash-guard hook` should:

1. resolve the current effective `cc-bash-guard` sources for that tool
2. resolve the current tool settings files for that tool
3. compute the effective fingerprint from both policy files and tool settings
4. look for the artifact matching that fingerprint and tool
5. reject execution if the artifact is missing, stale, or was compiled for an
   incompatible evaluation semantics version
6. evaluate only the compiled pipeline from that artifact

`evaluation_semantics_version` is bumped when policy evaluation semantics change
in a way that can affect allow/ask/deny outcomes. A mismatch must fail closed and
tell the user to run `cc-bash-guard verify`.

When config files use top-level `include`, `verify` resolves all included files
recursively before writing the artifact. `source_paths` contains the root config
files and included config files that contributed to the bundled pipeline.
Included file contents are part of the effective fingerprint, so changing any
included file makes the artifact stale. Hook runtime evaluates the bundled
pipeline from the artifact rather than treating included YAML files as separate
policy inputs.

For Claude hook execution, the effective fingerprint also includes the
permission-relevant parts of Claude settings files: `permissions.allow`,
`permissions.ask`, and `permissions.deny`. Unrelated Claude settings keys do
not make the artifact stale.

## Non-Goals

- human readability
- user editing
- long-term compatibility across arbitrary schema generations

The artifact is an internal compiled runtime format, not a public config
surface.

## Contract Metadata

The artifact does not need to expose human-readable support tiers, but the
compiled pipeline inside it may depend on built-in contracts from multiple tiers.

At minimum, the runtime should preserve the already-validated rewrite specs.
Future versions may include contract metadata when that materially improves
runtime diagnostics.
