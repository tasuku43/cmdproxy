---
title: "Verified Hook Artifact"
status: proposed
date: 2026-04-21
---

# Verified Hook Artifact

## Purpose

`cc-bash-proxy` should not execute hook-time policy directly from the human-edited
YAML source config.

Instead, `cc-bash-proxy verify` compiles the current effective config into a
machine-only JSON artifact. `cc-bash-proxy hook` reads only that artifact.

## Required Fields

The runtime artifact must carry at least:

- `version`
- `tool`
- `fingerprint`
- `source_paths`
- `settings_paths`
- `cmdproxy_version`
- `verified_at`
- `pipeline`

## Runtime Gate

`cc-bash-proxy hook` should:

1. resolve the current effective `cc-bash-proxy` sources for that tool
2. resolve the current tool settings files for that tool
3. compute the effective fingerprint from both policy files and tool settings
4. look for the artifact matching that fingerprint and tool
5. reject execution if the artifact is missing or stale
6. evaluate only the compiled pipeline from that artifact

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
