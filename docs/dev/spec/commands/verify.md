---
title: "cmdproxy verify"
status: proposed
date: 2026-04-23
---

# cmdproxy verify

## Purpose

`cmdproxy verify <tool>` is a stricter trust-oriented check than `cmdproxy doctor`.

It exists to answer a narrower question:

**Can the current local `cmdproxy` setup for this tool be reasonably trusted as
part of the execution path?**

## Behavior

`cmdproxy verify <tool>` should:

- resolve and merge global and project-local `cmdproxy` policy
- resolve global and project-local settings for the target tool
- run the same config and rule validation used by `doctor`
- run rewrite tests, permission rule tests, and top-level E2E tests against the
  effective merged state
- compile and write a tool-specific verified hook artifact
- require build metadata to be visible in the current binary
- for Claude, fail if Claude Code settings exist but do not point at
  `cmdproxy hook claude`
- for Claude, fail if Claude Code settings use `cmdproxy hook claude` via PATH lookup
  rather than an absolute binary path
- for Claude, fail if an absolute Claude Code hook target does not exist or is not
  executable
- for Claude, fail if Claude Code points at a different `cmdproxy` binary than the one
  currently being verified

It should not require the target tool to be installed. If no tool settings file
is present, that condition should remain informational rather than fatal.

## Output

### Human-readable

The default output should include:

- the running version
- the target tool
- the visible VCS revision or an explicit missing marker
- the underlying doctor-style checks
- a final verified true/false result
- the artifact cache paths when verification also produced executable hook artifacts

### JSON

`cmdproxy verify --format json` should expose:

- `verified`
- `tool`
- `build_info`
- `report`
- `failures`
- `artifact_built`
- `artifact_cache`

## Relationship To `doctor`

- `doctor` is broad and diagnostic
- `verify` is narrow and trust-oriented

`doctor` may emit warnings that are acceptable in development. `verify` should
promote a smaller set of trust-critical conditions into failures.

## Hook Relationship

`cmdproxy hook <tool>` reads only verified artifacts at runtime.

- If a verified artifact exists and matches the current config hash, the hook uses it
- If the config changed and no verified artifact is available, the hook should try an implicit verify once
- If that implicit verify still fails, the hook must return a deny response with `invalid_config`
