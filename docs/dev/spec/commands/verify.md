---
title: "cc-bash-proxy verify"
status: proposed
date: 2026-04-23
---

# cc-bash-proxy verify

## Purpose

`cc-bash-proxy verify` is a stricter trust-oriented check than `cc-bash-proxy doctor`.

It exists to answer a narrower question:

**Can the current local `cc-bash-proxy` setup be reasonably trusted as
part of the execution path?**

## Behavior

`cc-bash-proxy verify` should:

- resolve and merge global and project-local `cc-bash-proxy` policy
- resolve global and project-local settings for the target tool
- run the same config and rule validation used by `doctor`
- run rewrite tests, permission rule tests, and top-level E2E tests against the
  effective merged state
- compile and write a tool-specific verified hook artifact
- require build metadata to be visible in the current binary
- for Claude, fail if Claude Code settings exist but do not point at
  `cc-bash-proxy hook`
- for Claude, fail if Claude Code settings use `cc-bash-proxy hook` via PATH lookup
  rather than an absolute binary path
- for Claude, fail if an absolute Claude Code hook target does not exist or is not
  executable
- for Claude, fail if Claude Code points at a different `cc-bash-proxy` binary than the one
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

`cc-bash-proxy verify --format json` should expose:

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

`cc-bash-proxy hook` reads only verified artifacts at runtime.

- If a verified artifact exists and matches the current config hash, the hook uses it
- If the config changed and no verified artifact is available, the hook should try an implicit verify once
- If that implicit verify still fails, the hook must return a deny response with `invalid_config`
