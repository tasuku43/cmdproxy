---
title: "cmdproxy verify"
status: proposed
date: 2026-04-20
---

# cmdproxy verify

## Purpose

`cmdproxy verify` is a stricter trust-oriented check than `cmdproxy doctor`.

It exists to answer a narrower question:

**Can the current local `cmdproxy` setup be reasonably trusted as part of the
execution path?**

## Behavior

`cmdproxy verify` should:

- run the same config and rule validation used by `doctor`
- require build metadata to be visible in the current binary
- fail if Claude Code settings exist but do not point at `cmdproxy hook claude`
- fail if Claude Code settings use `cmdproxy hook claude` via PATH lookup
  rather than an absolute binary path

It should not require Claude Code to be installed. If no Claude settings file is
present, that condition should remain informational rather than fatal.

## Output

### Human-readable

The default output should include:

- the running version
- the visible VCS revision or an explicit missing marker
- the underlying doctor-style checks
- a final verified true/false result

### JSON

`cmdproxy verify --format json` should expose:

- `verified`
- `build_info`
- `report`
- `failures`

## Relationship To `doctor`

- `doctor` is broad and diagnostic
- `verify` is narrow and trust-oriented

`doctor` may emit warnings that are acceptable in development. `verify` should
promote a smaller set of trust-critical conditions into failures.
