---
title: "cmdguard doctor"
status: implemented
date: 2026-04-18
---

# cmdguard doctor

## Purpose

`cmdguard doctor` reports the health of the current `cmdguard` setup, including
configuration validity, rule quality, and installation state.

## Categories

v1 doctor checks should be grouped into these categories:

- `config`: file presence, parseability, schema validity
- `rules`: regex compilation, examples present, examples pass
- `diagnostics`: quality warnings such as likely shadowing or broad patterns
- `install`: binary and supported hook integration checks

## Required v1 Checks

At minimum, doctor should cover:

- config parsing for every discovered layer
- schema validation for every loaded rule
- duplicate rule IDs
- regex compilation
- example presence
- example pass/fail status
- Claude Code hook registration presence, when that environment exists

## Recommended Diagnostic Warnings

The following should be warnings rather than hard failures in v1:

- likely rule shadowing caused by first-match order
- overly broad patterns that match many allow examples unintentionally

These warnings are useful because v1 keeps the runtime model intentionally
simple and order-sensitive.

## Output Modes

`cmdguard doctor` supports:

- default human-readable output
- `--format json` structured output

The JSON form should be stable enough for CI consumption and should include at
least:

- check ID
- category
- status
- summary message

## Exit Behavior

- `0`: no failing checks
- `1`: one or more failing checks, or doctor itself encountered an error

Warnings alone should not make the command fail in v1.
