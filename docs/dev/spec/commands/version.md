---
title: "cc-bash-proxy version"
status: proposed
date: 2026-04-20
---

# cc-bash-proxy version

## Purpose

`cc-bash-proxy version` prints build and provenance metadata for the running binary.

The main security purpose of this command is to help users confirm which build
they are executing before trusting it as part of their command path.

## Behavior

`cc-bash-proxy version` should report:

- tool version
- module path
- Go toolchain version
- VCS revision when available
- VCS build time when available
- VCS modified state when available

## Output Modes

### Human-readable

The default output should be concise and easy to inspect in a terminal.

### JSON

`cc-bash-proxy version --format json` should emit machine-readable metadata suitable
for diagnostics, support scripts, or future verification commands.

## Role In The Security Model

This command is not a full verification workflow by itself. It is a visibility
primitive that supports:

- manual provenance inspection
- troubleshooting mismatched installed binaries
- future `verify` or `doctor` checks
