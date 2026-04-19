---
title: "Configuration Model"
status: implemented
date: 2026-04-18
---

# Configuration Model

## 1. Scope

This document defines where `cmdproxy` looks for configuration in v1.

## 2. Supported Locations

v1 supports one primary configuration file:

1. User-wide: `$XDG_CONFIG_HOME/cmdproxy/cmdproxy.yml`, or
   `~/.config/cmdproxy/cmdproxy.yml` by default

The file is optional. If it does not exist, evaluation proceeds with an empty
rule set.

## 3. ID Collision Policy

Rule IDs must be unique across the effective configuration set.

- Duplicate IDs within one file are errors
v1 does not provide an override mechanism based on matching IDs.

## 4. Empty and Invalid States

- Missing file: allowed, treated as no configured rules
- Empty file: invalid configuration
- Invalid YAML: invalid configuration
- Valid YAML with schema errors: invalid configuration

Invalid configuration causes `cmdproxy hook claude` to return a deny response rather than
silently falling back to partial policy enforcement.

## 5. Future Extensions

These are post-v1 concerns:

- project-local policy files
- `include:` directives
- rule packs
- explicit override semantics
- additional config layers such as repo-global or team-managed paths
