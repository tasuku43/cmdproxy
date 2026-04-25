---
title: "Configuration Model"
status: implemented
date: 2026-04-18
---

# Configuration Model

## 1. Scope

This document defines where `cc-bash-proxy` looks for configuration in v1.

## 2. Supported Locations

`cc-bash-proxy` loads pure policy from two optional layers:

1. User-wide:
   - `$XDG_CONFIG_HOME/cc-bash-proxy/cc-bash-proxy.yml`, or
   - `~/.config/cc-bash-proxy/cc-bash-proxy.yml` by default
2. Project-local:
   - `<project-root>/.cc-bash-proxy/cc-bash-proxy.yml`
   - `<project-root>/.cc-bash-proxy/cc-bash-proxy.yaml`

The effective policy is the merge of:

- global `cc-bash-proxy` policy
- project-local `cc-bash-proxy` policy

Merge order is deterministic:

- user-wide policy is loaded first
- project-local policy is loaded second
- rewrite rules append in source order
- permission rules append within each bucket in source order
- top-level E2E tests append in source order
- scalar options, such as `claude_permission_merge_mode`, use the last
  non-empty value, so project-local config can override user-wide config

Project root resolution is currently delegated to the Claude-aware runtime paths
used by `cc-bash-proxy hook` and `cc-bash-proxy verify`.

Missing files are allowed and treated as absent layers.

## 3. Rule Identity

The current schema does not expose rule IDs. Rules are identified by their
position, source layer, bucket, selector, and effect in traces and validation
messages.

There is no ID-based override or collision behavior in the current contract.

## 4. Empty and Invalid States

- Missing file: allowed, treated as no configured rules
- Empty file: invalid configuration
- Invalid YAML: invalid configuration
- Valid YAML with schema errors: invalid configuration

Invalid configuration causes `cc-bash-proxy hook` to return a deny response rather than
silently falling back to partial policy enforcement.

## 5. Future Extensions

These are still post-v1 concerns:

- `include:` directives
- rule packs
- explicit override semantics
- rule IDs and ID collision policy
- additional config layers such as repo-global or team-managed paths
