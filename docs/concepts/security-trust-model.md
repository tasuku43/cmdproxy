---
title: "Security Trust Model"
status: proposed
date: 2026-04-20
---

# Security Trust Model

## 1. Why This Matters

`cc-bash-proxy` is not a passive formatter. It may rewrite commands immediately
before execution. That makes it more security-sensitive than a typical local
CLI.

If a malicious change lands in the distributed binary, the risk is not limited
to crashes or incorrect output. A compromised build could:

- rewrite a command into a different credential shape
- insert unexpected wrappers or flags
- weaken the user's downstream permission model
- silently redirect execution into an organization-unsafe form

For that reason, users should treat `cc-bash-proxy` as part of their local execution
trust boundary.

## 2. Primary Threat Model

The highest-priority threat for `cc-bash-proxy` is **binary or implementation
tampering**.

This includes:

1. a malicious contribution that changes rewrite behavior
2. a compromised release process that ships different code than the reviewed
   repository state
3. a local replacement of the expected binary after installation

This document does **not** treat user-authored policy rules as the main threat.
Dangerous local rules are still possible, but the primary security question for
publication is whether users can trust the shipped tool itself.

## 3. Security Principles

`cc-bash-proxy` should follow these principles:

1. **Typed rewrites only**
   Rewrites must remain narrow, typed, and reviewable. Free-form command
   templating or script execution should stay out of scope.
2. **Deterministic behavior**
   A reviewed rule set and reviewed binary should produce predictable results.
3. **Visible transformations**
   Rewrites should be observable through trace data and user-visible summaries.
4. **Minimal trust expansion**
   `cc-bash-proxy` should normalize command shape, not become a general shell macro
   engine.
5. **Verifiable distribution**
   Users should be able to verify what binary they installed and what source
   revision it came from.

## 4. Required Publication Controls

Before wider publication, the project should adopt the following baseline:

### Repository and Review

- protect the default branch
- require PR review before merge
- add `CODEOWNERS` for security-sensitive paths
- treat changes in hook handling, rewrite primitives, config loading, and rule
  evaluation as security-sensitive

### Release Integrity

- publish release checksums for every binary artifact
- expose build metadata such as version and commit
- prefer signed releases or artifact attestations over unsigned binaries
- document the recommended verified installation path

### Runtime Verification

- make it easy to inspect the installed binary identity
- make it easy to inspect the hook command Claude Code is actually executing
- keep rewrite behavior visible through trace and `systemMessage`

## 5. Near-term Project Work

The next practical security steps are:

1. add `cc-bash-proxy version --build-info`
2. add a verification command for installation and hook wiring
3. add `CODEOWNERS` for hook, directive, policy, and config-loading paths
4. publish checksums for release artifacts
5. document a verified install workflow in the README

## 6. Non-goals

This trust model does not attempt to solve:

- low-level runtime sandboxing
- credential compromise outside `cc-bash-proxy`
- arbitrary shell escape paths that should be handled by the downstream runtime
- centralized remote policy enforcement

`cc-bash-proxy` should remain a local invocation policy proxy, but one that users can
reasonably trust as part of their execution boundary.
