---
title: "Security Trust Model Design"
status: proposed
date: 2026-04-20
---

# Security Trust Model Design

## Summary

This plan defines the publication-time security stance for `cc-bash-proxy`.

The main security concern is not user-authored rules. It is the risk that a
published binary or merged implementation change could introduce malicious
rewrite behavior. Because `cc-bash-proxy` runs directly in the command path before
execution, a compromised build could change invocation shape in ways that are
hard for users to notice.

## Threat Priorities

Highest priority:

1. malicious or compromised changes to rewrite behavior
2. compromised release artifacts
3. local binary replacement after installation

Lower priority for this phase:

1. user-written dangerous policies
2. low-level sandbox escape paths outside the tool's responsibility

## Design Response

### Product-level constraints

- keep rewrites typed and declarative
- avoid free-form command templating
- preserve visible traceability for every rewrite chain

### Development controls

- protect the default branch
- require review for merges
- add `CODEOWNERS` for:
  - `internal/cli`
  - `internal/config`
  - `internal/domain/directive`
  - `internal/domain/policy`
  - `docs/dev/spec`

### Release controls

- publish checksums with every release
- expose commit metadata in the binary
- prefer signed artifacts or artifact attestations

### Runtime verification

- add `cc-bash-proxy version --build-info`
- add a `verify` command or equivalent `doctor` checks for:
  - resolved binary path
  - Claude hook command wiring
  - config path
  - build metadata visibility

## Success Criteria

This work is successful when:

1. users can identify exactly which binary they are running
2. release artifacts can be checksum-verified
3. security-sensitive paths cannot merge without review
4. rewrite behavior stays observable to the user

## Implementation Order

1. document the trust model
2. add build metadata output
3. add release checksum publication
4. add review protection and `CODEOWNERS`
5. add verification command or `doctor` extension
