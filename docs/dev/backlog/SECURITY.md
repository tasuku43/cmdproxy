---
title: "SECURITY backlog"
status: implemented
date: 2026-04-21
---

# SECURITY Backlog

This backlog tracks the security work required to publish and operate
`cmdproxy` as a trusted command-rewriting binary.

The primary threat model is **binary or implementation tampering**, not
user-authored rules.

## P0: Must be completed before public release

- [x] SECURITY-001: Trust model documentation
  - What: define the publication-time threat model, trust boundary, and minimum
    controls for a command-rewriting binary.
  - Specs:
    - `docs/concepts/security-trust-model.md`
    - `docs/plans/2026-04-20-security-trust-model-design.md`
  - Depends: none
  - Serial: no

- [x] SECURITY-002: Security-sensitive path ownership
  - What: protect rewrite, hook, config-loading, and policy paths with
    `CODEOWNERS`.
  - Specs:
    - `.github/CODEOWNERS`
  - Depends: none
  - Serial: no

- [x] SECURITY-003: Binary provenance visibility
  - What: expose build metadata so users can inspect the running binary.
  - Specs:
    - `internal/buildinfo/buildinfo.go`
    - `internal/cli/app.go`
    - `docs/dev/spec/commands/version.md`
  - Depends: none
  - Serial: no

- [x] SECURITY-004: Trust-oriented local verification
  - What: add a strict local verification command on top of `doctor`.
  - Specs:
    - `internal/cli/app.go`
    - `docs/dev/spec/commands/verify.md`
  - Depends: SECURITY-003
  - Serial: yes

- [x] SECURITY-005: Vulnerability scanning in CI
  - What: run `govulncheck` in CI and nightly automation.
  - Specs:
    - `.github/workflows/ci.yml`
    - `.github/workflows/security-nightly.yml`
    - `Taskfile.yml`
  - Depends: none
  - Serial: no

- [x] SECURITY-006: Release checksums
  - What: publish `checksums.txt` with every release.
  - Specs:
    - `.goreleaser.yaml`
    - `.github/workflows/release.yml`
    - `docs/dev/ops/RELEASING.md`
  - Depends: none
  - Serial: yes

- [x] SECURITY-007: Signed release artifacts or attestations
  - What: add artifact signing or GitHub artifact attestation so users can
    verify checksums against a trusted release process.
  - Specs:
    - `.github/workflows/release.yml`
    - `docs/dev/ops/RELEASING.md`
    - `README.md`
  - Depends: SECURITY-006
  - Serial: yes

- [x] SECURITY-008: Branch protection and required review policy
  - What: enable GitHub branch protection and require review before merge for
    the default branch.
  - Specs:
    - repository settings
    - `CONTRIBUTING.md`
  - Depends: SECURITY-002
  - Serial: yes

- [x] SECURITY-009: Public security policy
  - What: add `SECURITY.md` describing vulnerability reporting and supported
    release verification paths.
  - Specs:
    - `SECURITY.md`
    - `README.md`
  - Depends: SECURITY-001
  - Serial: no

- [x] SECURITY-010: Contribution security gate
  - What: add `CONTRIBUTING.md` guidance for security-sensitive changes,
    required quality checks, and release expectations.
  - Specs:
    - `CONTRIBUTING.md`
    - `docs/dev/backlog/README.md`
  - Depends: SECURITY-002
  - Serial: no

- [x] SECURITY-016: Resolve `GO-2026-4602` in release toolchains
  - What: update the project's Go toolchain baseline and CI / release runners
    so release artifacts are built and scanned with a Go version that includes
    the fix for `GO-2026-4602` (`os`, fixed in Go `1.25.8`).
  - Why:
    - GitHub Actions run `24689692027` failed in `govulncheck`
    - the current code path is reported via `internal/config/load.go`
  - Specs:
    - `go.mod`
    - `Taskfile.yml`
    - `.github/workflows/ci.yml`
    - `.github/workflows/security-nightly.yml`
    - `.github/workflows/release.yml`
    - `CONTRIBUTING.md`
  - Depends: SECURITY-005
  - Serial: yes

## P1: High priority after release baseline

- [x] SECURITY-011: `verify` hook-path strictness
  - What: make `verify` distinguish between acceptable development states and
    suspicious production wiring, including mismatched hook commands and missing
    absolute-path guidance.
  - Specs:
    - `internal/cli/app.go`
    - `internal/doctor/doctor.go`
    - `docs/dev/spec/commands/verify.md`
  - Depends: SECURITY-004
  - Serial: no

- [x] SECURITY-012: Release verification guide
  - What: document a concrete user workflow for verifying downloaded artifacts,
    checksums, and provenance metadata.
  - Specs:
    - `README.md`
    - `docs/user/START_HERE.md`
    - `docs/dev/ops/RELEASING.md`
  - Depends: SECURITY-006
  - Serial: no

- [x] SECURITY-013: Review checklist for rewrite changes
  - What: define a PR checklist for changes that affect rewrite primitives,
    hook output, config loading, or policy evaluation.
  - Specs:
    - `CONTRIBUTING.md`
    - PR template
  - Depends: SECURITY-002
  - Serial: no

- [ ] SECURITY-014: CI pinning hardening
  - What: replace floating `@latest` tool installs in CI with pinned versions
    where practical.
  - Specs:
    - `.github/workflows/ci.yml`
    - `.github/workflows/security-nightly.yml`
    - `.github/workflows/release.yml`
    - `Taskfile.yml`
  - Depends: SECURITY-005
  - Serial: no

- [x] SECURITY-015: Release invariant automation baseline
  - What: rewrite release operations guidance so the default expectation is that
    main-branch protection and release workflows guarantee most conditions
    automatically, leaving only minimal human verification after publish.
  - Specs:
    - `docs/dev/ops/RELEASING.md`
  - Depends: SECURITY-006
  - Serial: no

## P2: Medium-term improvements

- [ ] SECURITY-021: Tap-release trust documentation
  - What: document the trust assumptions for Homebrew tap updates and how they
    relate to signed releases and checksums.
  - Specs:
    - `docs/dev/ops/RELEASING.md`
    - `README.md`
  - Depends: SECURITY-007
  - Serial: no

- [ ] SECURITY-022: Richer local integrity checks
  - What: explore integrity checking for installed hook wiring and expected
    binary path, inspired by `rtk verify`.
  - Specs:
    - `internal/cli/app.go`
    - `internal/doctor/doctor.go`
    - `docs/dev/spec/commands/verify.md`
  - Depends: SECURITY-011
  - Serial: no

- [ ] SECURITY-023: `homebrew-cmdproxy` release-pipeline integration
  - What: define and implement the release-path contract between the main
    `cmdproxy` repository and `tasuku43/homebrew-cmdproxy`, so Homebrew formula
    updates are treated as part of the trusted publish pipeline rather than an
    ad-hoc post-release step.
  - Specs:
    - `.github/workflows/release.yml`
    - `.github/scripts/update-homebrew-formula.sh`
    - `docs/dev/ops/RELEASING.md`
    - `/Users/tasuku43/work/github.com/tasuku43/homebrew-cmdproxy`
  - Depends: SECURITY-006
  - Serial: yes

- [ ] SECURITY-024: `homebrew-cmdproxy` repository protections and CI baseline
  - What: apply the same minimum trust controls to the tap repository, including
    branch protection, required review, and CI validation for formula changes,
    so a compromised or weakly protected tap cannot undercut signed releases and
    checksums from the main repository.
  - Specs:
    - `/Users/tasuku43/work/github.com/tasuku43/homebrew-cmdproxy`
    - `docs/dev/ops/RELEASING.md`
  - Depends: SECURITY-023
  - Serial: yes
