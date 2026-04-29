# Releasing

## Overview

`cc-bash-guard` releases are tag-driven.

The intended pipeline is:

1. push a tag like `v0.1.0`
2. run CI-style preflight checks
3. build archives with GoReleaser
4. publish GitHub Release artifacts and `checksums.txt`
5. for stable tags without prerelease suffixes, optionally open a PR against
   `tasuku43/homebrew-cc-bash-guard`

This document describes the designed release process. If no public GitHub
Release exists yet, treat these steps as the target release policy rather than
an already-exercised distribution guarantee.

As of the latest repository check, public GitHub Releases exist. The current
release state still needs to be verified per release by inspecting the GitHub
Release assets, workflow run, and attestation availability; this document does
not make retroactive guarantees for every previously published tag.

## Release Inputs

- Workflow: `.github/workflows/release.yml`
- Packaging: `.goreleaser.yaml`
- Homebrew update script: `.github/scripts/update-homebrew-formula.sh`
- Local preflight: `task release:preflight`

## Artifacts

The intended release policy is that every tagged release publishes:

- platform archives
- `checksums.txt`
- artifact attestations for archives and `checksums.txt`

Checksums are part of the security story for `cc-bash-guard` because users are
trusting a binary that can allow, ask for confirmation, or deny Claude Code
Bash execution. Default policy evaluation does not rewrite commands; `hook
--rtk` is the explicit bridge to external RTK rewriting.

The automated workflow currently builds archives with GoReleaser, publishes
`checksums.txt`, and calls `actions/attest` for the archives listed in
`dist/checksums.txt` and for `dist/checksums.txt` itself. For releases that
include GitHub Artifact Attestations, consumers can verify provenance with:

```sh
gh attestation verify path/to/cc-bash-guard_<tag>_<os>_<arch>.tar.gz -R tasuku43/cc-bash-guard
gh attestation verify path/to/checksums.txt -R tasuku43/cc-bash-guard
```

Checksums and attestations are integrity and provenance signals. They do not
prove that the source code is safe, that the binary's runtime behavior is safe,
or that the maintainer and repository should be trusted.

Use `task release:preflight` before pushing a tag. It runs formatting checks,
`go vet`, `go test`, Staticcheck, binary smoke tests, `govulncheck`, and
`goreleaser check` so the GoReleaser configuration is validated without
publishing artifacts.

## Automated Workflow Behavior

The release pipeline should enforce as much as possible automatically. The
current workflow behavior is:

1. tag pushes matching `v*` trigger `.github/workflows/release.yml`
2. `task release:preflight` runs before publishing
3. GoReleaser builds macOS and Linux archives for `amd64` and `arm64`
   (`amd64` archives are named `x64`)
4. GoReleaser publishes `checksums.txt`
5. `actions/attest` generates provenance attestations for archives listed in
   `dist/checksums.txt` and for `dist/checksums.txt`
6. stable tags without prerelease suffixes attempt the Homebrew tap PR path

The intended health criteria for a release are:

1. CI-quality checks already passed before code merged to `main`
2. the release workflow completed successfully for the pushed tag
3. the GitHub Release contains:
   - macOS archives for amd64 (`x64`) and arm64
   - Linux archives for amd64 (`x64`) and arm64
   - `checksums.txt`
4. stable tags open a Homebrew formula PR when Homebrew secrets are configured
5. the Homebrew tap is treated as part of the trusted release path, not as an
   independent substitute for release checksums and attestations

Do not treat CI success alone as a complete trust guarantee. CI shows that the
configured checks passed in that workflow context; it does not replace review of
the code, release configuration, repository permissions, or the downloaded
artifact.

## Manual Maintainer Verification

Manual checks should stay small and focus on what CI cannot prove by itself.

After a release is published:

1. confirm the release is not a draft and has the intended prerelease status
2. confirm the expected archives and `checksums.txt` are attached
3. download one artifact
4. verify its checksum against `checksums.txt`
5. run `gh attestation verify` against the downloaded artifact and
   `checksums.txt` when attestations are present
6. install or unpack the artifact and run:
   - `cc-bash-guard version --format json`
   - `cc-bash-guard verify --format json`
   - `cc-bash-guard help semantic`
7. confirm the reported VCS revision matches the intended release commit when
   the version output exposes it
8. for stable tags, confirm whether the Homebrew formula PR was opened; if not,
   determine whether Homebrew secrets were absent or the tap update failed

## User-Side Release Verification

Users should verify their own downloaded copy before trusting it to make shell
permission decisions:

1. download the archive for their platform
2. download `checksums.txt` from the same GitHub Release
3. verify the archive checksum:

   ```sh
   grep "  cc-bash-guard_<tag>_<os>_<arch>.tar.gz$" checksums.txt | shasum -a 256 -c -
   ```

4. for releases that include attestations, verify the archive and checksum file:

   ```sh
   gh attestation verify cc-bash-guard_<tag>_<os>_<arch>.tar.gz -R tasuku43/cc-bash-guard
   gh attestation verify checksums.txt -R tasuku43/cc-bash-guard
   ```

5. run:
   - `cc-bash-guard version --format json`
   - `cc-bash-guard verify --format json`
6. confirm the VCS revision or tag when exposed by version output

## Security Notes

- `checksums.txt` is the minimum release integrity signal and should always be
  present.
- GitHub Artifact Attestations should be present for newly published release
  archives and `checksums.txt` while the current workflow remains in use.
- A release is not considered fully verified until an artifact has been
  downloaded and checked outside the CI environment.
- A release artifact is still executable code from this repository and
  maintainer path; checksums and attestations do not make it a sandbox or prove
  runtime safety.

## Homebrew Tap

Stable tags can update the Homebrew tap automatically when these secrets are
configured:

- `HOMEBREW_APP_ID`
- `HOMEBREW_APP_KEY`

Without those secrets, the GitHub Release still completes and Homebrew update
steps are skipped.

The Homebrew tap is part of the delivery path, so it should inherit the same
minimum trust controls as the main repository:

- review is required before formula changes merge
- the tap may auto-merge only the trusted release bot PRs
- formula changes should have CI validation in the tap repository
- users should still verify release checksums and attestations against the
  GitHub Release artifacts that the formula references
