# Releasing

## Overview

`cc-bash-proxy` releases are tag-driven.

The intended pipeline is:

1. push a tag like `v0.1.0`
2. run CI-style preflight checks
3. build archives with GoReleaser
4. publish GitHub Release artifacts and `checksums.txt`
5. for stable tags without prerelease suffixes, optionally open a PR against
   `tasuku43/homebrew-cc-bash-proxy`

## Release Inputs

- Workflow: `.github/workflows/release.yml`
- Packaging: `.goreleaser.yaml`
- Homebrew update script: `.github/scripts/update-homebrew-formula.sh`

## Artifacts

Every release should publish:

- platform archives
- `checksums.txt`
- artifact attestations for archives and `checksums.txt`

Checksums are part of the security story for `cc-bash-proxy` because users are
trusting a binary that can rewrite commands before execution.

GitHub Artifact Attestations provide a signed provenance record for the release
artifacts. Consumers should be able to verify release provenance with:

```sh
gh attestation verify path/to/cc-bash-proxy_<tag>_<os>_<arch>.tar.gz -R tasuku43/cmdguard
```

## Release Invariants

The release pipeline should enforce as much as possible automatically.

Before a release is considered healthy, the system should guarantee:

1. CI-quality checks already passed before code merged to `main`
2. the release workflow completed successfully for the pushed tag
3. the GitHub Release contains:
   - macOS archives for amd64 and arm64
   - Linux archives for amd64 and arm64
   - `checksums.txt`
4. stable tags open a Homebrew formula PR when Homebrew secrets are configured
5. the Homebrew tap is treated as part of the trusted release path, not as an
   independent substitute for release checksums and attestations

## Minimal Human Verification

Manual checks should stay small and focus on what CI cannot prove by itself.

After a release is published:

1. download one artifact
2. verify its checksum against `checksums.txt`
3. run:
   - `cc-bash-proxy version --format json`
   - `cc-bash-proxy verify --format json`
4. run `gh attestation verify` against the downloaded artifact
5. confirm the reported VCS revision matches the intended release commit

## Security Notes

- `checksums.txt` is the minimum release integrity signal and should always be
  present.
- GitHub Artifact Attestations should be present for release archives and
  `checksums.txt`.
- A release is not considered fully verified until an artifact has been
  downloaded and checked outside the CI environment.

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
