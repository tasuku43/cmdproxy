# Releasing

## Overview

`cmdproxy` releases are tag-driven.

The intended pipeline is:

1. push a tag like `v0.1.0`
2. run CI-style preflight checks
3. build archives with GoReleaser
4. publish GitHub Release artifacts and `checksums.txt`
5. for stable tags without prerelease suffixes, optionally open a PR against
   `tasuku43/homebrew-cmdproxy`

## Release Inputs

- Workflow: `.github/workflows/release.yml`
- Packaging: `.goreleaser.yaml`
- Homebrew update script: `.github/scripts/update-homebrew-formula.sh`

## Artifacts

Every release should publish:

- platform archives
- `checksums.txt`

Checksums are part of the security story for `cmdproxy` because users are
trusting a binary that can rewrite commands before execution.

## Homebrew Tap

Stable tags can update the Homebrew tap automatically when these secrets are
configured:

- `HOMEBREW_APP_ID`
- `HOMEBREW_APP_KEY`

Without those secrets, the GitHub Release still completes and Homebrew update
steps are skipped.
