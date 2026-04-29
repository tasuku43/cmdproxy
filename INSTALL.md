# Install cc-bash-guard

Use Homebrew or mise for most installs. Manual GitHub Releases and Go builds
are available for environments that need explicit artifact handling or a local
Go toolchain build.

`cc-bash-guard` is part of your Claude Code shell execution trust boundary.
The installed binary decides whether Bash commands are allowed, confirmed, or
denied, so verify the delivery path you choose before relying on it.

## Release State and Trust Signals

Available today:

- Public GitHub Releases exist for this repository.
- Current release assets include macOS and Linux `tar.gz` archives for `arm64`
  and `x64`, plus `checksums.txt`.
- The release workflow is configured to generate GitHub artifact attestations
  for the archives listed in `checksums.txt` and for `checksums.txt` itself.

Expected for tagged releases:

- Tags matching `v*` run the release workflow.
- GoReleaser builds platform archives and publishes `checksums.txt`.
- Stable tags can open a Homebrew formula update PR only when the Homebrew
  GitHub App secrets are configured.
- The Homebrew formula pins SHA-256 values for the GitHub Release archives it
  references, but the tap is still part of the trusted delivery path.

Recommended user verification:

- Verify the archive against the release `checksums.txt`.
- For releases that include GitHub artifact attestations, verify the downloaded
  archive and `checksums.txt` with `gh attestation verify`.
- Inspect the installed binary with `cc-bash-guard version --format json`.
- Run `cc-bash-guard verify --format json` against your effective policy.
- Treat checksums and attestations as integrity and provenance signals, not as
  proof that the source code or runtime behavior is safe.

## Homebrew

```sh
brew tap tasuku43/cc-bash-guard
brew install cc-bash-guard
cc-bash-guard init --profile git-safe
cc-bash-guard verify
```

The formula in
[`tasuku43/homebrew-cc-bash-guard`](https://github.com/tasuku43/homebrew-cc-bash-guard)
pins SHA-256 checksums against GitHub Releases archives. Stable release tags
can open formula update PRs automatically only when the release workflow has
the Homebrew GitHub App secrets configured. Treat the tap and formula review as
part of the trusted delivery path; Homebrew is not more trustworthy than the
release artifacts it points to.

## mise

```sh
mise use -g github:tasuku43/cc-bash-guard@latest
cc-bash-guard init --profile git-safe
cc-bash-guard verify
```

## GitHub Releases

GitHub Releases publish prebuilt `tar.gz` archives for macOS and Linux on
arm64 and x64.

```sh
TAG=<tag>       # replace with the release tag you want
OS=macos        # macos or linux
ARCH=arm64      # arm64 or x64
ARCHIVE="cc-bash-guard_${TAG}_${OS}_${ARCH}.tar.gz"

curl -LO "https://github.com/tasuku43/cc-bash-guard/releases/download/${TAG}/${ARCHIVE}"
curl -LO "https://github.com/tasuku43/cc-bash-guard/releases/download/${TAG}/checksums.txt"
```

## Verify What You Install

Verify the SHA-256 checksum before installing:

```sh
# macOS
grep "  ${ARCHIVE}$" checksums.txt | shasum -a 256 -c -

# Linux
grep "  ${ARCHIVE}$" checksums.txt | sha256sum -c -
```

For releases that include GitHub artifact attestations, verify the downloaded
archive and checksum file:

```sh
gh attestation verify "$ARCHIVE" -R tasuku43/cc-bash-guard
gh attestation verify checksums.txt -R tasuku43/cc-bash-guard
```

Put the binary on `PATH`:

```sh
mkdir -p "$HOME/.local/bin"
tar -xzf "$ARCHIVE" cc-bash-guard
install -m 0755 cc-bash-guard "$HOME/.local/bin/cc-bash-guard"
cc-bash-guard init --profile git-safe
cc-bash-guard verify
```

Inspect the installed binary and policy verification output:

```sh
cc-bash-guard version --format json
cc-bash-guard verify --format json
```

If `version --format json` includes `vcs_revision`, confirm that it matches the
release tag or commit you intended to install. Missing VCS metadata should be
treated as a reason to inspect the build path more carefully, not as proof of a
bad build.

Release verification checklist:

1. download the platform archive
2. download `checksums.txt`
3. verify the archive SHA-256 against `checksums.txt`
4. verify GitHub artifact attestations when present
5. install the binary and run `cc-bash-guard version --format json`
6. run `cc-bash-guard verify --format json`
7. confirm the reported VCS revision or tag when the version output exposes it

## Build From Source

For Go toolchain users:

```sh
go install github.com/tasuku43/cc-bash-guard/cmd/cc-bash-guard@latest
cc-bash-guard init --profile git-safe
cc-bash-guard verify
```

Use `cc-bash-guard init --list-profiles` to see the available starter profiles.

The module requires Go 1.25 or newer. Make sure your Go install directory is on
`PATH`; by default that is usually `$(go env GOPATH)/bin`.

## Upgrade

Homebrew:

```sh
brew update
brew upgrade cc-bash-guard
cc-bash-guard verify
```

mise:

```sh
mise use -g github:tasuku43/cc-bash-guard@latest
cc-bash-guard verify
```

Go-installed binary:

```sh
go install github.com/tasuku43/cc-bash-guard/cmd/cc-bash-guard@latest
cc-bash-guard verify
```

For GitHub Releases, download the newer archive, verify it against that
release's `checksums.txt`, replace the binary on `PATH`, then run:

```sh
cc-bash-guard version --format json
cc-bash-guard verify --format json
```

Verified artifacts include an evaluation semantics version and the resolved
policy inputs. Regenerate them with `cc-bash-guard verify` after upgrading.
