# Start Here

`cmdproxy` is a local CLI that sits in front of command execution and evaluates
command policy in two phases:

1. rewrite the command into its canonical form
2. evaluate permissions on the rewritten command

Its config file is now the source of truth for both rewrite behavior and shell
permission behavior.

## Quick Start

1. Create the user config

```sh
cmdproxy init
```

2. Edit `~/.config/cmdproxy/cmdproxy.yml`

3. Verify the config after each change

```sh
cmdproxy verify
cmdproxy doctor --format json
```

4. Spot-check individual commands

```sh
cmdproxy check aws --profile read-only-profile s3 ls
cmdproxy check bash -c 'git status'
```

5. Register `cmdproxy hook claude --rtk` in Claude Code

## Verifying an Installed Binary

If you install `cmdproxy` from a release artifact, verify it before relying on
it in your command path.

1. Check the downloaded file against `checksums.txt`
2. Verify the release provenance with GitHub attestation data
3. Inspect the binary metadata
4. Run `cmdproxy verify`

Example:

```sh
shasum -a 256 -c checksums.txt
gh attestation verify path/to/cmdproxy_<tag>_<os>_<arch>.tar.gz -R tasuku43/cmdguard
cmdproxy version --format json
cmdproxy verify --format json
```

## Claude Code

For Claude Code, add `cmdproxy hook claude --rtk` as a `PreToolUse` Bash hook.

```json
{
  "matcher": "Bash",
  "hooks": [
    { "type": "command", "command": "cmdproxy hook claude --rtk" }
  ]
}
```

`cmdproxy hook claude --rtk` evaluates `cmdproxy` policy first. It returns:

- `allow`: auto-allow immediately
- `ask`: let Claude prompt
- `deny`: block immediately

If `rtk` rewriting is enabled, that final rewrite is applied after `cmdproxy`
has already decided the permission outcome.

## Current Config Model

- top-level keys are `rewrite`, `permission`, `test`
- `rewrite` is an ordered array of rewrite steps
- each rewrite step may have an optional `match`
- `permission` is split into `deny`, `ask`, `allow`
- permission buckets are evaluated in the order `deny -> ask -> allow`
- rewrite steps and permission rules can each have local tests
- top-level `test.expect` is for end-to-end behavior

If you are contributing to the implementation, start from
`docs/dev/README.md` instead.
