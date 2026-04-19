# cmdproxy

Policy proxy for CLI invocations used by AI agents and shell hooks.

`cmdproxy` sits in front of command execution and preserves permission intent by
normalizing command shape before the caller's own allow / ask / deny layer runs.

## Value Proposition

`cmdproxy` is not primarily a dangerous-command blocker.

It exists to make approved CLIs run in approved ways.

Typical examples:

- rewrite `aws --profile prod s3 ls` into `AWS_PROFILE=prod aws s3 ls`
- rewrite `bash -c 'git status'` into `git status`
- rewrite `bash -c 'git -C repo status'`, then re-evaluate `git -C repo status`
- reject invocation shapes that must not pass through unchanged

This makes downstream permission systems more predictable, because they evaluate
canonical command shapes instead of wrapper-heavy or drifted invocations.

## Current Status

The repository is transitioning from the earlier `cmdguard` deny-only model to a
directive-driven `cmdproxy` model.

Today, the codebase already supports:

- `match` and `pattern` based rule matching
- `reject` directives
- `rewrite.unwrap_shell_dash_c`
- `rewrite.move_flag_to_env`
- `rewrite.move_env_to_flag`
- `rewrite.unwrap_wrapper`
- `rewrite.continue`
- ordered first-match evaluation
- `cmdproxy test`, `cmdproxy check`, `cmdproxy doctor`, and `cmdproxy hook claude`

The current on-disk config format uses directive-local tests under
`rewrite.test` or `reject.test`.

## Typical Workflow

1. Initialize user config

```sh
cmdproxy init
```

2. Edit `~/.config/cmdproxy/cmdproxy.yml`

3. Validate rules

```sh
cmdproxy test
cmdproxy check aws --profile read-only-profile s3 ls
cmdproxy doctor --format json
```

4. Register `cmdproxy hook claude` in your hook runner

## Claude Code Setup

`cmdproxy` is intended to run before Claude Code permissions are evaluated.

Add a `PreToolUse` Bash hook that calls `cmdproxy hook claude`.

```json
{
  "matcher": "Bash",
  "hooks": [
    { "type": "command", "command": "cmdproxy hook claude" }
  ]
}
```

If you also use another Bash hook such as `rtk hook claude`, place
`cmdproxy hook claude` first so canonicalization and rejection happen before later
hook-side processing.

## Current Config Shape

The currently implemented config file looks like this:

```yaml
rules:
  - id: aws-profile-to-env
    match:
      command: aws
      args_contains:
        - "--profile"
    rewrite:
      move_flag_to_env:
        flag: "--profile"
        env: "AWS_PROFILE"
      test:
        expect:
          - in: "aws --profile read-only-profile s3 ls"
            out: "AWS_PROFILE=read-only-profile aws s3 ls"
        pass:
          - "AWS_PROFILE=read-only-profile aws s3 ls"

  - id: unwrap-safe-wrappers
    pattern: '^\s*(env|command|exec)\b'
    rewrite:
      unwrap_wrapper:
        wrappers:
          - "env"
          - "command"
          - "exec"
      test:
        expect:
          - in: "env AWS_PROFILE=dev command exec aws s3 ls"
            out: "AWS_PROFILE=dev aws s3 ls"
        pass:
          - "AWS_PROFILE=dev aws s3 ls"

  - id: no-shell-dash-c
    match:
      command_in:
        - bash
        - sh
        - zsh
        - dash
        - ksh
      args_contains:
        - "-c"
    reject:
      message: "shell -c must not pass through unchanged. Run the command directly instead."
      test:
        expect:
          - "bash -c 'git status && git diff'"
        pass:
          - "git status"
```

## Design Direction

The long-term model is directive-driven:

- `rewrite`: canonicalize invocation shape
- `reject`: stop invocation shapes that must not pass through unchanged
- implicit `pass`: forward unmatched invocations unchanged

Caller input stays intentionally simple: a raw command string in, structured
policy evaluation inside `cmdproxy`.

## Documentation

- Product concept: [docs/concepts/product-concept.md](docs/concepts/product-concept.md)
- Developer spec: [docs/dev/spec/README.md](docs/dev/spec/README.md)
- User docs: [docs/user/README.md](docs/user/README.md)

## License

MIT
