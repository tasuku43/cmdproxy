# Permission Schema

Permission policy is grouped into `deny`, `ask`, and `allow` buckets.

```yaml
include:
  - ./policies/git.yml
  - ./tests/git.yml

permission:
  deny: []
  ask: []
  allow: []
```

## include

Top-level `include` lets you split permission rules and E2E tests across
multiple local YAML files.

```yaml
include:
  - ./policies/git.yml
  - ./policies/aws.yml
  - ./tests/git.yml
```

Rules:

- `include` is top-level only and must be a list of strings.
- Relative paths are resolved from the file that declares the include, not from
  the process working directory.
- Included files may include other files. Cycles fail verification and report
  the include chain.
- Only local files are supported. URLs, shell expansion, environment variable
  expansion, command substitution, and globbing are not supported.
- Empty entries, missing files, and paths that do not resolve to regular files
  are verification errors.
- Symlinks use the same file reading behavior as normal config loading: if the
  operating system resolves the path to a regular file, it is read as that file.

Merge order is deterministic: `include[0]`, `include[1]`, then the current file.
`permission.deny`, `permission.ask`, `permission.allow`, and top-level `test`
lists are concatenated in that order. No deep merge is performed.

`cc-bash-guard verify` resolves includes and writes one effective verified
artifact. The hook uses that artifact for permission evaluation. Included files
are part of the artifact fingerprint, so editing an included file makes the
artifact stale and requires another `cc-bash-guard verify`.

Each rule can use `command`, `env`, and `patterns`.
Each rule may also set `message`; when that rule determines `allow`, `ask`, or
`deny`, the message is returned as Claude Code's permission decision reason.

## command

Use `command` to match a command by name. Use `name` for one command, or
`name_in` for a non-semantic OR list of command names. For commands with
semantic parser support, use `name` plus `command.semantic`.

```yaml
permission:
  allow:
    - name: git read-only
      command:
        name: git
        semantic:
          verb_in:
            - status
            - diff
            - log
            - show
```

The semantic schema is selected by `command.name`. Fields live directly under
`command.semantic`; no extra tool-name nesting is required.

`name` and `name_in` are mutually exclusive. `name_in` cannot be combined with
`semantic`; it may be combined with `env`.

`shape_flags_any`, `shape_flags_all`, and `shape_flags_none` can be placed under
`command` to match parser-derived shell shape flags for the same command
segment. These flags are quote-aware: `grep '2>&1' file` contains a literal
argument, not a redirection. Redirection flags include:

- `redirect_stream_merge` for descriptor merges such as `2>&1` and `1>&2`
- `redirect_to_devnull` for output redirected to `/dev/null`
- `redirect_file_write` for `> file`
- `redirect_append_file` for `>> file`
- `redirect_stdin_from_file` for `< file`
- `redirect_heredoc` for `<<`, `<<-`, and `<<<`

```yaml
permission:
  deny:
    - name: block stream merge redirects
      command:
        name_in:
          - ls
          - git
        shape_flags_any:
          - redirect_stream_merge
  allow:
    - name: read-only shell basics
      command:
        name_in:
          - ls
          - grep
```

With this policy, `ls 2>&1` is denied, `ls > /dev/null` may be allowed by the
base `ls` rule, and `ls > /tmp/out` still asks because file writes remain
fail-closed unless explicitly handled.

```yaml
permission:
  allow:
    - name: read-only shell basics
      command:
        name_in:
          - ls
          - pwd
          - head
          - tail
          - wc
          - grep
          - rg
```

Inspect supported commands with:

```sh
cc-bash-guard help semantic
cc-bash-guard semantic-schema --format json
```

See [`docs/user/SEMANTIC_COVERAGE.md`](SEMANTIC_COVERAGE.md) for the semantic
parser coverage matrix, field reference, examples, and limitations.

## env

Use `env` to require or reject environment variables for the invocation.

```yaml
permission:
  allow:
    - name: AWS identity
      command:
        name: aws
        semantic:
          service: sts
          operation: get-caller-identity
      env:
        requires:
          - AWS_PROFILE
```

`env.requires` means the variable must be present. `env.missing` means the
variable must not be present.

## patterns

Use `patterns` for raw regular expression matching against the original command
string and parsed command elements. Shell `-c` wrappers are unwrapped for
evaluation, so a pattern such as `^aws(\s|$)` also matches
`bash -c 'aws s3 ls'`. This is the fallback for raw-string checks or commands
that cannot be expressed with `command.name_in`.

Prefer `command` plus `command.semantic` when a command is listed by
`cc-bash-guard help semantic`. Pattern rules are best used for deliberate
raw-string checks.

```yaml
permission:
  allow:
    - name: read-only shell basics
      command:
        name_in:
          - ls
          - pwd
          - cat
```

Safer pattern rules are narrow and test-backed:

- anchor with `^` and `$`, or use explicit token boundaries such as `(\\s|$)`
- allow only intended subcommands, not an entire tool namespace
- avoid broad allow patterns such as `.*`, `^aws\\s+`, `^terraform\\s+`, or
  `^npm\\s+`
- account for shell metacharacters such as `;`, `&`, `|`, backticks, `$()`,
  redirects, subshells, and process substitution
- remember that allowed commands can invoke scripts, plugins, or subcommands
  that are not deeply inspected, such as `npm run lint` or `make test`

`cc-bash-guard verify` fails broad `permission.allow[*].patterns` when a regex
is unanchored, allows a whole command namespace, or uses broad wildcards that
can match shell metacharacters. Fix these rules with `command.name_in`,
`command.semantic` for supported commands, or a narrower anchored regex that
excludes shell metacharacters.

When you use a semantic allow rule for a supported command, do not add another
broader allow rule for the same command in the same effective policy. For
example, a semantic `git status` allow must not be paired with `command.name:
git`, `command.name_in` containing `git`, a broad raw pattern such as
`^git\\s+.*$`, or an env-only allow rule that can allow any command when the
environment matches. `cc-bash-guard verify` fails these structural conflicts by
default because the broader allow makes the semantic allow misleading. Move
whole command namespace handling to `permission.ask`, keep `permission.allow`
semantic and narrow, and add explicit `permission.deny` rules for dangerous
operations where appropriate.

Example fallback for a command that needs raw-string subcommand checks:

```yaml
permission:
  allow:
    - name: terraform read-only fallback
      patterns:
        - "^terraform\\s+(plan|show)(\\s|$)[^;&|`$()]*$"

test:
  - in: "terraform plan -out=tfplan"
    decision: allow
  - in: "terraform apply -auto-approve"
    decision: ask
  - in: "terraform plan; terraform apply -auto-approve"
    decision: ask
```

## Valid Combinations

Rules can combine fields as follows:

- `command`
- `command` plus `env`
- `command` plus `semantic`
- `command` plus `semantic` plus `env`
- `patterns`
- `patterns` plus `env`
- `env`

Use semantic matching when a command is listed by `cc-bash-guard help semantic`.
Use `patterns` for commands without semantic support or when raw regex matching
is the intended policy.

## Evaluation Order

`cc-bash-guard` policy and Claude settings permissions are permission sources.
Each source returns `deny`, `ask`, `allow`, or `abstain`.

Decision precedence is:

```text
deny > ask > allow > abstain
```

`abstain` means no matching rule. The final fallback is `ask` only when all
permission sources abstain.

## Command Evaluation

`cc-bash-guard` policy evaluation does not rewrite commands. It only returns a
permission decision: `allow`, `ask`, or `deny`.

Parser-backed normalization is evaluation-only:

- shell `-c` wrappers can be inspected as inner commands
- absolute command paths can match by basename
- command-specific parsers can expose semantic fields such as AWS profile,
  service, and operation

The command returned to Claude Code is not changed by permission evaluation.
The default hook does not emit `updatedInput`; only `hook --rtk` may emit it as
a bridge to external RTK.
