# Troubleshooting

For the full security boundary, known limitations, fail-closed cases, and RTK
integration boundary, see `docs/user/THREAT_MODEL.md`.

## Verified Artifact Missing Or Stale

Run:

```sh
cc-bash-guard verify
```

The hook asks with a warning when the verified artifact is missing or stale.
Run `cc-bash-guard verify`, then retry the Claude Code command.

The hook prints Claude Code `PreToolUse` JSON with
`hookSpecificOutput.permissionDecision: "ask"`, a
`permissionDecisionReason`, a warning `systemMessage`, and
`hookSpecificOutput.additionalContext` explaining the artifact problem. The
process still exits `0` after producing that JSON so Claude Code will parse the
structured decision.

If your config uses `include`, every included YAML file is part of the verified
artifact. Editing an included policy or test file makes the artifact stale; run
`cc-bash-guard verify` again.

## Reading Verify Output

Human output starts with a compact summary:

```text
PASS verify
  config files: 4
  permission rules: 28
  tests: 42
  artifact: updated
```

On failure, `verify` prints each failure with source-aware context. For an E2E
test failure, check:

- `source`: YAML file and `test[index]`
- `input`: command under test
- `expected` and `actual`: final permission decisions
- `decisions`: cc-bash-guard policy, Claude settings, and final merged decision
- `matched rule`: YAML file, bucket, index, name, and message when available

Warnings are shown separately from failures. Duplicate rule names and broad
env-only allow rules are warnings; they do not fail verification by themselves.
Broad `permission.allow[*].patterns` are failures by default when a regex is
unanchored, allows a whole command namespace such as `^aws`, or uses wildcards
that can match shell metacharacters too broadly.

Use JSON output for tooling:

```sh
cc-bash-guard verify --format json
```

The JSON payload includes `ok`, `summary`, `failures`, and `warnings`. It never
contains ANSI color codes.

Human output uses color only when appropriate. The default is `--color auto`,
which enables color on terminals and disables it for pipes. `NO_COLOR` and
`TERM=dumb` disable color. You can also use:

```sh
cc-bash-guard verify --color always
cc-bash-guard verify --color never
```

To collect every failure instead of stopping after the first E2E failure, run:

```sh
cc-bash-guard verify --all-failures
```

## Include Errors

Common include failures:

- the include entry is empty
- the path is a URL instead of a local file path
- the file is missing or is not a regular file
- a nested include forms a cycle

Relative include paths are resolved from the file that declares the include. For
example, if `policies/base.yml` includes `./git.yml`, that path resolves to
`policies/git.yml`.

## Unsupported Semantic Field

Inspect the registered fields for the command:

```sh
cc-bash-guard help semantic git
cc-bash-guard semantic-schema git --format json
```

If verify reports an unknown key, use the current permission shape:
`command`, `env`, and `patterns`.

Verify reports the invalid semantic field, command name, source YAML location,
supported fields for that command, and a help hint. For example:

```sh
cc-bash-guard help semantic git
```

## Command Without Semantic Support

Semantic matching only works for commands listed by:

```sh
cc-bash-guard help semantic
```

Use `patterns` for raw regex rules when a command has no semantic schema.
Prefer semantic rules when they are available.

## Final Result Is ask

`abstain` means no matching rule. If all permission sources abstain,
`cc-bash-guard` falls back to `ask`.

Add an explicit `allow`, `ask`, or `deny` rule when you want a stable decision.

To see why a specific command reached `allow`, `ask`, or `deny`, run:

```sh
cc-bash-guard explain "unknown-tool foo"
```

`explain` does not execute the command. It shows parser output, semantic fields,
the matched cc-bash-guard rule and source YAML file when available, the Claude
settings decision, and the final merged reason. Use `--format json` when another
tool needs to consume the diagnostic result.

## Regex Pattern Not Matching

`patterns` match the original command string and parsed command elements,
including shell `-c` inner commands. Anchor patterns carefully:

```yaml
permission:
  allow:
    - name: pwd
      patterns:
        - "^pwd$"
```

In YAML double-quoted strings, escape backslashes. Single-quoted YAML strings
can be easier for complex regular expressions.

## Broad Pattern Allow Rules

Avoid broad allow patterns such as `.*`, `^aws\\s+`, `^terraform\\s+`, or
`^npm\\s+`. They can allow destructive subcommands, and allowed commands can
invoke scripts, plugins, or subcommands that cc-bash-guard does not deeply
inspect.

Use `cc-bash-guard verify` with top-level tests that cover allowed examples and
near misses:

```yaml
permission:
  allow:
    - name: terraform read-only fallback
      patterns:
        - "^terraform\\s+(plan|show)(\\s|$)[^;&|`$()]*$"

test:
  allow:
    - "terraform plan -out=tfplan"
  ask:
    - "terraform apply -auto-approve"
    - "terraform plan; terraform apply -auto-approve"
```

## AWS Profile Style

Prefer this style in project guidance:

```sh
AWS_PROFILE=myprof aws eks list-clusters
```

The AWS parser can still evaluate profile, service, and operation semantically.
See `docs/user/AWS_GUIDELINES.md`.

## Command Not Being Rewritten

`cc-bash-guard` policy evaluation and the default hook do not rewrite commands.
Parser-backed normalization is evaluation-only. It only returns `allow`, `ask`,
or `deny`.
If you use RTK rewriting, run `cc-bash-guard hook --rtk` as the single Bash hook
so permission evaluation runs before external `rtk rewrite`. RTK is not called
for `deny`.
