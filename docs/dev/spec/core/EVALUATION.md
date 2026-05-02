---
title: "Evaluation Model"
status: implemented
date: 2026-04-26
---

# Evaluation Model

`cc-bash-guard` is a permission-only policy proxy.

Evaluation flow:

1. receive the original command string
2. parse it into a `CommandPlan`
3. apply parser-backed normalization for evaluation only
4. evaluate permission buckets in order: `deny`, `ask`, `allow`
5. return `allow`, `ask`, or `deny`

The command string is not rewritten before execution. `Decision.Command` remains
the original command.

Evaluation-only normalization includes:

- shell `-c` wrapper inspection, including `bash`, `sh`, `zsh`, `dash`, `ksh`,
  `/bin/bash`, `env bash`, `command bash`, `exec sh`, `sudo bash`, `nohup`,
  `timeout`, and `busybox sh`
- `rtk proxy <command...>` wrapper inspection; an optional `--` immediately
  after `proxy` is treated as a separator
- basename command matching for absolute command paths
- `xargs` semantic inspection; policy must match `command.name: xargs`
  explicitly, because stdin-derived runtime arguments are dynamic
- command-specific semantic parsing, including AWS `--profile`,
  `--profile=value`, and `AWS_PROFILE`

Unsafe shell shapes, parse errors, redirects, background execution, subshells,
command substitution, process substitution, and unknown shapes fail closed and
must not broaden to `allow`.

Compound commands are evaluated through `CommandPlan.Commands`. If any inner
command is denied, the whole command is denied. If all inner commands are
allowed and the composition shape is allowable, the whole command may allow;
otherwise it falls back to `ask`. When multiple permission sources are active,
each inner command is evaluated through the merged source result before the
compound decision is aggregated.

Raw regex matching is always `patterns`. `patterns` match the original command
string and parsed command elements in `CommandPlan.Commands`, including shell
`-c` inner commands. Semantic parser support is reserved for higher-risk
command families such as `git`, `gh`, `aws`, `kubectl`, and `helmfile`.
Commands without semantic parsers should be covered with `patterns`.
