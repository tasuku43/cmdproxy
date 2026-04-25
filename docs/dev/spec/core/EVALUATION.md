---
title: "Evaluation Model"
status: implemented
date: 2026-04-25
---

# Evaluation Model

## 1. Scope

This document defines the current evaluation model for `cc-bash-proxy`.

`cc-bash-proxy` evaluates a requested CLI invocation in two phases:

1. rewrite the command through an ordered rewrite pipeline
2. evaluate permissions on the rewritten command

## 2. Caller Contract

`cc-bash-proxy` keeps caller input intentionally simple.

- the caller provides a requested command invocation
- the primary external form is still a raw command string for `exec`
- internal parsing and normalization complexity stays inside `cc-bash-proxy`

The caller should not need to understand the internal matcher model.

## 3. Internal Normalization

Inside `cc-bash-proxy`, the raw command string is normalized into a parsed
invocation model that may include:

- environment assignments
- executable basename
- argument vector
- subcommand
- a limited set of launcher-style wrappers
- shell AST classification for deciding whether structured `allow` matching is
  safe

Structured `allow` rules only auto-allow commands that are classified as safe
for evaluation. Safe evaluation requires no parser diagnostics, a supported
shell shape, and an AST-safe simple command for each command that would be
allowed. Syntax parse errors, diagnostics, unknown shapes, redirects,
subshells, background execution, command substitution, process substitution,
and unsafe `bash -c` payloads fail closed to `ask`. Pattern-based `allow` rules
follow the same gate by default. `allow_unsafe_shell: true` can opt into
full-command raw allow only after the command passes this fail-closed
evaluation safety gate.

## 4. Configuration Source

The effective policy is built from user-wide config first and project-local
config second:

- `$XDG_CONFIG_HOME/cc-bash-proxy/cc-bash-proxy.yml`
- `~/.config/cc-bash-proxy/cc-bash-proxy.yml` when `XDG_CONFIG_HOME` is not set
- `<project-root>/.cc-bash-proxy/cc-bash-proxy.yml`
- `<project-root>/.cc-bash-proxy/cc-bash-proxy.yaml`

Rules append in that source order. For permission rules, bucket priority still
wins first (`deny -> ask -> allow`), then source order decides the first match
inside the winning bucket. Trace entries include source metadata for matched
rewrite and permission rules.

## 5. Rewrite Phase

Rewrite evaluation order is fixed and deterministic.

1. Preserve rewrite step order from the file
2. For each rewrite step:
   - if the step has `match`, require it to match
   - attempt the single configured rewrite primitive
3. If the rewrite succeeds:
   - parse the rewritten command into a fresh `CommandPlan`
   - record a rewrite trace step with before/after shell shape and safety
   - if `continue: true`, continue evaluating later rewrite steps against the rewritten command
   - otherwise stop the rewrite phase early

If a rewrite step is considered but cannot safely rewrite the invocation, it is
a no-op and evaluation continues.

Rewrite is policy-preserving canonicalization, not arbitrary transformation.
Each successful step must preserve the evaluation safety boundary. A rewrite
must not convert a safe command plan into an unsafe command plan, and must not
change a `simple` shell shape into `compound` or `unknown`. If a rewrite
violates this invariant, the rewritten command remains the final command under
evaluation, the rewrite trace records `effect: fail_closed`, and permission
evaluation treats the command as unsafe so automatic `allow` is unavailable.
This rule also applies to every intermediate step in a `continue: true` rewrite
chain.

Examples:

- move a flag value into a sanctioned environment variable
- unwrap `bash -c 'single command'` into the direct command form
- remove a wrapper that obscures the effective executable
- normalize `/bin/ls` into `ls`

## 6. Permission Phase

After the rewrite phase finishes, `cc-bash-proxy` evaluates permission rules
only against the resulting command. Permission rules do not evaluate the
original command or intermediate rewrite-chain states.

The full effective order is fixed:

1. run the rewrite pipeline
2. evaluate raw/full-command `deny` rules against the rewritten command
3. evaluate extracted-command composition for `deny`/explicit `ask` when the
   rewritten command is unsafe for automatic allow
4. evaluate raw/full-command `ask` rules against the rewritten command
5. stop at `ask` when the rewritten command is unsafe for automatic allow
6. evaluate raw/full-command `allow` rules against the rewritten command
7. evaluate `CommandPlan` composition for non-simple shell expressions
8. return the default outcome, `ask`

Raw/full-command rules include both structured `match` selectors and raw
`pattern` / `patterns` selectors evaluated against the whole rewritten command
string. The bucket order is therefore:

1. `deny`
2. `ask`
3. `allow`

Within each bucket, source order is preserved.

The first matching permission rule in the current bucket wins. If a bucket does
not match, evaluation moves to the next bucket.

For `allow` rules, the raw/full-command stage is gated by fail-closed
evaluation safety. A normal `allow` rule may match only commands classified as
structured-safe for automatic allow. Supported compound lists and pipelines may
be allowed only through composition, where every extracted command must be
individually safe and allowed. Syntax parse errors, diagnostics, redirects,
subshells, background execution, unknown shell shapes, command substitution,
process substitution, and unsafe AST forms never reach allow matching. An
`allow` rule with
`allow_unsafe_shell: true` opts into raw full-command allow for supported
safe-for-evaluation shapes, but it cannot override parse errors, diagnostics,
or unsupported shell shapes.

If nothing matches, the default outcome is `ask`.

This yields three runtime outcomes:

- `deny`: the command is blocked
- `ask`: the user should be prompted
- `allow`: the command may proceed automatically

Regex selectors are compiled when the policy is loaded into its runtime form.
Runtime evaluation uses the prepared policy model rather than compiling regexes
for each hook invocation.

## 7. Hook Behavior

`cc-bash-proxy hook` maps the final permission outcome into Claude hook JSON:

- `allow`: emit `permissionDecision: "allow"`
- `ask`: omit `permissionDecision` so Claude prompts
- `deny`: emit `permissionDecision: "deny"`

The internal permission verdict also supports `abstain`, meaning no
`cc-bash-proxy` permission rule matched. `abstain` is a merge input, not a hook
output. The final fallback to `ask` is applied only after the Claude settings
merge, and only when both `cc-bash-proxy` and Claude settings abstain.

If `--rtk` is enabled, the `rtk` rewrite runs only after `cc-bash-proxy` has
already decided the permission outcome.

Claude settings merge behavior is controlled by `claude_permission_merge_mode`:

- `strict` is the default and applies explicit `deny > ask > allow`; Claude
  `allow` does not upgrade an explicit `cc-bash-proxy` `ask`, but it is honored
  when `cc-bash-proxy` abstains
- `migration_compat` is explicit opt-in for legacy coexistence behavior,
  including Claude `allow` upgrading `cc-bash-proxy` `ask`
- `cc_bash_proxy_authoritative` ignores Claude `allow` and `ask`, but still
  honors Claude `deny`; if `cc-bash-proxy` also abstains, the final fallback is
  `ask`

The hook trace includes the effective Claude permission merge mode for every
Claude permission bridge evaluation. Trace output records `no_match` for
`cc-bash-proxy` abstain and `default` for final fallback ask, so explicit ask
rules and fallback ask are distinguishable.

## 8. Testing Model

The schema has three testing layers:

- rewrite-step-local tests
- permission-rule-local tests
- top-level end-to-end tests

Top-level E2E tests assert:

- the input command
- optionally the rewritten command
- the final decision

Security-sensitive behavior is also covered by the implemented security test
matrix in `core/TEST_MATRIX.md`. Matrix cases assert the final outcome, trace,
and shell shape for compound commands, unsafe shell features, parser fallback,
permission priority, merge mode differences, and rewrite interaction.

## 9. Consequences Of This Model

Because the contract is pipeline-based:

- rewrite order is meaningful
- permission order is meaningful within each effect bucket
- `deny -> ask -> allow` is part of the public behavior
- tests can deterministically assert both rewrite shape and final permission
  outcome

## 10. Compound Command Composition

Permission evaluation uses `CommandPlan.Commands` and `CommandPlan.Shape` for
compound shell expressions after the raw/full-command permission stages above
have not produced a decision. `CommandPlan.Shape.Kind` is a primary
classification tag with only `simple`, `compound`, and `unknown` as current
contract values. Detailed structure is stored as additive flags:

- `HasPipeline`
- `HasConditional`
- `HasSequence`
- `HasBackground`
- `HasRedirection`
- `HasSubshell`
- `HasCommandSubstitution`
- `HasProcessSubstitution`

Evaluation must not infer safety from `Kind` alone. It must consult the flags
so mixed structures such as pipeline plus subshell plus redirection remain
visible to fail-closed logic. Trace entries for `fail_closed` and `composition`
include both `shape` and `shape_flags`.

Raw `deny` and raw `ask` pattern rules can block or require confirmation for a
full compound command even when each extracted command would otherwise be
individually allowed. Unsafe commands record a `fail_closed` trace step before
permission matching continues. Deny rules still apply to unsafe commands,
including extracted commands when available. Raw `allow` pattern rules do not
bypass shell safety by default; with `allow_unsafe_shell: true`, they can allow
only commands that still pass the fail-closed evaluation safety gate.

For `simple`, the existing structured allow behavior applies.

For supported `compound` shapes with only list-style flags (`HasConditional`,
`HasSequence`) or only `HasPipeline`, each extracted command is evaluated
independently:

- allow if every extracted command is individually `allow`
- deny if any extracted command is individually `deny`
- otherwise ask

The pipeline policy is intentionally Claude-Code-compatible: `git status | sh`
is allowed only when both `git status` and `sh` are individually allowed. A rule
for the left side of a pipeline does not authorize the right side.

For `background`, `redirect`, `subshell`, command substitution, process
substitution, pipeline combined with additional shell features, and `unknown`,
allow rules are not evaluated. The default remains ask unless an extracted
command is denied. These shapes keep their shell composition metadata on
`CommandPlan.Shape`; individual `Command` objects do not store operator
metadata.

Process substitution is a `compound` shell shape with
`HasProcessSubstitution` set, and its inner statement list is still visited.
Commands inside `<(...)` and `>(...)` are emitted as `composition.command` trace
entries and are evaluated in `deny -> ask -> allow` order with the other
extracted commands. For example, `cat <(rm -rf /tmp/x)` is denied when
`rm -rf /tmp/x` matches a deny rule, and `echo >(sh)` is denied when `sh`
matches a deny rule. If no extracted command is denied, the whole
process-substitution expression still asks by default.
