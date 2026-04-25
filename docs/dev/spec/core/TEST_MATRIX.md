---
title: "Security Test Matrix"
status: implemented
date: 2026-04-25
---

# Security Test Matrix

## 1. Scope

`cc-bash-proxy` tests are security boundary tests, not only feature tests. The
regression matrix must keep the important allow/ask/deny boundaries stable
across refactors.

The matrix lives in table-driven Go tests and covers:

- compound command composition
- shell features that fail closed
- parser-specific and generic parser behavior
- raw and structured permission rules
- Claude permission merge modes
- rewrite and permission interaction

## 2. Required Assertions

Every security matrix case must assert:

- final outcome: `allow`, `ask`, or `deny`
- trace presence and the security-relevant trace step
- shell shape: `simple`, `compound`, or `unknown`
- shape flags when the boundary depends on shell structure

Trace assertions must include the security-relevant event, such as:

- `fail_closed`
- `composition`
- `composition.command`
- rewrite primitive names
- `claude_permission_merge_mode`
- `claude_settings`

## 3. Invariants

The matrix must preserve these invariants:

- `deny` must not become `allow`
- unsafe shell shapes must not become automatic `allow`
- raw `allow` must not become broader without explicit opt-in and tests
- parser removal or generic fallback must not widen a semantic rule to `allow`
- Claude `migration_compat`, `strict`, and `cc_bash_proxy_authoritative` must
  have explicit, tested differences
- rewrite steps must not hide the final shell shape used for permission
  evaluation

## 4. Required Categories

The security matrix must include at least these categories.

### Compound

- `&&`
- `||`
- pipeline
- sequence
- nested compound expressions

Supported list and pipeline shapes may allow only when every extracted command
is individually allowed. Nested or mixed unsafe shapes must ask unless an
extracted command is denied.

### Shell Features

- subshell
- command substitution
- process substitution
- redirection

These features are unsafe for automatic allow. Deny rules still apply to
extracted commands when the parser can find them.

### Parser

- semantic parser, including the Git parser
- generic fallback
- unknown command

When a deny or ask rule requires semantic fields and the semantic parser is not
available, evaluation must ask instead of falling through to a broader allow.

### Permission

- raw `deny`
- raw `ask`
- raw `allow`
- structured match

Raw `deny` and `ask` keep their priority. Raw `allow` must remain narrow and
must not authorize unsafe shell syntax unless the rule explicitly opts into the
supported raw allow path and the command remains safe for evaluation.

### Merge Mode

- `strict`
- `migration_compat`
- `cc_bash_proxy_authoritative`

The merge mode matrix must show where the modes differ. In particular, only
`migration_compat` may upgrade a `cc-bash-proxy` `ask` to `allow` from Claude
settings, and no mode may upgrade an existing `deny` to `allow`. The matrix
must also cover `cc-bash-proxy` `abstain`: in `strict`, Claude `allow`, `ask`,
and `deny` are honored when `cc-bash-proxy` abstains, while both sides
abstaining falls back to final `ask`. E2E hook tests must assert trace
distinguishes `no_match` from final fallback `default` ask.

### Rewrite

- shell unwrap
- environment or flag movement
- rewrite chains

The matrix must assert both the final rewritten command and the final decision.
Successful rewrite trace entries must include before/after shape and safety.
