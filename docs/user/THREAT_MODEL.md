# Threat Model

## Purpose

`cc-bash-guard` is a local permission guard for Claude Code Bash hook
execution. It evaluates a Bash command string against verified permission
policy and returns `allow`, `ask`, or `deny`.

This document describes what the tool is intended to protect, where enforcement
happens, what must be trusted, and the limitation classes that policy authors
must account for.

## Assets Protected

`cc-bash-guard` helps protect local command execution paths that can affect:

- local shell execution through Claude Code Bash tool calls
- Git working trees and Git remotes
- GitHub operations performed through `gh`
- AWS profiles, accounts, and regions
- Kubernetes contexts, namespaces, and resources
- Helmfile and Argo CD operations
- local files indirectly reachable through otherwise allowed commands

Protection is policy-based. The tool can block, ask for confirmation, or allow
commands according to configured rules and Claude settings permissions. It does
not isolate the process after a command is allowed.

## Enforcement Points

The main enforcement point is the Claude Code `PreToolUse` Bash hook:

1. Claude Code sends hook input containing the Bash command.
2. `cc-bash-guard hook` validates the hook input.
3. The hook loads the verified effective policy artifact.
4. The command is parsed into a `CommandPlan`.
5. Permission policy is evaluated in `deny`, `ask`, then `allow` order.
6. The cc-bash-guard decision is merged with Claude settings permissions using
   `deny > ask > allow > abstain`.
7. The hook returns Claude Code JSON containing `permissionDecision`.

`abstain` means no matching rule. The final fallback is `ask` only when all
permission sources abstain.

`cc-bash-guard explain` is a diagnostic enforcement preview. It does not
execute the command. `cc-bash-guard verify` validates configuration, tests, and
verified artifacts before the hook relies on them.

## Trust Assumptions

`cc-bash-guard` assumes:

- the installed binary is the intended binary for the user's environment
- the configured Claude Code hook invokes the intended binary and flags
- the user or project policy files are trusted enough to decide local
  `allow`, `ask`, and `deny` behavior
- the verified artifact was produced by `cc-bash-guard verify` from reviewed
  policy and tool settings
- Claude Code honors the structured `PreToolUse` hook response
- downstream tools such as `git`, `gh`, `aws`, `kubectl`, `helmfile`,
  `argocd`, shell interpreters, plugins, and script runners behave according
  to their own implementations and credentials
- local environment, current working directory, config files, credentials, and
  external services may affect what an allowed command actually does

## Non-Goals

`cc-bash-guard` is not:

- an OS sandbox
- a filesystem sandbox
- a network sandbox
- a container runtime
- a malware detector
- a full interpreter of arbitrary scripts invoked by allowed commands

It does not prevent an allowed process from using its normal filesystem,
network, credential, plugin, or subprocess capabilities. It does not deeply
inspect script bodies invoked by commands such as `npm run`, `make`, or
`sh script.sh`.

## Known Bypass Or Limitation Classes

Policy authors should account for these limitation classes:

- overly broad allow regexes can allow more commands than intended
- script runners such as `npm run`, `make`, and `sh script.sh` can execute
  script bodies that are not deeply inspected
- aliases and shell functions that are not visible in the command string are
  not resolved by cc-bash-guard
- shell indirection and dynamic evaluation can hide behavior from static
  command parsing
- plugins and subcommands invoked by allowed tools can perform additional work
  beyond the top-level command shape
- command behavior can depend on environment variables, current working
  directory, credentials, local config, remote service state, and external
  network state
- semantic parser coverage is finite; unsupported commands or unsupported
  fields require `patterns` or conservative `ask` / `deny` fallbacks

Use semantic rules for supported tools when possible. Use raw regex `patterns`
only when semantic support is unavailable or too coarse, and cover both allowed
examples and near misses with top-level `test` entries.

Semantic `permission.allow` rules can be weakened by broader allow rules in the
same effective policy. A broad `command.name`, `command.name_in`, broad raw
pattern such as `^aws\\s+.*$`, env-only allow, or script runner allow can make
the policy look narrow while allowing a much larger namespace. `cc-bash-guard
verify` rejects broad `permission.allow` rules by default. Use
`permission.ask` for broad command namespaces and reserve `permission.allow` for
explicit semantic intent or narrow anchored fallback patterns with tests.

## Fail-Closed Behavior

The hook fails closed for trust-critical errors by returning Claude Code
structured JSON with `hookSpecificOutput.permissionDecision: "deny"` and an
explanatory `permissionDecisionReason`.

The hook exits `0` after producing valid deny JSON because Claude Code parses
structured hook JSON from stdout only when the hook process succeeds. A non-zero
exit would make Claude Code treat the result as a hook process error rather
than as the intended permission decision.

Fail-closed cases include:

- invalid hook input
- incompatible verified artifacts
- unsafe or unparsable shell shapes
- invalid config

Missing or stale verified artifacts return `ask` with a warning instead of
evaluating stale policy.

Unsafe shell shapes include parse errors, redirects, background execution,
subshells, command substitution, process substitution, and unknown shell shapes.
These must not become broad `allow` decisions.

When no rule matches and all permission sources abstain, the result is `ask`.
That is a conservative fallback, not an allow.

## Verified Artifact Model

`cc-bash-guard verify` resolves user and project config, including local
`include` files, validates the effective policy, runs configured tests, and
writes a verified artifact for hook execution.

At hook time, `cc-bash-guard hook` relies on the verified effective artifact
rather than directly trusting human-edited YAML. Included file contents are part
of the artifact fingerprint. Editing any included policy or test file makes the
artifact stale and requires another `cc-bash-guard verify`.

A missing or stale artifact fails closed as `deny`. Hook-time auto-verification
is not supported because regenerating artifacts during hook execution weakens
the review boundary between policy changes and enforcement. Run
`cc-bash-guard verify` explicitly after policy, include, test, or Claude
settings changes.

## Pattern-Rule Risks

`patterns` are raw regular expressions. They are useful for commands without
semantic parser support, but they are easier to over-broaden than structured
semantic rules.

Risky allow rules include regexes that:

- are unanchored
- allow an entire command namespace such as all `aws` or all `npm` invocations
- use broad wildcards that can cross shell metacharacters
- do not distinguish read-only operations from destructive operations
- allow script runners, plugin systems, or generic interpreters without
  additional confirmation

Safer pattern rules are narrow, anchored, and tested. Prefer command-specific
semantic rules for `git`, `gh`, `aws`, `kubectl`, `helmfile`, and `argocd`
where those parsers expose the fields needed by policy.

## RTK Integration Boundary

`cc-bash-guard` policy evaluation does not rewrite commands.

The default hook, `cc-bash-guard hook`, does not rewrite commands and does not
emit `updatedInput.command` for policy evaluation. Parser-backed normalization
is evaluation-only.

When `cc-bash-guard hook --rtk` is used, the hook evaluates permissions first.
Only when the merged permission decision is not `deny` does it delegate to the
external `rtk rewrite` command. If the decision is `deny`, RTK must not be
invoked.

Use `cc-bash-guard hook --rtk` as the single Bash hook when RTK rewriting is
needed. Do not register RTK as a second Bash hook, because that would create a
separate rewrite path outside cc-bash-guard's permission-first flow.

## Recommended Deployment Posture

- Start with explicit `deny` rules for known dangerous operations.
- Prefer semantic rules for supported high-risk tools.
- Use `ask` for ambiguous operations and unsupported command families.
- Keep allow regexes narrow, anchored, and covered by top-level tests.
- Run `cc-bash-guard verify` after every policy or included file change.
- Keep Claude Code configured with one Bash hook entry for cc-bash-guard.
- Use `cc-bash-guard hook --rtk` only when RTK rewriting is required.
- Review changes to hook setup, policy files, included files, and Claude
  settings as security-sensitive changes.
- Treat credentials, current working directory, local tool config, and remote
  state as part of the effective risk of an allowed command.
