# cc-bash-guard

Declarative, testable Bash permission policy for Claude Code.

`cc-bash-guard` is policy-as-code for Claude Code Bash permissions. It evaluates
Bash commands against YAML policy, merges that result with Claude Code native
permissions, and returns `allow`, `ask`, or `deny`. In default mode it never
rewrites commands: parser-backed normalization is used only for evaluation, and
the command passed through the hook remains the original command. Semantic
matching for tools such as `git`, `aws`, `kubectl`, `gh`, `gws`, `helm`,
`helmfile`,
and `argocd`, plus `verify`, `explain`, and `suggest`, lets humans and coding agents iterate on
policy safely.

`cc-bash-guard` policy evaluation never rewrites commands. The default hook does not emit `updatedInput`.

## Safety Scope

`cc-bash-guard` is a permission policy layer, not an OS, filesystem, or network
sandbox. It helps decide whether a Claude Code Bash command should be allowed,
confirmed, or denied before execution.

What it helps with:

- evaluates command strings using parser-backed command plans, semantic rules,
  raw `patterns`, environment checks, Claude settings permissions, and verified
  policy artifacts
- merges permission sources as `deny > ask > allow > abstain`, with final
  fallback to `ask` when all sources abstain
- fails closed when the verified artifact is missing, stale, or incompatible

What it does not do:

- sandbox an allowed process after the decision is `allow`
- remove the allowed process's normal filesystem, network, credential, plugin,
  or subprocess capabilities
- deeply inspect arbitrary script bodies or behavior behind `npm run`, `make`,
  `sh script.sh`, shell aliases/functions, or plugin-invoked commands
- detect malware or prove a command is safe

Recommended posture:

- prefer semantic rules for supported tools, explicit `deny` rules, and narrow
  `ask` / `allow` rules
- avoid broad allow regexes and broad command namespace allows such as all
  `aws`, `npm`, or `terraform` invocations
- add tests for allowed commands and near misses, then run
  `cc-bash-guard verify` after policy changes

For details, read [`docs/user/THREAT_MODEL.md`](docs/user/THREAT_MODEL.md).

## Opening Demo

One semantic rule. Multiple equivalent command forms. Tested.

```yaml
permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      test:
        allow:
          - "git status"
        abstain:
          - "git push --force origin main"

test:
  allow:
    - "git status"
    - "/usr/bin/git status"
    - "bash -c 'git status'"
    - "env bash -c 'git status'"
    - "command git status"
    - "git -C repo status"
  ask:
    - "git push --force origin main"
```

```sh
cc-bash-guard verify
cc-bash-guard explain "bash -c 'git status'"
```

See the complete runnable file at
[`examples/git-status-semantic.yml`](examples/git-status-semantic.yml).

## What It Is

The core value is policy-as-code:

- declarative YAML rules for `deny`, `ask`, and `allow`
- semantic command parsing for high-risk CLIs
- examples as tests with `cc-bash-guard verify`
- decision diagnostics with `cc-bash-guard explain`
- verified artifacts used by hook execution

`cc-bash-guard` is not:

- an OS sandbox
- a filesystem or network sandbox
- a malware detector
- a full interpreter for arbitrary scripts
- a command rewriting tool in default mode

Parser-backed normalization is evaluation-only unless `hook --rtk` is used.

## Why Semantic Policy?

Claude Code native permissions are useful for coarse tool and pattern
permissions, but prefix or wildcard rules can either miss equivalent command
forms or become too broad. A native-style pattern such as `Bash(git status*)`
does not naturally cover all normalized ways an agent might express a Git
status check, while a broad wildcard can accidentally include operations you
did not intend to allow.

`cc-bash-guard` adds a semantic policy layer on top: the policy can say
"allow Git whose semantic verb is status" and test the expected forms.

Claude Code native permissions:

```json
{
  "permissions": {
    "allow": ["Bash(git status*)"]
  }
}
```

Semantic policy:

```yaml
permission:
  allow:
    - command:
        name: git
        semantic:
          verb: status
```

The semantic policy expresses the intent directly and can be tested with
`cc-bash-guard verify`.

## Quick Start

Homebrew:

```sh
brew tap tasuku43/cc-bash-guard
brew install cc-bash-guard
cc-bash-guard init --profile git-safe
cc-bash-guard verify
```

mise:

```sh
mise use -g github:tasuku43/cc-bash-guard@latest
cc-bash-guard init --profile git-safe
cc-bash-guard verify
```

`init` creates the user config if needed and prints the Claude Code hook
snippet. Use `cc-bash-guard init --list-profiles` to see starter profiles such
as `balanced`, `strict`, `git-safe`, `aws-k8s`, and `argocd`. `verify`
validates the effective policy, runs configured examples, and writes the
verified artifact used by the hook.

To choose a practical operating posture for personal, Git-focused,
infrastructure, team, or CI verification workflows, see
[`docs/user/OPERATIONAL_TEMPLATES.md`](docs/user/OPERATIONAL_TEMPLATES.md).

For manual GitHub Releases installs, checksum verification, and Go toolchain
builds, see [`INSTALL.md`](INSTALL.md).

## Verified Artifact Model

```text
YAML policy + includes + tests + Claude settings
        |
        v
cc-bash-guard verify
        |
        v
verified artifact
        |
        v
cc-bash-guard hook
        |
        v
allow / ask / deny
```

## Agentic Policy Authoring Loop

`verify` and `explain` make the policy suitable for both human review and
Claude Code/Codex-style maintenance. A coding agent can edit YAML, run tests,
inspect the parsed command and matched rule, then refine the policy until the
examples pass.

```sh
cc-bash-guard init --profile git-safe
$EDITOR ~/.config/cc-bash-guard/cc-bash-guard.yml
cc-bash-guard suggest "git push --force origin main"
cc-bash-guard verify
cc-bash-guard explain "git push --force origin main"
```

Expected loop:

1. Use `cc-bash-guard suggest "<command>"` for a starter rule when useful.
2. Add or edit YAML policy.
3. Add test examples for allowed commands and near misses.
4. Run `cc-bash-guard verify`.
5. Use `cc-bash-guard explain` to inspect parse shape, semantic fields,
   matched rule, Claude settings contribution, and final decision.
6. Iterate until the policy is correct.

See [`docs/user/AGENTIC_POLICY_AUTHORING.md`](docs/user/AGENTIC_POLICY_AUTHORING.md)
for a short worked example.

Ask Claude Code to maintain policy with a prompt like:

```text
Edit ~/.config/cc-bash-guard/cc-bash-guard.yml.

Add a rule that denies destructive Argo CD app deletion, but does not match
argocd app get or argocd app sync.

Add tests for both matching and non-matching commands.
Run cc-bash-guard verify.
Use cc-bash-guard explain to confirm the parsed semantic fields and final decision.
Iterate until verification passes.
```

## Installation

### Homebrew

```sh
brew tap tasuku43/cc-bash-guard
brew install cc-bash-guard
```

The formula in
[`tasuku43/homebrew-cc-bash-guard`](https://github.com/tasuku43/homebrew-cc-bash-guard)
pins SHA-256 checksums against GitHub Releases archives.

### mise

```sh
mise use -g github:tasuku43/cc-bash-guard@latest
```

For manual GitHub Releases installs, checksum verification, and source builds,
see [`INSTALL.md`](INSTALL.md).

## Claude Code Hook Setup

Register Claude Code with a `PreToolUse` Bash hook. `cc-bash-guard init` prints
the snippet for your environment.

```json
{
  "matcher": "Bash",
  "hooks": [
    { "type": "command", "command": "cc-bash-guard hook" }
  ]
}
```

By default, `cc-bash-guard hook` uses verified artifacts generated by
`cc-bash-guard verify`. It fails closed when the artifact is missing, stale, or
incompatible. The `--auto-verify` flag regenerates artifacts during hook
execution and should be used only when that review tradeoff is acceptable.

Hook decisions are returned as Claude Code `PreToolUse` JSON on stdout:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "cc-bash-guard permission evaluated"
  }
}
```

`permissionDecision` is `allow`, `ask`, or `deny`. `allow` skips Claude Code's
permission prompt, `ask` asks the user to confirm, and `deny` blocks the Bash
tool call. `cc-bash-guard hook` exits `0` after printing valid hook JSON,
including deny JSON, because Claude Code only reads structured hook JSON from
stdout after a successful hook process.

## Permission Model

Permission evaluation is deterministic:

1. Parse the original command string into a command plan.
2. Evaluate cc-bash-guard `deny`, then `ask`, then `allow`.
3. Return `abstain` when no cc-bash-guard rule matches.
4. Merge cc-bash-guard policy and Claude settings permissions with
   `deny > ask > allow > abstain`.
5. Fall back to `ask` only when all permission sources abstain.

`abstain` means no matching rule or no opinion. An explicit `ask` is not
overridden by `allow` from another source. Permission rules use only
`command`, `env`, and `patterns`; permission `match` and singular `pattern` are
not supported. `command` and `patterns` cannot be combined in one rule.

## Writing Policy

### Semantic Command Rules

Prefer semantic rules for commands listed by `cc-bash-guard help semantic`.
Semantic fields live directly under `command.semantic`; `command.name` selects
the parser namespace.

```yaml
permission:
  deny:
    - name: git force push
      command:
        name: git
        semantic:
          verb: push
          force: true
      test:
        deny:
          - "git push --force origin main"
        abstain:
          - "git push origin main"

  allow:
    - name: kubectl read-only
      command:
        name: kubectl
        semantic:
          verb_in:
            - get
            - describe
      test:
        allow:
          - "kubectl get pods"
        abstain:
          - "kubectl delete pod app"
```

Supported semantic parsers currently include `git`, `aws`, `kubectl`, `gh`,
`gws`, `helm`, `helmfile`, `argocd`, `terraform`, and `docker`. Treat `cc-bash-guard help semantic` and
`cc-bash-guard semantic-schema --format json` as the source of truth for the
installed binary.

Complete runnable examples:

- [`examples/personal-cautious.yml`](examples/personal-cautious.yml)
- [`examples/infra-cautious.yml`](examples/infra-cautious.yml)
- [`examples/team-baseline.yml`](examples/team-baseline.yml)
- [`examples/git-status-semantic.yml`](examples/git-status-semantic.yml)
- [`examples/git-safe-readonly.yml`](examples/git-safe-readonly.yml)
- [`examples/aws-identity.yml`](examples/aws-identity.yml)
- [`examples/docker-readonly.yml`](examples/docker-readonly.yml)
- [`examples/docker-strict.yml`](examples/docker-strict.yml)
- [`examples/kubectl-readonly.yml`](examples/kubectl-readonly.yml)
- [`examples/gws-readonly.yml`](examples/gws-readonly.yml)
- [`examples/argocd-app-delete-deny.yml`](examples/argocd-app-delete-deny.yml)
- [`examples/helm-readonly-upgrade.yml`](examples/helm-readonly-upgrade.yml)
- [`examples/helmfile-diff-apply.yml`](examples/helmfile-diff-apply.yml)
- [`examples/terraform-readonly.yml`](examples/terraform-readonly.yml)
- [`examples/terraform-strict.yml`](examples/terraform-strict.yml)

### Raw Patterns

Use `patterns` as a fallback for deliberate raw-string checks or commands
without semantic support. Keep allow patterns narrow and test-backed.

```yaml
permission:
  allow:
    - name: terraform read-only fallback
      patterns:
        - "^terraform\\s+(plan|show)(\\s|$)[^;&|`$()]*$"
      test:
        allow:
          - "terraform plan -out=tfplan"
        abstain:
          - "terraform apply -auto-approve"
```

Avoid broad allow regexes such as `.*`, `^aws\\s+`, `^terraform\\s+`, or
`^npm\\s+`. Current `verify` fails broad `permission.allow[*].patterns` when a
regex is unanchored, allows a whole command namespace, or uses wildcards that
can cross shell metacharacters.

### Environment Requirements

Use `env.requires` and `env.missing` to require or reject environment variables
for the invocation.

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
      test:
        allow:
          - "AWS_PROFILE=dev aws sts get-caller-identity"
        abstain:
          - "aws sts get-caller-identity"
```

### Includes

Use top-level `include` to split policy and tests across local YAML files:

```yaml
include:
  - ./policies/git.yml
  - ./policies/aws.yml
  - ./tests/git.yml
```

Relative paths are resolved from the file that declares them. Included files
are resolved into one effective verified artifact. Editing any included file
makes the artifact stale, so run `cc-bash-guard verify` after changes.

### Tests

Top-level `test` examples assert end-to-end decisions:

```yaml
test:
  allow:
    - "git status"
  ask:
    - "git push origin main"
  deny:
    - "git push --force origin main"
  abstain:
    - "unknown-tool status"
```

`test.allow`, `test.ask`, and `test.deny` assert the final merged hook
decision. `test.abstain` asserts only the cc-bash-guard policy source outcome;
the final hook decision can still be `ask` when all permission sources abstain.

Rule-local `test` entries are required for permission rules. They use the same
vocabulary, but `abstain` means the individual rule should not match that
example.

## Explain And Verify

Run `verify` after editing policy and after upgrading the binary:

```sh
cc-bash-guard verify
cc-bash-guard verify --format json
```

`verify` validates config, semantic schemas, rule-local tests, top-level tests,
and broad allow pattern checks, then writes the verified artifact used by the
hook.

Use `explain` to inspect a command without executing it:

```sh
cc-bash-guard explain "git push --force origin main"
cc-bash-guard explain --format json "git status"
cc-bash-guard explain --why-not allow "git status > /tmp/out"
```

The output shows the parsed command, semantic fields, matched rule, rule source
file, Claude settings contribution, and final merged decision. It uses the same
verified artifact as the hook. See [`docs/user/EXPLAIN.md`](docs/user/EXPLAIN.md)
for how to read the output.

Use `--why-not allow|ask|deny` when you need a direct, agent-friendly diagnosis
for a near miss. The output includes the requested outcome, actual policy,
Claude settings, final outcomes, parsed shape, semantic fields, concise reasons,
and safe suggestions.

Use `suggest` to generate a pasteable starter rule without executing the command
or mutating config:

```sh
cc-bash-guard suggest "git status"
cc-bash-guard suggest --decision deny "git push --force origin main"
cc-bash-guard suggest --format json "argocd app delete my-app"
```

`suggest` prefers semantic rules, includes rule-local tests, and falls back to a
narrow anchored pattern with `ask` when classification or semantic parsing is
uncertain.

## RTK Integration

`cc-bash-guard` policy evaluation does not rewrite commands. If you use RTK rewriting, use `cc-bash-guard hook --rtk` as the single Bash hook:

```json
{
  "matcher": "Bash",
  "hooks": [
    { "type": "command", "command": "cc-bash-guard hook --rtk" }
  ]
}
```

With `--rtk`, cc-bash-guard evaluates permissions first. If the merged decision
is not `deny`, it invokes external `rtk rewrite` once and emits
`updatedInput` only when RTK returns a different command. For Claude Code Bash
payloads, `updatedInput` preserves the original `tool_input` object and replaces
only `command`. The default hook is policy-only and never emits `updatedInput`.
A `deny` decision never invokes RTK. Do not register RTK as a second Bash hook.

Top-level `rewrite` is not supported; if a config contains top-level `rewrite`, `verify` fails with migration guidance.

## Threat Model And Limitations

Read [`docs/user/THREAT_MODEL.md`](docs/user/THREAT_MODEL.md) before relying on
broad allow rules.

Visible boundaries:

- No sandboxing is claimed.
- No malware detection is claimed.
- Arbitrary scripts are not fully interpreted.
- Bash parser coverage is finite; unsupported or unsafe shell shapes fail
  closed or fall back conservatively.
- Allowed commands can still use their normal filesystem, network, credential,
  plugin, and subprocess capabilities.
- Parser-backed normalization is evaluation-only unless `hook --rtk` is used.

## CLI Reference

Useful commands:

```sh
cc-bash-guard init
cc-bash-guard init --profile git-safe
cc-bash-guard init --list-profiles
cc-bash-guard verify
cc-bash-guard explain "git status"
cc-bash-guard suggest "git status"
cc-bash-guard doctor
cc-bash-guard version
cc-bash-guard help setup
cc-bash-guard help permission
cc-bash-guard help semantic
cc-bash-guard help semantic git
cc-bash-guard help explain
cc-bash-guard help suggest
cc-bash-guard help examples
cc-bash-guard help troubleshoot
```

User docs:

- [`docs/user/QUICKSTART.md`](docs/user/QUICKSTART.md)
- [`docs/user/AGENTIC_POLICY_AUTHORING.md`](docs/user/AGENTIC_POLICY_AUTHORING.md)
- [`docs/user/EXPLAIN.md`](docs/user/EXPLAIN.md)
- [`docs/user/PERMISSION_SCHEMA.md`](docs/user/PERMISSION_SCHEMA.md)
- [`docs/user/SEMANTIC_SCHEMAS.md`](docs/user/SEMANTIC_SCHEMAS.md)
- [`docs/user/EXAMPLES.md`](docs/user/EXAMPLES.md)
- [`docs/user/THREAT_MODEL.md`](docs/user/THREAT_MODEL.md)
- [`docs/user/TROUBLESHOOTING.md`](docs/user/TROUBLESHOOTING.md)
