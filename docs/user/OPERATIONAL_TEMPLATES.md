# Operational Templates

Use these templates to choose a practical operating posture before writing
custom rules. They are examples of reviewed policy shape, not sandboxes. When a
command is allowed, the invoked tool still has its normal filesystem, network,
credential, plugin, and subprocess capabilities.

`ask` is the conservative default for ambiguity. If no cc-bash-guard rule or
Claude settings permission matches, the final fallback is `ask`. Prefer
semantic rules for supported commands and keep raw `patterns` narrow, anchored,
and covered by tests.

Run `cc-bash-guard verify` after editing policy or included files. Avoid
`hook --auto-verify` for reviewed team workflows unless hook-time policy
activation without a separate review step is an intentional tradeoff.

## Quick Choice

| Posture | Best for | Start with |
| --- | --- | --- |
| Personal cautious | Individual users who want a safe default | Built-in `balanced` or `examples/personal-cautious.yml` |
| Git-safe development | Daily coding with Git inspection allowed | Built-in `git-safe` or `examples/git-safe-readonly.yml` |
| Infrastructure cautious | AWS, Kubernetes, Helm, Helmfile, Terraform, Docker, and Argo CD work | `examples/infra-cautious.yml` |
| Team baseline | Shared policy reviewed by a small team | `examples/team-baseline.yml` plus split includes |
| CI / pre-commit verification | Making policy changes testable before use | `examples/ci-verify-policy.sh` |

List built-in starter profiles with:

```sh
cc-bash-guard init --list-profiles
```

Built-in profiles currently include `balanced`, `strict`, `git-safe`,
`aws-k8s`, and `argocd`. Use built-ins when they fit your workflow; use the
external examples when you want a fuller operational template to copy into a
user or project policy.

## Personal Cautious Mode

Intended user: an individual user adopting cc-bash-guard for normal Claude Code
use.

Allows:

- Git read-only inspection such as `status`, `diff`, `log`, `show`, and
  branch inspection.
- Basic local inspection commands through narrow raw patterns, when you choose
  to include them.

Asks:

- Git write operations such as `commit`, `push`, `reset`, `rebase`, and
  `merge`.
- Unknown commands by fallback when all permission sources abstain.

Denies:

- `git push --force`
- `git push --force-with-lease`
- `git reset --hard`
- `git clean -fdx` style destructive clean commands where semantic fields
  identify force, recursive, and ignored-file deletion.

Known limitations:

- A read-only looking command can still read sensitive local files or contact
  configured remotes depending on the tool.
- Raw allow patterns for local inspection should stay narrow and anchored.

How to verify:

```sh
cc-bash-guard verify
cc-bash-guard explain "git push --force origin main"
```

Template: [`examples/personal-cautious.yml`](../../examples/personal-cautious.yml)

## Git-Safe Development Mode

Intended user: a developer who wants smooth local code review while keeping
history and remote writes behind confirmation or denial.

Allows:

- `git status`, `git diff`, `git log`, `git show`, and branch inspection.

Asks:

- `git push`
- `git commit`
- `git reset`
- `git rebase`
- `git merge`

Denies:

- Force push forms covered by semantic fields.
- Hard reset.
- Destructive clean forms that remove ignored files recursively.

Known limitations:

- cc-bash-guard does not make Git operations safe after execution starts.
  Hooks, credential helpers, remotes, and local Git configuration still behave
  normally.

How to verify:

```sh
cc-bash-guard init --profile git-safe
cc-bash-guard verify
cc-bash-guard explain "git push origin main"
```

Built-in profile: `git-safe`

Runnable example: [`examples/git-safe-readonly.yml`](../../examples/git-safe-readonly.yml)

## Infrastructure Cautious Mode

Intended user: someone who works with cloud and deployment tools and wants a
strong `ask` posture.

Allows:

- `aws sts get-caller-identity`
- `kubectl get` and `kubectl describe`
- `helm list`, `helm status`, and `helm get`
- `helmfile diff`
- `terraform plan` and `terraform show`
- `docker ps`, `docker images`, and `docker inspect`
- `argocd app get`

Asks:

- AWS operations outside the narrow identity check.
- Kubernetes apply/delete and other mutating operations.
- Helm install/upgrade and plugin changes.
- Helmfile apply/sync/destroy.
- Terraform apply/destroy/state mutation.
- Docker run/exec/compose mutating commands.
- Argo CD sync.

Denies:

- Kubernetes delete in the example template.
- Helm uninstall.
- Terraform destroy with `-auto-approve`.
- Docker privileged containers, host namespace use, root mounts, Docker socket
  mounts, and destructive prune with volumes.
- Argo CD app delete.

Known limitations:

- Semantic matching is syntactic. It does not inspect Kubernetes manifests,
  Terraform plans, Helm charts, Docker images, compose files, plugins, or
  remote service state.
- Some cloud APIs use service-specific read/write names. Prefer `ask` unless
  you have reviewed the exact operation.

How to verify:

```sh
cc-bash-guard verify
cc-bash-guard explain "terraform apply tfplan"
cc-bash-guard explain "docker run --privileged alpine"
```

Template: [`examples/infra-cautious.yml`](../../examples/infra-cautious.yml)

## Team Baseline Mode

Intended user: a small team that wants a shared reviewed policy and repeatable
verification.

Recommended layout:

```text
.cc-bash-guard/
  cc-bash-guard.yml
  policies/
    git.yml
    infra.yml
  tests/
    git.yml
    infra.yml
```

Root config:

```yaml
include:
  - ./policies/git.yml
  - ./policies/infra.yml
  - ./tests/git.yml
  - ./tests/infra.yml
```

Use rule-local tests to prove the rule's direct behavior, and top-level tests
to prove end-to-end decisions after deny, ask, allow, Claude settings, and
fallback behavior are merged.

Review process:

- Treat hook config, policy files, included files, tests, and Claude settings
  as security-sensitive changes.
- Prefer semantic rules for supported commands.
- Require tests for allowed examples and near misses.
- Run `cc-bash-guard verify` after each policy change and after upgrading the
  binary.
- Do not rely on CI alone to enforce a local hook; each user still needs a
  verified local artifact for their effective config.

Template: [`examples/team-baseline.yml`](../../examples/team-baseline.yml)

## CI / Pre-Commit Verification

Use verification automation to make policy changes testable before use. This
checks that the policy and examples are internally consistent. It does not
replace each user's local Claude Code hook setup or local verified artifact.

Shell script:

```sh
examples/ci-verify-policy.sh
```

GitHub Actions sketch:

```yaml
name: cc-bash-guard policy

on:
  pull_request:
    paths:
      - ".cc-bash-guard/**"
      - "examples/**"
      - "docs/user/**"

jobs:
  verify-policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go run ./cmd/cc-bash-guard verify --all-failures
      - run: go run ./cmd/cc-bash-guard explain "git push --force origin main"
```

For local pre-commit, run:

```sh
cc-bash-guard verify --all-failures
cc-bash-guard explain "git push --force origin main"
```
