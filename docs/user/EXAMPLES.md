# Examples

These examples use the current permission shape: `command`, `env`, and
`patterns`. Prefer `command.name` plus `command.semantic` for supported tools;
use raw `patterns` as a fallback for commands without semantic support or for
deliberate raw-string checks.

For production-oriented operating postures that combine these patterns, see
`docs/user/OPERATIONAL_TEMPLATES.md`.

## Semantic Git Status

One semantic rule can allow equivalent forms of `git status` without a broad
regex.

```yaml
permission:
  allow:
    - name: git status
      command:
        name: git
        semantic:
          verb: status
      message: "allow git status"
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

## Split Policy And Tests

Root config:

```yaml
include:
  - ./policies/git.yml
  - ./policies/aws.yml
  - ./tests/git.yml
  - ./tests/aws.yml

permission:
  ask:
    - name: project fallback
      patterns:
        - "^helm\\s+upgrade\\b"
      test:
        ask:
          - "helm upgrade app chart"
        abstain:
          - "helmfile diff"
```

`./policies/git.yml`:

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
      test:
        allow:
          - "git status"
        abstain:
          - "git push origin main"
```

`./tests/git.yml`:

```yaml
test:
  - in: "git status"
    decision: allow
  - in: "git push --force origin main"
    decision: ask
```

Relative include paths are resolved from the file that declares them. Included
permission and test lists are concatenated before entries in the current file.
Run `cc-bash-guard verify` after editing any included file.

## Git Read-Only Allow

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
      test:
        allow:
          - "git status"
        abstain:
          - "git push origin main"
```

## Git Destructive Force Push Deny

```yaml
permission:
  deny:
    - name: git destructive force push
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
```

## AWS Identity Allow

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

## kubectl Read-Only Allow

```yaml
permission:
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

## gh Read-Only PR Inspection

```yaml
permission:
  allow:
    - name: gh pr read-only
      command:
        name: gh
        semantic:
          area: pr
          verb_in:
            - view
            - list
            - diff
      test:
        allow:
          - "gh pr view 123"
        abstain:
          - "gh pr merge 123"
```

## helmfile Diff Allow

```yaml
permission:
  allow:
    - name: helmfile diff
      command:
        name: helmfile
        semantic:
          verb: diff
      test:
        allow:
          - "helmfile diff"
        abstain:
          - "helmfile apply"
```

## Argo CD App Delete Deny

Argo CD semantic `verb` uses the action path, such as `app get`, `app sync`,
or `app delete`.

```yaml
permission:
  deny:
    - name: Argo CD app delete
      command:
        name: argocd
        semantic:
          verb: app delete
      test:
        deny:
          - "argocd app delete my-app"
        abstain:
          - "argocd app get my-app"

  ask:
    - name: Argo CD app sync
      command:
        name: argocd
        semantic:
          verb: app sync
      test:
        ask:
          - "argocd app sync my-app"
        abstain:
          - "argocd app get my-app"
```

## Helmfile Diff Allow, Apply Ask

```yaml
permission:
  allow:
    - name: helmfile diff
      command:
        name: helmfile
        semantic:
          verb: diff
      test:
        allow:
          - "helmfile diff"
        abstain:
          - "helmfile apply"

  ask:
    - name: helmfile apply
      command:
        name: helmfile
        semantic:
          verb: apply
      test:
        ask:
          - "helmfile apply"
        abstain:
          - "helmfile diff"
```

## Read-Only Shell Basics

Use `command.name_in` for non-semantic command-name lists. It still benefits
from parser-backed command-name normalization.

```yaml
permission:
  allow:
    - name: read-only shell basics
      command:
        name_in:
          - ls
          - pwd
          - cat
          - head
          - tail
          - wc
          - grep
          - rg
      test:
        allow:
          - "ls -la"
        abstain:
          - "rm -rf build"
```

## Unknown Command Fallback

Use `patterns` when a command has no semantic schema and cannot be expressed by
`command.name_in`.

```yaml
permission:
  ask:
    - name: tool preview
      patterns:
        - "^my-tool\\s+preview(\\s|$)"
      test:
        ask:
          - "my-tool preview prod"
        abstain:
          - "my-tool apply prod"
```

## Safe Pattern Fallback

Pattern rules are fallback rules. Anchor regexes, allow only intended
subcommands, exclude shell metacharacters where appropriate, and add tests for
commands that must remain `ask`.

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

test:
  - in: "terraform plan -out=tfplan"
    decision: allow
  - in: "terraform show tfplan"
    decision: allow
  - in: "terraform apply -auto-approve"
    decision: ask
  - in: "terraform plan; terraform apply -auto-approve"
    decision: ask
```

Avoid broad allow rules such as `.*`, `^terraform\\s+`, or `^npm\\s+`. They can
allow destructive subcommands or commands that invoke scripts and plugins that
cc-bash-guard does not deeply inspect. `cc-bash-guard verify` fails broad
`permission.allow[*].patterns` by default.
