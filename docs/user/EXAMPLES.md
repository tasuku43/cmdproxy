# Examples

These examples use the current permission shape: `command`, `env`, and
`patterns`.

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
```

## Read-Only Shell Basics

```yaml
permission:
  allow:
    - name: read-only shell basics
      patterns:
        - "^ls(\\s+-[A-Za-z0-9]+)?\\s+[^;&|`$()]+$"
        - "^pwd$"
        - "^cat\\s+[^;&|`$()]+$"
```

## Unknown Command Fallback

Use `patterns` when a command has no semantic schema.

```yaml
permission:
  ask:
    - name: tool preview
      patterns:
        - "^my-tool\\s+preview(\\s|$)"
```

## Safe Pattern Fallback

Prefer `command` plus `command.semantic` for commands listed by
`cc-bash-guard help semantic`. For commands without semantic support, anchor
regexes, allow only intended subcommands, and add top-level tests for commands
that must remain `ask`.

```yaml
permission:
  allow:
    - name: terraform read-only fallback
      patterns:
        - "^terraform\\s+(plan|show)(\\s|$)[^;&|`$()]*$"

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
cc-bash-guard does not deeply inspect, and `cc-bash-guard verify` fails them by
default.
