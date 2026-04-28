---
title: "Pipeline Schema"
status: implemented
date: 2026-04-26
---

# Pipeline Schema

Current configs are permission-only.

Top-level keys:

- `include`
- `permission`
- `test`

`include` is a top-level list of local YAML file paths. Relative include paths
resolve from the file that declares the include, and nested includes are
supported. Includes are resolved before the current file, so permission buckets
and top-level `test` entries concatenate as `include[0]`, `include[1]`, then the
current file. URLs, empty include entries, missing files, non-regular files,
shell expansion, environment expansion, command substitution, globbing, and
include cycles are invalid.

`claude_permission_merge_mode` is no longer supported. If present,
verification fails with:

```text
claude_permission_merge_mode is no longer supported; permission sources are merged using deny > ask > allow > abstain.
```

Top-level `rewrite` is no longer supported. If present, verification fails with:

```text
top-level rewrite is no longer supported; cc-bash-guard policy evaluation no longer rewrites commands. Use permission.command / env / patterns, and rely on parser-backed normalization for evaluation.
```

Permission rules use only `command`, `env`, and `patterns`. Singular
`pattern` and permission `match` are not supported. `patterns` evaluate the
original command string and parsed command elements, including shell `-c` inner
commands.

```yaml
permission:
  deny:
    - name: git destructive force push
      command:
        name: git
        semantic:
          verb: push
          force: true

  allow:
    - name: aws identity
      command:
        name: aws
        semantic:
          service: sts
          operation: get-caller-identity
      env:
        requires:
          - AWS_PROFILE

  ask:
    - name: helm upgrade fallback
      patterns:
        - "^helm\\s+upgrade\\b"
      env:
        requires:
          - KUBECONFIG
```

Rules may combine `command + env` or `patterns + env`. `command + patterns` is
invalid.

Top-level `test` asserts final permission decision only:

```yaml
test:
  - in: "git status"
    decision: allow
```

`rewritten` is not supported because `cc-bash-guard` policy evaluation does not
rewrite commands.
