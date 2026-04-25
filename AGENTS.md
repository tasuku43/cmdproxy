# Repository Instructions

## Language

Respond in Japanese, concisely and politely.

## GitHub PR URLs

Use the `gh` command for GitHub PR URLs.

When using `gh` commands or GitHub MCP, request escalated permissions.

## Source Of Truth

- User-facing current behavior: `README.md`
- Implementation contract: `docs/dev/spec/*`
- Actual behavior: tests plus `internal/domain/*`

`docs/dev/spec/*` files use frontmatter `status`.

- `status: implemented`: contract for current behavior
- `status: proposed`: selected or drafted target behavior, not necessarily shipped
- `status: planned`: identified future behavior, not shipped

Do not treat `status: proposed` or `status: planned` specs as implemented
behavior.

## When Documents And Code Disagree

If README, spec, tests, and implementation disagree:

- do not silently pick one source and proceed
- preserve security-first behavior
- fail closed for permission ambiguity
- prefer `deny` or `ask` over `allow`
- add or update tests that capture the chosen behavior
- update README/spec together with code when behavior changes

For user-visible current behavior, update `README.md`. For contract-level
behavior, update the relevant `docs/dev/spec/*` file and its `status` when
appropriate.

## Security-Sensitive Permission Behavior

For permission proxy behavior, ambiguity must not become permissive.

- raw `allow` must not become broader without explicit docs and tests
- compound command handling must not accidentally allow additional shell
  segments
- unknown shell shapes must not be made more permissive accidentally
- parser uncertainty must fall back to `ask` rather than broad `allow`
- fail-closed behavior must be preserved for parse errors, unsafe ASTs,
  redirects, background execution, subshells, process substitution, and unknown
  shell shapes

When changing `CommandPlan`, `ShellShape`, parser behavior, or permission
evaluation:

- update related tests
- update `README.md` if behavior is user-visible
- update `docs/dev/spec/*` if contract-level behavior changes
