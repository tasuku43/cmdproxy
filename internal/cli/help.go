package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	semanticpkg "github.com/tasuku43/cc-bash-guard/internal/domain/semantic"
)

func writeUsage(w io.Writer) {
	fmt.Fprint(w, `cc-bash-guard

cc-bash-guard is a security-first Bash permission guard for Claude Code hooks.
It evaluates Bash commands against policy and returns allow, ask, or deny.

Start here:
  cc-bash-guard help setup

Claude Code ready check:
  cc-bash-guard init --profile git-safe
  add the printed PreToolUse Bash snippet to Claude Code settings
  cc-bash-guard verify
  cc-bash-guard doctor

Policy authoring loop:
  write test examples -> add narrow rules -> cc-bash-guard verify
  -> cc-bash-guard explain "<command>" when unclear -> repeat

Usage:
  cc-bash-guard <command> [flags]

Commands:
  init     create the user config and print the Claude Code hook snippet
  explain  diagnose why a command would be allowed, asked, or denied
  suggest  suggest a pasteable starter permission rule for a command
  doctor   inspect config quality and installation state
  verify   verify config tests, trust-critical setup, and build metadata
  version  print build and source metadata for the running binary
  hook     Claude Code hook entrypoint
  semantic-schema
           print supported semantic match schemas

Policy model:
  Use command for semantic-supported commands.
  Use env for environment variable predicates.
  Use patterns for raw regex fallbacks and commands without semantic support.
  Rules live under permission.deny, permission.ask, and permission.allow.
  Use top-level include to split policy and E2E tests across local YAML files.
  Decision order is deny > ask > allow; unmatched commands fall back to ask.
  cc-bash-guard policy evaluation never rewrites commands; it returns allow,
  ask, or deny. The default hook does not emit updatedInput.

Learn more:
  cc-bash-guard help init
  cc-bash-guard help explain
  cc-bash-guard help suggest
  cc-bash-guard help config
  cc-bash-guard help permission
  cc-bash-guard help semantic
  cc-bash-guard help semantic git
  cc-bash-guard help examples
  cc-bash-guard help troubleshoot

Examples:
  cc-bash-guard init
  cc-bash-guard verify
  cc-bash-guard explain "git status"
  cc-bash-guard suggest "git status"
  cc-bash-guard semantic-schema --format json
  cc-bash-guard hook

Docs:
  docs/user/QUICKSTART.md
  docs/user/THREAT_MODEL.md
`)
}

func writeHelp(stdout, stderr io.Writer, args []string) int {
	if len(args) == 0 {
		writeUsage(stdout)
		return exitAllow
	}
	if args[0] == "semantic" {
		if err := writeSemanticHelp(stdout, args[1:]); err != nil {
			writeErr(stderr, err.Error())
			return exitError
		}
		return exitAllow
	}
	writeCommandHelp(stdout, args[0])
	return exitAllow
}

func writeCommandHelp(w io.Writer, command string) {
	switch command {
	case "setup":
		fmt.Fprint(w, `cc-bash-guard help setup

Set up cc-bash-guard and author policy with a test-first loop.

First-time setup:
  cc-bash-guard init --profile git-safe
  add the printed PreToolUse Bash snippet to Claude Code settings
  edit ~/.config/cc-bash-guard/cc-bash-guard.yml
  cc-bash-guard verify
  cc-bash-guard doctor

Claude Code is ready when:
  - cc-bash-guard verify exits with PASS verify
  - cc-bash-guard doctor reports the binary, config, verified artifact, and
    Claude Code Bash hook registration as pass

After init, replace the starter policy with examples from your workflow. Keep at
least one top-level test and one rule-local test for every rule you add.

Recommended policy loop:
  1. Write examples first.
     Include commands that should pass and near misses that must not pass.

  2. Add the smallest rules that make the examples pass.
     Prefer command.semantic for supported tools. See help permission for rule
     shape details.

  3. Run verify.
     cc-bash-guard verify

  4. Inspect unclear decisions.
     cc-bash-guard explain "git push origin main"

  5. Repeat.
     Add tests before broadening rules. Keep ambiguous commands as ask.

Test-first example:
  test:
    deny:
      - "git push --force origin main"
    ask:
      - "git push origin main"

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

Principles:
  - write near-miss tests for commands that look similar but should not pass
  - keep allow rules narrow and test-backed
  - use ask for review-required or ambiguous commands
  - rerun verify after every policy or include change

Use rule-local test to check whether one rule matches.
Use top-level test to check the final merged allow / ask / deny decision.

Next:
  cc-bash-guard help examples
  cc-bash-guard help semantic
  cc-bash-guard help permission
`)
	case "init":
		fmt.Fprint(w, `cc-bash-guard init

Create ~/.config/cc-bash-guard/cc-bash-guard.yml when it does not exist and print the
Claude Code PreToolUse hook snippet.

Usage:
  cc-bash-guard init
  cc-bash-guard init --profile balanced
  cc-bash-guard init --profile strict
  cc-bash-guard init --profile git-safe
  cc-bash-guard init --profile aws-k8s
  cc-bash-guard init --profile argocd
  cc-bash-guard init --list-profiles

What it does:
  - creates a starter config when the config file is missing
  - can create a verified starter profile with policy examples and tests
  - leaves an existing config file unchanged
  - prints the user config path
  - prints the Claude Code PreToolUse Bash hook snippet

After init:
  cc-bash-guard init --profile git-safe
  add the printed snippet to ~/.claude/settings.json
  cc-bash-guard verify
  cc-bash-guard doctor
  edit ~/.config/cc-bash-guard/cc-bash-guard.yml
`)
	case "doctor":
		fmt.Fprint(w, `cc-bash-guard doctor

Inspect config validity, pipeline quality, and Claude Code hook registration.

Usage:
  cc-bash-guard doctor [--format json]

Examples:
  cc-bash-guard doctor
  cc-bash-guard doctor --format json
`)
	case "verify":
		fmt.Fprint(w, `cc-bash-guard verify

Verify the local trust-critical cc-bash-guard setup.
This command is stricter than doctor: it fails when the config is broken, when
configured tests fail, when the effective global/local tool settings and
cc-bash-guard policy disagree with expected E2E outcomes, or when build metadata is
missing.

Usage:
  cc-bash-guard verify [--format json] [--color auto|always|never] [--all-failures]

Options:
  --format json              print structured diagnostics for tooling
  --color auto|always|never  colorize human output; default is auto
  --all-failures             collect all validation and E2E failures

Examples:
  cc-bash-guard verify
  cc-bash-guard verify --format json

Output:
  Human output starts with PASS verify or FAIL verify, then a compact summary.
  Failures include source YAML path, test or rule index, expected and actual
  decisions, final reason, source decisions, and matched rule source when known.
  JSON output includes ok, summary, failures, and warnings. JSON never contains
  ANSI color. NO_COLOR and TERM=dumb disable color for human output.
  Use top-level test entries to cover both allowed examples and near misses,
  especially for patterns fallback rules. See docs/user/EXAMPLES.md.
  Verify fails on broad allow.patterns, including unanchored regexes, whole
  command namespaces such as ^aws, and broad shell-metacharacter matches.

Semantic diagnostics:
  Unsupported semantic fields and invalid semantic types include the command,
  field, supported fields, and a hint such as:
    cc-bash-guard help semantic git
`)
	case "hook":
		fmt.Fprint(w, `cc-bash-guard hook

Claude Code hook entrypoint.
Reads stdin JSON, parses the command, evaluates permission policy, and
returns Claude Code hook JSON for allow, ask, deny, or error outcomes.

Usage:
  cc-bash-guard hook [--rtk]

Options:
  --rtk  optional bridge to external RTK after permission evaluation

Note:
  You usually do not run this manually. Edit rules and use cc-bash-guard verify
  while authoring policy instead. When verified artifacts are missing or stale,
  the hook verifies the current effective config before evaluating it. If that
  verification fails, the hook asks with a warning.
  Safe single-command cc-bash-guard invocations, including cc-bash-guard verify,
  bypass hook policy to avoid setup deadlocks. Compound commands, redirects, and
  pipelines do not bypass policy.

Hook protocol:
  The hook prints Claude Code PreToolUse JSON to stdout and exits 0 when that
  JSON was produced. Decisions are encoded in hookSpecificOutput:
    permissionDecision: allow, ask, or deny
    permissionDecisionReason: rule message or a cc-bash-guard fallback

  Deny is also returned as JSON with exit 0. Claude Code only parses structured
  hook JSON from successful hook processes; non-zero exits are reserved for
  hook command failures and make Claude Code ignore stdout JSON. Invalid input
  invalid input therefore fails closed by returning permissionDecision: deny.
  Missing or stale verified artifacts are regenerated before evaluation when
  verification passes. If verification fails, the hook returns
  permissionDecision: ask with a warning systemMessage and additionalContext,
  so Claude Code can continue through confirmation without trusting stale
  policy.

RTK integration:
  --rtk is optional. Use it only when you want RTK command rewriting.
  If you use RTK rewriting, use cc-bash-guard hook --rtk as the single Bash hook.
  Do not register RTK as a second Bash hook.
  cc-bash-guard evaluates permissions first, then invokes external rtk rewrite
  only when the merged decision is not deny. It emits updatedInput only when RTK
  returns a different command, preserving the Claude tool_input object and
  replacing only command. Deny never invokes RTK.

`)
	case "explain":
		fmt.Fprint(w, `cc-bash-guard explain

Diagnose why a command would be allowed, asked, or denied.
This command does not execute the command.
It uses the verified policy artifact used by the hook, so run verify after
editing policy or included policy files.

Usage:
  cc-bash-guard explain [--format text|json] [--why-not allow|ask|deny] "<command>"

Examples:
  cc-bash-guard explain "git status"
  cc-bash-guard explain --format json "git push --force origin main"
  cc-bash-guard explain --why-not allow "git status > /tmp/out"

Notes:
  - text output is for humans
  - JSON output is stable enough for tooling and tests
  - --why-not explains why the final outcome was not the requested outcome
  - stale or missing verified artifacts fail with a hint to run verify
`)
	case "suggest":
		fmt.Fprint(w, `cc-bash-guard suggest

Suggest a pasteable starter permission rule for a command.
This command does not execute the command, write files, or mutate config.

Usage:
  cc-bash-guard suggest [--decision allow|ask|deny] [--format yaml|json] "<command>"

Examples:
  cc-bash-guard suggest "git status"
  cc-bash-guard suggest --decision deny "git push --force origin main"
  cc-bash-guard suggest --format json "argocd app delete my-app"

Notes:
  - default format is yaml
  - default decision is conservative and falls back to ask when uncertain
  - semantic rules are preferred when a semantic parser is available
  - unsupported commands use a narrow anchored pattern fallback
  - generated rules include rule-local tests
`)
	case "version":
		fmt.Fprint(w, `cc-bash-guard version

Print build metadata for the running binary. Use this to inspect the module,
Go toolchain, and VCS information embedded in the installed executable.

Usage:
  cc-bash-guard version [--format json]

Examples:
  cc-bash-guard version
  cc-bash-guard version --format json
`)
	case "semantic-schema":
		fmt.Fprint(w, `cc-bash-guard semantic-schema

Print supported command-specific semantic match schemas.

Usage:
  cc-bash-guard semantic-schema [command] [--format json]

Examples:
  cc-bash-guard semantic-schema --format json
  cc-bash-guard semantic-schema git --format json
`)
	case "permission":
		fmt.Fprint(w, `cc-bash-guard help permission

Permission rules are grouped into deny, ask, and allow buckets.
Start with deny rules for dangerous commands, allow rules for known safe
commands, and ask rules for commands that need review.

Rule fields:
  command   Match a command by name/name_in, shape flags, and supported semantic fields.
  env       Match environment variables required or missing for the invocation.
  patterns  Match the raw command string with one or more regular expressions.

Valid combinations:
  command (name)
  command (name) + env
  command (name_in)
  command (name_in) + env
  command + shape_flags_any/all/none
  command + shape_flags_any/all/none + env
  command + semantic
  command + semantic + env
  patterns
  patterns + env
  env

When to use each matcher:
  Use command.semantic for commands listed by cc-bash-guard help semantic.
  The semantic schema is selected by command.name.
  Use command.name_in for a non-semantic OR list of command names.
  Use command.shape_flags_any/all/none for parser-derived shell shape flags,
  such as redirect_stream_merge, redirect_to_devnull, redirect_file_write,
  redirect_append_file, redirect_stdin_from_file, and redirect_heredoc.
  Use permission.tolerated_redirects.only when already allowed commands should
  remain allowed with specific harmless redirects, such as stdout_to_devnull
  or stderr_to_devnull. This global setting applies after includes are merged.
  Use command.tolerated_redirects.only in an allow rule when only that command
  rule should tolerate those redirects.
  Tolerated redirects do not allow new commands by themselves; they only relax
  fail-closed redirect handling for otherwise matching allow rules.
  Supported tolerated redirect values:
    stdout_to_devnull
    stderr_to_devnull
    stdin_from_devnull
  File writes, append redirects, stream merges such as 2>&1, heredocs,
  dynamic redirect targets, and unknown redirects still ask.
  Semantic fields live directly under command.semantic; no extra tool-name
  nesting is required because command.name is the discriminator.
  Use patterns for raw regex fallbacks that cannot be expressed with name_in.
  Use env when a rule depends on variables such as AWS_PROFILE.
  Put rules under permission.deny, permission.ask, or permission.allow.
  Do not combine command and patterns in the same rule.

Example:
  permission:
    tolerated_redirects:
      only:
        - stdout_to_devnull
        - stderr_to_devnull

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

      - name: AWS identity
        command:
          name: aws
          semantic:
            service: sts
            operation: get-caller-identity
        env:
          requires:
            - AWS_PROFILE

      - name: read-only basics
        command:
          name_in:
            - ls
            - pwd
            - head
            - tail
            - wc
    deny:
      - name: block stream merge redirects
        command:
          name_in:
            - ls
            - git
          shape_flags_any:
            - redirect_stream_merge

Docs:
  docs/user/PERMISSION_SCHEMA.md
`)
	case "examples":
		fmt.Fprint(w, `cc-bash-guard help examples

Copyable permission policy examples using the current rule shape.

Split policy and tests:
  include:
    - ./policies/git.yml
    - ./tests/git.yml

  # ./tests/git.yml
  test:
    - in: "git status"
      decision: allow

Git read-only allow:
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

Git destructive force push deny:
  permission:
    deny:
      - name: git destructive force push
        command:
          name: git
          semantic:
            verb: push
            force: true

AWS identity allow:
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

kubectl read-only allow:
  permission:
    allow:
      - name: kubectl read-only
        command:
          name: kubectl
          semantic:
            verb_in:
              - get
              - describe

Read-only shell basics:
  permission:
    allow:
      - name: read-only shell basics
        command:
          name_in:
            - ls
            - pwd
            - head
            - tail
            - wc

Unknown command fallback:
  permission:
    ask:
      - name: tool preview
        patterns:
          - "^my-tool\\s+preview(\\s|$)"

Safe patterns fallback:
  permission:
    allow:
      - name: terraform read-only fallback
        patterns:
          - "^terraform\\s+(plan|show)(\\s|$)[^;&|$()]*$"
        test:
          allow:
            - "terraform plan -out=tfplan"
          abstain:
            - "terraform apply -auto-approve"

  test:
    allow:
      - "terraform plan -out=tfplan"
    ask:
      - "terraform apply -auto-approve"

Docs:
  docs/user/EXAMPLES.md
`)
	case "troubleshoot":
		fmt.Fprint(w, `cc-bash-guard help troubleshoot

Common checks:

Verified artifact missing or stale:
  The hook verifies the current effective config before evaluating it. If
  verification fails, run cc-bash-guard verify to inspect the diagnostics.
  Included policy files are part of the verified artifact fingerprint.

Include error:
  include is top-level only and contains local file paths. Relative paths are
  resolved from the file that declares them. URLs, empty entries, missing files,
  non-regular files, and include cycles fail verification.

Unsupported semantic field:
  Run cc-bash-guard help semantic <command> or
  cc-bash-guard semantic-schema <command> --format json. If verify reports an
  unknown key, use the current permission shape: command, env, and patterns.

Command has no semantic schema:
  Use patterns for raw regex rules. Semantic matching only works for commands
  listed by cc-bash-guard help semantic. Prefer semantic rules when available.

All permission sources abstained:
  The final result is ask. Add an allow, ask, or deny rule when you want an
  explicit decision.

Regex pattern not matching:
  patterns match the raw command string. Anchor carefully and escape backslashes
  for YAML double-quoted strings, or use single-quoted YAML strings.

Broad pattern allow rules:
  Avoid broad allow patterns such as .*, ^aws\\s+, ^terraform\\s+, or ^npm\\s+.
  Allowed commands may invoke scripts, plugins, or subcommands that are not
  deeply inspected. Verify fails these broad allow patterns by default. Prefer
  command.name_in, command.semantic, or narrow anchored regexes that exclude
  shell metacharacters.

AWS profile style:
  Prefer AWS_PROFILE=myprof aws eks list-clusters in project guidance. The AWS
  parser can still evaluate profile, service, and operation semantically.

Command not being rewritten:
  cc-bash-guard policy evaluation and the default hook do not rewrite commands.
  Parser-backed normalization is evaluation-only. It only returns allow, ask,
  or deny. If you use RTK rewriting, use cc-bash-guard hook --rtk as the single
  Bash hook so permission evaluation runs before external rtk rewrite.

Docs:
  docs/user/TROUBLESHOOTING.md
  docs/user/THREAT_MODEL.md
  docs/user/AWS_GUIDELINES.md
`)
	case "config":
		fmt.Fprint(w, `cc-bash-guard help config

Config files live at:
  - ~/.config/cc-bash-guard/cc-bash-guard.yml
  - ./.cc-bash-guard/cc-bash-guard.yaml (project-local, optional)

First-time setup:
  cc-bash-guard init
  edit ~/.config/cc-bash-guard/cc-bash-guard.yml
  cc-bash-guard verify
  cc-bash-guard doctor

Top-level sections are:
  - include: local YAML files to resolve before the current file
  - permission: deny / ask / allow buckets
  - test: end-to-end expect cases

Include:
  include:
    - ./policies/git.yml
    - ./tests/git.yml

  Relative paths are resolved from the including file. Included files may also
  include other files. URLs, shell expansion, environment variables, command
  substitution, and globbing are not supported. permission and test lists are
  concatenated as include[0], include[1], then the current file.

  cc-bash-guard verify bundles included files into one effective artifact. The
  hook evaluates that artifact, and included file changes make it stale.

Tests:
  - rule-local test checks whether one rule matches or passes examples
  - top-level test checks final allow / ask / deny decisions after all sources merge

Top-level rewrite is no longer supported. cc-bash-guard never changes the
command string it evaluates or returns to Claude. Parser-backed normalization is
evaluation-only: shell -c wrappers are inspected as inner commands, absolute
paths match by basename, and AWS profile flags are parsed semantically.

Permission source merge rule:
  cc-bash-guard policy and Claude settings.json permissions are both permission
  sources. Each source returns deny, ask, allow, or abstain. Abstain means no
  matching rule. No configuration is required to choose merge behavior.

Decision order:
  deny > ask > allow > abstain. Deny always wins. An explicit ask is not
  overridden by allow from another source. The final fallback is ask only when
  all sources abstain.

Permission rule example:
  permission:
    allow:
      - command:
          name_in:
            - ls
            - pwd
            - head
            - tail
            - wc
        test:
          allow:
            - "/bin/ls -la"
            - "bash -c 'pwd'"
          abstain:
            - "rm -rf /tmp"

      - command:
          name: aws
          semantic:
            service: sts
            operation: get-caller-identity
        env:
          requires:
            - "AWS_PROFILE"
        test:
          allow:
            - "AWS_PROFILE=read-only-profile aws sts get-caller-identity"
          abstain:
            - "AWS_PROFILE=read-only-profile aws s3 ls"

E2E test example:
  test:
    allow:
      - "AWS_PROFILE=read-only-profile aws sts get-caller-identity"
    ask:
      - "unknown-tool status"

For permission predicate fields, run:
  cc-bash-guard help match

For semantic command schemas, run:
  cc-bash-guard help semantic

`)
	case "match":
		writeCommandHelp(w, "permission")
	default:
		writeUsage(w)
	}
}

func writeSemanticHelp(w io.Writer, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(w, `Semantic match schemas

Semantic matchers are command-specific.
The schema is selected by command.name.
Semantic fields live directly under command.semantic; command.name selects
which parser namespace validates those fields.
Supported commands are generated from the semantic schema registry.

Supported commands:
`)
		for _, schema := range semanticpkg.AllSchemas() {
			fmt.Fprintf(w, "  %-10s %s\n", schema.Command, schema.Description)
		}
		fmt.Fprint(w, `
Try:
  cc-bash-guard help semantic <command>
  cc-bash-guard semantic-schema --format json
  cc-bash-guard semantic-schema <command> --format json

Example:
  permission:
    deny:
      - command:
          name: git
          semantic:
            verb: push
            force: true

Notes:
  semantic.flags_contains / semantic.flags_prefixes inspect options
  recognized by the command-specific parser.

Docs:
  docs/user/SEMANTIC_SCHEMAS.md
`)
		return nil
	}
	if len(args) > 1 {
		return errors.New("usage: cc-bash-guard help semantic [command]")
	}
	schema, ok := semanticpkg.Lookup(args[0])
	if !ok {
		return fmt.Errorf("unknown semantic command %q. Supported commands: %s", args[0], strings.Join(semanticpkg.SupportedCommands(), ", "))
	}
	fmt.Fprintf(w, "Semantic schema: %s\n\n", schema.Command)
	fmt.Fprintf(w, "Description: %s\n", schema.Description)
	fmt.Fprintf(w, "Parser support: %s\n\n", schema.Parser)
	fmt.Fprint(w, "YAML path: command.semantic\n")
	fmt.Fprint(w, "Discriminator: command.name = "+schema.Command+"\n\n")
	fmt.Fprint(w, "Fields:\n")
	for _, field := range schema.Fields {
		fmt.Fprintf(w, "  %-38s %-9s %s\n", field.Name, field.Type, field.Description)
	}
	if len(schema.Notes) > 0 {
		fmt.Fprint(w, "\nBoolean field definitions and notes:\n")
		for _, note := range schema.Notes {
			fmt.Fprintf(w, "  - %s\n", note)
		}
	} else {
		fmt.Fprint(w, "\nBoolean field definitions are included in the field descriptions above.\n")
	}
	fmt.Fprint(w, "\nValidation rules:\n")
	fmt.Fprint(w, "  - permission command.semantic requires exact command.name.\n")
	fmt.Fprint(w, "  - fields are interpreted in the namespace selected by command.name.\n")
	fmt.Fprint(w, "  - unsupported fields and unsupported value types fail verify.\n")
	fmt.Fprint(w, "  - GenericParser fallback never satisfies semantic match.\n")
	if len(schema.Examples) > 0 {
		fmt.Fprint(w, "\nExamples:\n")
		for _, example := range schema.Examples {
			fmt.Fprintf(w, "  %s:\n%s\n", example.Title, indent(example.YAML, "    "))
		}
	}
	fmt.Fprint(w, "\nDocs:\n")
	fmt.Fprint(w, "  docs/user/SEMANTIC_SCHEMAS.md\n")
	if schema.Command == "aws" {
		fmt.Fprint(w, "  docs/user/AWS_GUIDELINES.md\n")
	}
	return nil
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func wantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func writeErr(w io.Writer, msg string) {
	fmt.Fprintln(w, msg)
}
