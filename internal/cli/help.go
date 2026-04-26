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
  cc-bash-guard init
  edit ~/.config/cc-bash-guard/cc-bash-guard.yml
  cc-bash-guard verify
  cc-bash-guard doctor
  add the printed PreToolUse Bash snippet to Claude Code settings

Usage:
  cc-bash-guard <command> [flags]

Commands:
  init     create the user config and print the Claude Code hook snippet
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
  Decision order is deny > ask > allow; unmatched commands fall back to ask.
  cc-bash-guard evaluates commands but does not rewrite them.

Learn more:
  cc-bash-guard help init
  cc-bash-guard help config
  cc-bash-guard help permission
  cc-bash-guard help semantic
  cc-bash-guard help semantic git
  cc-bash-guard help examples
  cc-bash-guard help troubleshoot

Examples:
  cc-bash-guard init
  cc-bash-guard verify
  cc-bash-guard semantic-schema --format json
  cc-bash-guard hook

Docs:
  docs/user/QUICKSTART.md
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
	case "init":
		fmt.Fprint(w, `cc-bash-guard init

Create ~/.config/cc-bash-guard/cc-bash-guard.yml when it does not exist and print the
Claude Code PreToolUse hook snippet.

Usage:
  cc-bash-guard init

What it does:
  - creates a starter deny rule and test case when the config file is missing
  - prints the user config path
  - prints the Claude Code PreToolUse Bash hook snippet

After init:
  cc-bash-guard init
  edit ~/.config/cc-bash-guard/cc-bash-guard.yml
  cc-bash-guard verify
  add the printed snippet to ~/.claude/settings.json
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
  cc-bash-guard verify [--format json]

Examples:
  cc-bash-guard verify
  cc-bash-guard verify --format json
`)
	case "hook":
		fmt.Fprint(w, `cc-bash-guard hook

Claude Code hook entrypoint.
Reads stdin JSON, parses the command, evaluates permission policy, and
returns Claude Code hook JSON for allow, ask, deny, or error outcomes.

Usage:
  cc-bash-guard hook [--auto-verify]

Options:
  --auto-verify  regenerate verified hook artifacts when they are missing or stale

Note:
  You usually do not run this manually. Edit rules and use cc-bash-guard verify
  while authoring policy instead. Without --auto-verify, the hook fails closed
  when verified artifacts are missing or stale. --auto-verify is convenient, but
  it lets hook-time config changes become active without a separate review step.

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
  command   Match a command by name and, when supported, command-specific semantic fields.
  env       Match environment variables required or missing for the invocation.
  patterns  Match the raw command string with one or more regular expressions.

Valid combinations:
  command
  command + env
  command + semantic
  command + semantic + env
  patterns
  patterns + env
  env

When to use each matcher:
  Use command.semantic for commands listed by cc-bash-guard help semantic.
  The semantic schema is selected by command.name.
  Use patterns for commands without semantic support or for raw regex fallbacks.
  Use env when a rule depends on variables such as AWS_PROFILE.
  Put rules under permission.deny, permission.ask, or permission.allow.
  Do not combine command and patterns in the same rule.

Example:
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
        patterns:
          - "^ls(\\s|$)"
          - "^pwd$"

Docs:
  docs/user/PERMISSION_SCHEMA.md
`)
	case "examples":
		fmt.Fprint(w, `cc-bash-guard help examples

Copyable permission policy examples using the current rule shape.

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
        patterns:
          - "^ls(\\s|$)"
          - "^pwd$"

Unknown command fallback:
  permission:
    ask:
      - name: tool preview
        patterns:
          - "^my-tool\\s+preview(\\s|$)"

Docs:
  docs/user/EXAMPLES.md
`)
	case "troubleshoot":
		fmt.Fprint(w, `cc-bash-guard help troubleshoot

Common checks:

Verified artifact missing or stale:
  Run cc-bash-guard verify after editing policy. The hook fails closed when the
  verified artifact is missing or stale unless hook --auto-verify is configured.

Unsupported semantic field:
  Run cc-bash-guard help semantic <command> or
  cc-bash-guard semantic-schema <command> --format json. If verify reports an
  unknown key, use the current permission shape: command, env, and patterns.

Command has no semantic schema:
  Use patterns for raw regex rules. Semantic matching only works for commands
  listed by cc-bash-guard help semantic.

All permission sources abstained:
  The final result is ask. Add an allow, ask, or deny rule when you want an
  explicit decision.

Regex pattern not matching:
  patterns match the raw command string. Anchor carefully and escape backslashes
  for YAML double-quoted strings, or use single-quoted YAML strings.

AWS profile style:
  Prefer AWS_PROFILE=myprof aws eks list-clusters in project guidance. The AWS
  parser can still evaluate profile, service, and operation semantically.

Command not being rewritten:
  cc-bash-guard evaluates commands but does not rewrite them. Parser-backed
  normalization is evaluation-only.

Docs:
  docs/user/TROUBLESHOOTING.md
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
  - permission: deny / ask / allow buckets
  - test: end-to-end expect cases

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
          pass:
            - "AWS_PROFILE=read-only-profile aws s3 ls"

E2E test example:
  test:
    - in: "AWS_PROFILE=read-only-profile aws sts get-caller-identity"
      decision: allow

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
