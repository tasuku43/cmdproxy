package cli

import (
	"fmt"
	"io"
)

func writeUsage(w io.Writer) {
	fmt.Fprint(w, `cc-bash-proxy

Declarative, testable command policy for AI-agent shell commands.

Typical workflow:
  1. Edit ~/.config/cc-bash-proxy/cc-bash-proxy.yml
  2. Optionally add .cc-bash-proxy/cc-bash-proxy.yaml in the project
  3. Add rewrite, permission, and E2E tests
  4. Run cc-bash-proxy verify
  5. Let Claude Code call cc-bash-proxy hook --rtk from PreToolUse

Usage:
  cc-bash-proxy <command> [flags]

Commands:
  init     create the user config and print the Claude Code hook snippet
  doctor   inspect config quality and installation state
  verify   verify config tests, trust-critical setup, and build metadata
  version  print build and source metadata for the running binary
  hook     Claude Code hook entrypoint

Help:
  cc-bash-proxy help <command>
  cc-bash-proxy <command> --help
  cc-bash-proxy help config
  cc-bash-proxy help rewrite
  cc-bash-proxy help match

Examples:
  cc-bash-proxy init
  cc-bash-proxy verify --format json
  cc-bash-proxy version --format json
  cc-bash-proxy hook --rtk
  cc-bash-proxy doctor --format json
`)
}

func writeCommandHelp(w io.Writer, command string) {
	switch command {
	case "init":
		fmt.Fprint(w, `cc-bash-proxy init

Create ~/.config/cc-bash-proxy/cc-bash-proxy.yml when it does not exist and print the
Claude Code PreToolUse hook snippet.

Usage:
  cc-bash-proxy init

Typical use:
  cc-bash-proxy init
`)
	case "doctor":
		fmt.Fprint(w, `cc-bash-proxy doctor

Inspect config validity, pipeline quality, and Claude Code hook registration.

Usage:
  cc-bash-proxy doctor [--format json]

Examples:
  cc-bash-proxy doctor
  cc-bash-proxy doctor --format json
`)
	case "verify":
		fmt.Fprint(w, `cc-bash-proxy verify

Verify the local trust-critical cc-bash-proxy setup.
This command is stricter than doctor: it fails when the config is broken, when
configured tests fail, when the effective global/local tool settings and
cc-bash-proxy policy disagree with expected E2E outcomes, or when build metadata is
missing.

Usage:
  cc-bash-proxy verify [--format json]

Examples:
  cc-bash-proxy verify
  cc-bash-proxy verify --format json
`)
	case "hook":
		fmt.Fprint(w, `cc-bash-proxy hook

Claude Code hook entrypoint.
Reads stdin JSON, evaluates the configured rewrite and permission pipeline, and
returns Claude Code hook JSON for allow, ask, deny, or error outcomes.

Usage:
  cc-bash-proxy hook [--rtk]

Options:
  --rtk   run "rtk rewrite" once after cc-bash-proxy policy evaluation and return
          the final rewritten command if it changes

Note:
  You usually do not run this manually. Edit rules and use cc-bash-proxy verify
  while authoring policy instead.
`)
	case "version":
		fmt.Fprint(w, `cc-bash-proxy version

Print build metadata for the running binary. Use this to inspect the module,
Go toolchain, and VCS information embedded in the installed executable.

Usage:
  cc-bash-proxy version [--format json]

Examples:
  cc-bash-proxy version
  cc-bash-proxy version --format json
`)
	case "config":
		fmt.Fprint(w, `cc-bash-proxy help config

Config files live at:
  - ~/.config/cc-bash-proxy/cc-bash-proxy.yml
  - ./.cc-bash-proxy/cc-bash-proxy.yaml (project-local, optional)

Top-level sections are:
  - rewrite: ordered rewrite pipeline
  - permission: deny / ask / allow buckets
  - test: end-to-end expect cases

Rewrite step example:
  rewrite:
    - match:
        command: aws
        args_contains:
          - "--profile"
      move_flag_to_env:
        flag: "--profile"
        env: "AWS_PROFILE"
      strict: true
      continue: true
      test:
        - in: "aws --profile read-only-profile s3 ls"
          out: "AWS_PROFILE=read-only-profile aws s3 ls"
        - pass: "AWS_PROFILE=read-only-profile aws s3 ls"

Permission rule example:
  permission:
    allow:
      - match:
          command: aws
          subcommand: sts
          env_requires:
            - "AWS_PROFILE"
        test:
          allow:
            - "AWS_PROFILE=read-only-profile aws sts get-caller-identity"
          pass:
            - "AWS_PROFILE=read-only-profile aws s3 ls"

E2E test example:
  test:
    - in: "aws --profile read-only-profile sts get-caller-identity"
      rewritten: "AWS_PROFILE=read-only-profile aws sts get-caller-identity"
      decision: allow

For matcher fields, run:
  cc-bash-proxy help match

For rewrite primitives, run:
  cc-bash-proxy help rewrite
`)
	case "match":
		fmt.Fprint(w, `cc-bash-proxy help match

Supported match fields:
  - command: exact executable name
  - command_in: executable must be one of these names
  - subcommand: exact first subcommand
  - args_contains: exact arg tokens that must exist
  - args_prefixes: arg tokens that must start with these prefixes
  - env_requires: env vars that must be present
  - env_missing: env vars that must be absent

Example:
  match:
    command: aws
    args_prefixes:
      - "--profile"

Pattern is still supported when shell-shape matching is easier than argv
matching.

Example:
  pattern: '^\s*cd\s+[^&;|]+\s*(&&|;|\|)'
`)
	case "rewrite":
		fmt.Fprint(w, `cc-bash-proxy help rewrite

Supported rewrite primitives:
  - unwrap_shell_dash_c: unwrap safe "bash -c 'single command'" payloads
  - unwrap_wrapper: strip safe wrappers such as env, command, exec, nohup
  - move_flag_to_env: move a flag value into an env assignment
  - move_env_to_flag: move an env assignment into a flag
  - strip_command_path: convert an absolute-path command token into its basename
  - continue: after a successful rewrite, restart evaluation from the top

Each rewrite step is an element in the top-level rewrite array and may add an
optional match block. If match is omitted, the step is considered for every
command.

Example:
  rewrite:
    - match:
        command: aws
        args_contains:
          - "--profile"
      move_flag_to_env:
        flag: "--profile"
        env: "AWS_PROFILE"
      strict: true
      continue: true
      test:
        - in: "aws --profile read-only-profile s3 ls"
          out: "AWS_PROFILE=read-only-profile aws s3 ls"
        - pass: "AWS_PROFILE=read-only-profile aws s3 ls"

Each step may set exactly one rewrite primitive.
`)
	default:
		writeUsage(w)
	}
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
