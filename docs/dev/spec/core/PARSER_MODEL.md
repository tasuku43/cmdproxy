---
title: "Parser Model"
status: implemented
date: 2026-04-25
---

# Parser Model

## 1. Scope

This document defines how `cc-bash-proxy` turns a shell invocation into a
`Command` before permission evaluation.

Permission decisions depend on the meaning of `Command`, so parser behavior
must be stable when new CLI parsers such as `aws` or `kubectl` are added.

## 2. Layers

`Command` has two layers.

The structural layer is always present:

- `Raw`
- `Program`
- `ProgramToken`
- `Env`
- `RawWords`
- `RawOptions`
- shell shape metadata on `CommandPlan`

The semantic layer is optional and parser-specific:

- `ActionPath`
- `GlobalOptions`
- `Options`
- `Args`
- `WorkingDirectory`
- `Namespace`
- `ResourceType`
- `ResourceName`

`Parser` records the parser that returned the command. `SemanticParser` is set
only when a CLI-specific parser added semantic fields.

## 3. Parse Flow

Parsing always runs in this order:

1. parse the shell into an `Invocation`
2. run `GenericParser` to build the structural layer
3. dispatch an optional CLI-specific parser by `Program`
4. return the CLI-specific command when it accepts the base command
5. otherwise return the generic structural command

CLI-specific parsers receive `Command`, not `Invocation`. They must preserve
the structural layer and only add or refine semantic fields.

## 4. Generic Parser Contract

`GenericParser` is not a fallback semantic parser. It produces the minimum
structure needed to evaluate policies safely:

- it preserves raw words after the executable token
- it records flat raw option tokens in `RawOptions`
- it does not infer `ActionPath`
- it does not split semantic `Args`
- it does not guess option value arity

When no CLI-specific parser exists, permission evaluation can still use
`Program`, `ProgramToken`, `Env`, `RawWords`, `RawOptions`, and shell shape.
Precision may be lower, but evaluation must fail closed rather than invent
domain meaning.

## 5. CLI-Specific Parser Contract

A CLI-specific parser adds meaning for one program family.

For example, `GitParser` understands supported git global options, identifies
the git action path, and separates git command options from positional args.

Adding a new parser must not change the meaning of existing parser output or
existing raw-word matchers. It may only improve semantic precision for its own
program.

## 6. Match Semantics

Structured `match` fields are split by source:

- `command`, `command_in`, `command_is_absolute_path`, `env_requires`, and
  `env_missing` match structural data
- `args_contains` and `args_prefixes` match `RawWords`
- `subcommand` first uses semantic `ActionPath[0]` when available
- without a semantic parser, `subcommand` uses a limited structural fallback:
  the first raw word that is not option-shaped

The structural `subcommand` fallback is intentionally shallow. It does not
infer option value arity, so commands with leading options may not match as
precisely without a CLI-specific parser.

If a command has no semantic parser and a same-scope `deny` or `ask` rule uses
semantic match fields, evaluation must not continue into a broader `allow`
rule. It falls back to `ask`. This prevents removing a parser from changing a
decision from `deny` to `allow`.

Trace output must include `Parser` for every parsed command. Commands with
CLI-specific semantics also set `SemanticParser`.
