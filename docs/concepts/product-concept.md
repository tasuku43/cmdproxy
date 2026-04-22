---
title: "Product Concept: Invocation Policy Proxy"
status: proposed
date: 2026-04-22
---

# Product Concept

## 1. Purpose

This document defines the target product concept for `cmdproxy`.

`cmdproxy` is a local policy proxy that:

1. rewrites commands into policy-approved canonical forms
2. evaluates permissions on those rewritten commands

## 2. Problem

In AI-assisted command execution, many operational mistakes come from invocation
drift rather than raw capability drift.

Typical failures look like:

1. the right CLI invoked with the wrong credential shape
2. the right CLI invoked with an unsafe flag or wrapper
3. the right CLI invoked in a way that defeats the intended permission policy
4. a shell wrapper causing the true command shape to become opaque

Runtime permission systems often sit too low in the stack to express these
rules clearly. They can tell that `aws`, `git`, or `kubectl` ran, but not
whether the invocation respected the team's calling conventions.

## 3. Product Thesis

`cmdproxy` should own both command canonicalization and permission evaluation.

The key design idea is:

- users describe preferred invocation shape in one config file
- `cmdproxy` rewrites commands into that shape
- `cmdproxy` then decides `deny`, `ask`, or `allow`
- hook runners consume that result rather than acting as the primary policy
  engine

## 4. Primary Persona

**Operators of AI-agent shell execution**

- run Claude Code, shell hooks, CI wrappers, or similar systems
- want consistent invocation conventions for approved CLIs
- want flexible local permission policy without depending on tool-specific
  settings formats
- need a reviewable local tool rather than ad-hoc shell glue

## 5. Core Value Proposition

`cmdproxy` should make approved commands conform to policy-approved invocation
shape and then evaluate permissions on that canonical command.

That value appears in three concrete ways:

1. **Canonicalization**
   Rewrite valid-but-noncanonical invocations into the approved form.
2. **Permission Evaluation**
   Decide `deny`, `ask`, or `allow` after rewrite, using matcher power richer
   than a simple prefix list.
3. **Reviewability**
   Keep invocation policy declarative, testable, and portable across runtimes.

## 6. Operating Model

`cmdproxy` runs as a local CLI in front of command execution.

- the caller provides a requested invocation, usually as a raw command string
- `cmdproxy` parses that invocation internally
- ordered rewrite steps canonicalize command shape
- permission buckets are evaluated in order `deny -> ask -> allow`
- the resulting decision is returned to the caller

The mental model is closer to a local policy pipeline than to a deny-list
filter.

## 7. Pipeline Model

The target pipeline model is:

- `rewrite`: transform an invocation into a canonical, policy-approved form
- `permission.deny`: block specific rewritten command shapes
- `permission.ask`: prompt for specific rewritten command shapes
- `permission.allow`: auto-allow specific rewritten command shapes
- top-level `test`: assert the full pipeline end-to-end

The primary long-term behavior is still `rewrite`, but it is now paired with a
first-class permission phase.

## 8. Non-goals

1. Acting as a general shell interpreter or full shell AST executor
2. Providing arbitrary command macros or free-form text transformation
3. Hosting policy centrally as a network control plane
4. Replacing sandboxing or runtime isolation controls
