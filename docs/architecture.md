# peSentinel — Architecture

> Auto-updated per the AGENTS.md rule. Append changes; do not rewrite
> history. Each entry: date, summary, touched-files tree.

## Current state (2026-06-19 — kickoff)

Project scaffolded. No source code yet. Stages 1-7 planned in MVP.md
and specified in spec.md.

```
OS/
  MVP.md
  spec.md
  AGENTS.md
  opencode.json
  .gitignore
  .env.example
  docs/
    architecture.md      <- this file
  src/                    <- to be created in Stage 1
  tests/                  <- to be created in Stage 1
  data/                   <- to be created in Stage 1 (rules, baseline, audit)
```

## Changelog

### 2026-06-19 — Project kickoff
- Created MVP.md (7 stages, all features as checkboxes).
- Created spec.md (product/technical layers, Ch.14/15 mapping, PE
  schema, scoring math, edge cases from refinement pass, security
  notes).
- Created AGENTS.md (stack enforcement, code style, TCB boundary,
  error handling, testing, auto-docs rule).
- Created opencode.json (instructions, /test /lint /selfscan
  commands, permission allow-list).
- Created .gitignore (aggressive — Python, venv, env, caches, IDE,
  runtime artifacts).
- Created .env.example.
- git init + initial empty commit.
