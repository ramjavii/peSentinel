# peSentinel — Architecture

> Auto-updated per the AGENTS.md rule. Append changes; do not rewrite
> history. Each entry: date, summary, touched-files tree.

## Current state (2026-06-19 — Stage 1 delivered)

Stage 1 complete: protection core (Ch.14 TCB) + hash reputation signal.
76 tests passing, ruff/mypy clean.

```
OS/
  MVP.md
  spec.md
  AGENTS.md
  opencode.json
  .gitignore
  .env.example
  plan.md                      # Stage 1 plan (feature-loop)
  pyproject.toml
  docs/
    architecture.md
  src/
    pesentinel/
      __init__.py
      cli.py                   # Typer entrypoint: --file, --report, --offline
      protection/              # TCB (Ch.14) — mypy strict, no signals/security imports
        __init__.py
        types.py               # Right, Verdict, EventKind enums + exceptions
        capability.py          # unforgeable Capability + Kernel-only minting (Ex 14.10)
        access_matrix.py       # sparse access matrix + access-list/capability-list views
        domain.py              # ActiveDomain context manager + AuditSink protocol
        stack_inspection.py    # do_privileged + check_permission (Fig 14.9)
        policy_bindings.py     # @requires_capability decorator (declarative, §9.1)
        revocation.py          # runtime revoke + ref-counted orphan tracking (Ex 14.7/8)
        kernel.py              # ProtectionKernel facade (the TCB API)
      signals/
        __init__.py
        hash_reputation.py     # SHA-256 + MalwareBazaar, least-priv domain
      core/
        __init__.py
        verdict.py             # SignalResult + AggregatedVerdict dataclasses
        pipeline.py            # orchestrates domain switch -> signal -> aggregate
        report.py              # Rich terminal report
  tests/
    __init__.py
    conftest.py                # fixtures: kernel, benign_sample, empty_sample
    test_protection_types.py
    test_capability.py
    test_access_matrix.py
    test_domain.py
    test_stack_inspection.py
    test_policy_bindings.py
    test_revocation.py
    test_kernel.py
    test_hash_reputation.py
    test_verdict.py
    test_pipeline.py
    test_report.py
    test_cli.py
    test_tcb_boundary.py       # enforces protection/ imports nothing from signals/security/core
    test_integration_stage1.py # end-to-end benign + mocked-malicious + CLI report
  data/
    rules/                     # (empty; YARA rules arrive in Stage 4)
```

## Changelog

### 2026-06-19 — Stage 1 delivered
- `feat(protection)`: protection core (access matrix, capabilities,
  domains, stack inspection, declarative decorators, revocation,
  kernel facade) — implements Ch.14 §10, §9.1, §9.2, Ex 14.1/7/8/10/21.
- `feat(signals)`: hash reputation signal (SHA-256 + MalwareBazaar)
  running in a least-privilege domain.
- `feat(core)`: pipeline orchestrator, verdict aggregation, Rich
  report, Typer CLI (`--file`, `--report`, `--offline`).
- `test`: 76 tests (unit + TCB boundary + integration), all green.
- `chore`: pyproject.toml, venv, ruff/pytest/mypy config.
- MVP Stage 1 checkboxes flipped to `[x]`; Current Stage -> 2.
