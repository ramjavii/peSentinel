# peSentinel — Architecture

> Auto-updated per the AGENTS.md rule. Append changes; do not rewrite
> history. Each entry: date, summary, touched-files tree.

## Current state (2026-06-19 — Stage 3 delivered)

Stages 1-3 complete: protection core + policy/audit/auth + PE heuristics.
107 tests passing, ruff/mypy clean.

```
  src/pesentinel/signals/
    hash_reputation.py         # Stage 1
    pe_heuristics.py           # Stage 3: entropy/packer/imports/imphash (§6.3 anomaly)
    windows_model.py           # Stage 3: UAC/integrity/admin from PE manifest (§15.9)
  tests/
    ... (Stages 1-2)
    test_pe_heuristics.py
    test_windows_model.py
    test_integration_stage3.py
```

## Changelog

### 2026-06-19 — Stage 3 delivered
- `feat(signals)`: pe_heuristics.py — per-section entropy, packer
  detection (UPX), suspicious Win32 imports (injection/crypto/
  networking/anti-analysis), imphash, section-name anomalies. The
  anomaly-detection half of Ch.15 §6.3.
- `feat(signals)`: windows_model.py — reads PE manifest for UAC
  requestedExecutionLevel, integrity level, admin requirement, DLL
  hardening flags. Implements §15.9 (the Windows security model).
- `chore`: added pefile + lief deps.
- `test`: 107 tests (11 new), all green. Synthetic PE fixture.
- MVP Stage 3 checkboxes flipped to [x]; Current Stage -> 4.

### 2026-06-19 — Stage 2 delivered
- `feat(security)`: policy.py (load + apply policy.yaml to access
  matrix, RBAC roles — Ch.15 §6.1).
- `feat(security)`: audit.py (JsonlAuditSink append-only log, read-
  back, strange-hour anomaly hook — §6.5).
- `feat(security)`: auth.py (challenge-response H(pw,ch), S/Key
  CodeBook, two-factor AuthService with 3x lockout — §5.4, Ex 10.5).
- `feat(cli)`: CLI now loads policy.yaml at startup, wires
  JsonlAuditSink, --policy flag.
- `chore`: added pyyaml + cryptography deps.
- `test`: 96 tests (20 new), all green.
- MVP Stage 2 checkboxes flipped to [x]; Current Stage -> 3.

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
