# peSentinel — Architecture

> Auto-updated per the AGENTS.md rule. Append changes; do not rewrite
> history. Each entry: date, summary, touched-files tree.

## Current state (2026-06-19 — Stage 2 delivered)

Stages 1-2 complete: protection core + policy/audit/auth.
96 tests passing, ruff/mypy clean.

```
OS/
  ... (Stage 1 files unchanged)
  data/
    policy.yaml               # the living security document (§6.1)
    rules/                    # (empty; YARA rules arrive in Stage 4)
  src/pesentinel/security/    # Ch.15 defenses (imports protection/, not vice versa)
    __init__.py
    policy.py                 # load_policy + apply_policy + RBAC roles (§6.1)
    audit.py                  # JsonlAuditSink + is_strange_hour (§6.5)
    auth.py                   # challenge-response + CodeBook + AuthService (§5.4)
  tests/
    ... (Stage 1 tests)
    test_policy.py
    test_audit.py
    test_auth.py
    test_integration_stage2.py
```

## Changelog

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
