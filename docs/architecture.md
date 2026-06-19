# peSentinel — Architecture

> Auto-updated per the AGENTS.md rule. Append changes; do not rewrite
> history. Each entry: date, summary, touched-files tree.

## Current state (2026-06-19 — Stage 6 delivered)

Stages 1-6 complete: full protection + security + detection + self-
defense + TCSEC classification. 155 tests passing, ruff/mypy clean.

```
  src/pesentinel/security/
    selfscan.py               # Stage 6: vulnerability self-scan (§6.2)
    classifier_tcsec.py       # Stage 6: TCSEC C2 self-classification (§8)
  tests/
    test_selfscan.py
    test_tcsec.py
```

## Changelog

### 2026-06-19 — Stage 6 delivered
- `feat(security)`: selfscan.py — vulnerability self-scan checking
  setuid binaries, world-writable dirs, PATH dangers, checksum
  changes (reuses integrity.py). Implements Ch.15 §6.2 checklist.
- `feat(security)`: classifier_tcsec.py — TCSEC self-classification
  targeting C2. Documents TCB = protection core. Verifies C2
  requirements: individual ACL, selective audit, TCB self-protection,
  object reuse. Ch.15 §8.
- `test`: 155 tests (11 new), all green.
- MVP Stage 6 checkboxes flipped to [x]; Current Stage -> 7.

### 2026-06-19 — Stage 5 delivered
- `feat(signals)`: scorer.py — weighted aggregation of signal outputs
  with floor logic (2+ malicious -> malicious; 1 malicious or any
  suspicious -> at least suspicious). Weights from policy.yaml (§9.1).
- `feat(security)`: firewall.py — egress allow-list (host/port/scheme),
  application-proxy response validation (§7).
- `feat(security)`: crypto.py — HMAC-SHA256 report signing, Ed25519
  asymmetric signing, PBKDF2 salted credential hashing (§10, Ex 15.3/4).
- `test`: 144 tests (23 new), all green.
- MVP Stage 5 checkboxes flipped to [x]; Current Stage -> 6.

### 2026-06-19 — Stage 4 delivered
- `feat(signals)`: yara_signatures.py — compiles YARA rules from
  data/rules/, scans sample, maps matches to verdict. The signature
  half of Ch.15 §6.3.
- `feat(security)`: integrity.py — Tripwire baseline DB (SHA-256
  signatures), detects added/deleted/changed/shrinking files (§6.4).
- `feat(core)`: bayes_pia() — Bayes' theorem P(I|A) computation
  (§6.3). Includes textbook example and Ex 15.15 as tests.
- `chore`: added yara-python dep. Synthetic test YARA rule vendored.
- `test`: 121 tests (14 new), all green.
- MVP Stage 4 checkboxes flipped to [x]; Current Stage -> 5.

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
