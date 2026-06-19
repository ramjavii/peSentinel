# Stage 2 — Implementation Plan

> feature-loop Phase 2. Pre-approved by user ("loop if needed").

## Micro-feature

Stage 2 = "Policy, Audit, Authentication" (MVP.md). Chapter 15
defenses begin wrapping the Chapter 14 kernel:
- §6.1 security policy file drives the access matrix + RBAC roles
- §6.5 audit logging of every access decision + auth event
- §5.4 one-time / challenge-response authentication + two-factor +
  S/Key code book for privileged (admin) operations

## 1. File targets

New files:
```
src/pesentinel/security/
  __init__.py
  policy.py       # load policy.yaml -> AccessMatrix + RBAC roles
  audit.py        # AuditSink impl: JSONL append-only log
  auth.py         # challenge-response H(pw,ch), two-factor, S/Key
data/policy.yaml  # default policy file (the living document, §6.1)
tests/
  test_policy.py
  test_audit.py
  test_auth.py
  test_integration_stage2.py
```

Modified:
```
src/pesentinel/protection/kernel.py   # accept AuditSink in constructor (already does)
src/pesentinel/cli.py                 # load policy.yaml at startup, wire audit sink
```

## 2. Precise modifications

### security/policy.py
- `PolicyConfig` dataclass: objects, domains, roles, scoring,
  firewall, auth, bayes sections
- `load_policy(path: Path) -> PolicyConfig`: parse YAML
- `apply_policy(kernel, policy)`: populate AccessMatrix grants +
  register RBAC roles
- `RIGHT_NAMES`: map str -> Right enum
- Returns the parsed config for use by later stages (scoring,
  firewall, auth)

### security/audit.py
- `JsonlAuditSink` implements `AuditSink` protocol from
  `protection/domain.py`
- `__init__(log_path: Path)`: open for append
- `record(...)`: write one JSON line (ts, event, domain, subject,
  obj, right, decision, reason, stack_annot)
- Thread-safe via a lock (even though v1 is single-threaded; future-
  proofing + matches §6.5 "structured")
- `AuditReader` class: read back records for the protection trace
  panel + anomaly detection
- Strange-hour hook: `is_strange_hour(ts) -> bool` (outside 8am-8pm
  local -> flagged)

### security/auth.py
- `challenge() -> str`: generate random challenge `ch` (hex)
- `compute_response(pw: str, ch: str) -> str`: H(pw, ch) = HMAC-
  SHA256(pw, ch) hex
- `verify(pw: str, ch: str, response: str) -> bool`
- `CodeBook` class: S/Key-style list of N single-use OTPs
  - `generate(seed: bytes, n: int) -> CodeBook`: hash chain
  - `use_next() -> str | None`: pop next OTP, mark used
  - `is_exhausted() -> bool`
  - `remaining() -> int`
- `TwoFactorAuth`:
  - `verify(pin: str, otp: str, codebook: CodeBook) -> bool`
  - "something you know" (PIN) + "something you have" (OTP from
    codebook)
- `AuthService`:
  - `authenticate_admin(pin, otp) -> bool`: two-factor for admin ops
  - On 3 failures: lockout for session (Ex 10.5)
  - Audit auth_success / auth_failure events

### data/policy.yaml
- The default living document (§6.1). Matches spec §3.3 schema.

### cli.py changes
- At startup: load policy.yaml (default `data/policy.yaml` or `--policy`)
- Create `JsonlAuditSink(data/audit.jsonl)`, pass to `ProtectionKernel(audit=sink)`
- `apply_policy(kernel, policy)` to populate the matrix
- The hash_signal grants now come from policy, not hardcoded
- New flag `--policy <path>` to override default

## 3. Tests
- `test_policy.py`: load policy.yaml, verify objects/domains/rights
  parsed; apply to kernel, verify matrix populated; RBAC role lookup
- `test_audit.py`: record writes JSONL; read back; strange-hour
  detection; AuditSink protocol satisfied
- `test_auth.py`: challenge-response round-trip; wrong response
  fails; codebook generation + use_next + exhaustion; two-factor
  success/failure; 3x lockout
- `test_integration_stage2.py`: CLI loads policy, audit log written,
  privileged op (simulated admin) fails without auth

## 4. Risks
- TCB boundary: security/ may import protection/, NOT vice versa.
  policy.py imports kernel/types — OK. audit.py implements the
  AuditSink Protocol defined in protection/domain.py — OK (Protocol
  satisfaction doesn't create an import dependency from protection).
- mypy: security/ uses default mypy (not strict) — lower risk.
- pyyaml must be added to pyproject deps.
- cryptography needed for HMAC — already planned in spec, add dep.

## 5. MVP impact
Flips Stage 2 checkboxes to [x]. Current Stage -> 3.
