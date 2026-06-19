# peSentinel — Technical Specification

> Living document. Date each amendment at the top.
> Last amended: 2026-06-19 (initial draft + refinement pass)

---

## 1. Product Layer

### 1.1 User journey

1. Operator installs peSentinel (`pip install -e .`), creates a venv,
   optionally runs `pesentinel --init-baseline` to seed the Tripwire
   integrity DB (Stage 4).
2. Operator runs `pesentinel --file <sample.exe>` (or `.dll`/`.msi`/
   `.bin`).
3. The CLI loads `policy.yaml` (Stage 2), populates the access matrix,
   and enters the default `pipeline_core` domain.
4. The pipeline switches to each signal's least-privilege domain and
   runs the signal, auditing every access decision.
5. Signals return evidence + a per-signal verdict.
6. The scorer (Stage 5) aggregates into a final verdict
   (`benign | suspicious | malicious`) + confidence + Bayes P(I|A).
7. peSentinel prints a Rich terminal report and writes a signed JSON
   report to disk.

### 1.2 Choice points

- **Auth method for privileged ops:** challenge-response `H(pw, ch)`
  one-time password (Ch.15 §5.4). Two-factor (PIN + code book) for
  admin operations (rule-DB update, baseline reset, self-scan
  auto-fix). No password storage in plaintext — salted hashes only.
- **Reputation provider:** MalwareBazaar API (free, no key, POST
  SHA-256). VirusTotal is optional and out of v1 scope.
- **Detection paradigm:** both signature-based (YARA, Ch.15 §6.3) and
  anomaly-based (PE heuristics, Ch.15 §6.3) — "two sides of the same
  coin" per the text. ML deferred; heuristics satisfy the anomaly
  requirement.
- **Report integrity:** HMAC-SHA256 signed JSON (Stage 5); optional
  Ed25519 asymmetric signing.

---

## 2. Technical Layer (hard constraints)

| Constraint | Decision |
|---|---|
| Language | Python 3.11+ (no other languages) |
| PE parsing | `pefile` + `lief` only (no proprietary parsers) |
| Signature engine | `yara-python` (vendored community rules; no live rule download) |
| HTTP client | `requests` (sync; no async framework in v1) |
| CLI framework | `typer` + `rich` (no other TUI libs) |
| Config | `pyyaml` (policy.yaml); no .toml for runtime config |
| Crypto | `cryptography` library (HMAC, Ed25519, salted PBKDF2) |
| Tests | `pytest` + `pytest-cov`; no other test runner |
| Lint/format | `ruff` + `ruff format`; no black, no flake8 |
| Types | `mypy --strict` on `src/pesentinel/protection/`; `mypy` default elsewhere |
| Packaging | PEP 621 `pyproject.toml`; `pip install -e .` for dev |
| State | No external database server. Integrity DB + audit log are local files (SQLite optional, JSONL default) |
| Network | Outbound HTTPS to MalwareBazaar only, through the egress firewall (Stage 5). No inbound. |
| Threading | Single-threaded in v1; batch scan is sequential. Concurrency is a Stage 7 polish item. |
| Sample handling | Samples are READ-only. peSentinel never executes a sample. No sandbox execution in v1. |

---

## 3. Data Schema Drafts

peSentinel has no relational database server. Persistent state lives
in three local artifacts.

### 3.1 Integrity DB (Tripwire, Ch.15 §6.4) — `data/baseline.db`

JSON file (or SQLite if it grows). One record per monitored file.

```
Record {
  path:        str          # relative to install root
  hash:        str          # SHA-256 of file contents
  size:        int          # bytes
  mtime:       float        # epoch seconds
  attrs_mask:  int          # bitmask of monitored inode-style attrs
  recorded_at: float        # epoch seconds when baselined
}
```

Relations: none (flat key-value by path). Monitored set = all files
under `data/rules/`, the model file (if ML added later), and the
installed `pesentinel` entry-point script.

### 3.2 Audit log (Ch.15 §6.5) — `data/audit.jsonl`

Append-only JSON Lines. One record per access decision or auth event.

```
Record {
  ts:          float        # epoch seconds
  event:       str          # "access_check" | "auth_success" | "auth_failure" | "authz_deny" | "capability_grant" | "capability_revoke"
  domain:      str          # active protection domain
  subject:     str          # signal/module requesting
  object:      str          # protected resource name
  right:       str          # "READ" | "WRITE" | "EXECUTE" | "NETWORK_CALL" | "SCAN"
  decision:    str          # "allow" | "deny"
  reason:      str          # human-readable detail
  stack_annot: bool         # was a doPrivileged frame present?
}
```

### 3.3 Policy file (Ch.15 §6.1) — `policy.yaml`

Drives the access matrix + RBAC roles + scoring weights + firewall
allow-list. Schema:

```yaml
objects:
  - sample_file
  - rules_dir
  - reports_dir
  - network
  - audit_log
  - baseline_db
  - model_file
domains:
  pipeline_core:   { rights: { sample_file: [READ], reports_dir: [WRITE] } }
  hash_signal:     { rights: { sample_file: [READ], network: [NETWORK_CALL] } }
  yara_signal:     { rights: { sample_file: [READ], rules_dir: [READ] } }
  heuristic_signal:{ rights: { sample_file: [READ] } }
  reporter:        { rights: { reports_dir: [WRITE], audit_log: [WRITE] } }
  admin:           { rights: { rules_dir: [WRITE], baseline_db: [WRITE] } }
roles:
  Scanner:        [pipeline_core, hash_signal, yara_signal, heuristic_signal]
  ReputationLookup: [hash_signal]
  Reporter:       [reporter]
  Admin:          [admin]
scoring:
  hash_reputation: 0.40
  yara:            0.35
  heuristics:      0.25
  malicious_threshold: 0.60
  suspicious_threshold: 0.30
firewall:
  allow:
    - host: "mb-api.abuse.ch"
      port: 443
      scheme: https
auth:
  two_factor_for_admin: true
  code_book_size: 100
bayes:
  assumed_intrusion_rate: 0.00002   # P(I), from text example
```

---

## 4. API Surface (CLI + External)

### 4.1 CLI commands (`cli.py`, Typer)

| Command | Stage | Purpose |
|---|---|---|
| `pesentinel --file <path>` | 1 | Analyze a single PE file |
| `pesentinel --folder <dir>` | 7 | Batch analyze a directory |
| `pesentinel --report <out.json>` | 1 | Write JSON report to path |
| `pesentinel --init-baseline` | 4 | Seed the Tripwire integrity DB |
| `pesentinel --selfscan` | 6 | Run vulnerability self-scan |
| `pesentinel --verify-report <file>` | 5 | Validate a signed report |
| `pesentinel --policy <policy.yaml>` | 2 | Override default policy |
| `pesentinel --offline` | 1 | Skip all network signals |

### 4.2 MalwareBazaar API interaction

- **Endpoint:** `POST https://mb-api.abuse.ch/api/v1/`
- **Body:** `query=get_info&hash=<sha256>` (form-encoded)
- **Response:** JSON; `query_status == "ok"` with `data[]` means known
  malicious; `query_status == "hash_not_found"` means not in DB
  (not proof of benign).
- **Rate:** no documented hard limit; peSentinel throttles to
  1 req/sec to be safe. Cached per-session by SHA-256.
- **Failure handling:** network error / 5xx / timeout -> signal
  returns `unknown` (not `benign`); verdict notes offline reputation.

---

## 5. UI/UX Component Hierarchy (CLI)

```
cli.py (Typer app)
  +-- core/pipeline.py        # orchestrator
  |     +-- protection/*      # access control wraps each signal call
  |     +-- signals/*         # each runs in its own domain
  |     +-- security/audit.py # logs every decision
  +-- core/verdict.py         # aggregates + Bayes
  +-- core/report.py
        +-- Rich Panel: Verdict Header (verdict + confidence)
        +-- Rich Table: Signal Results (signal, verdict, evidence)
        +-- Rich Panel: Protection Trace (domain switches, access decisions)
        +-- Rich Panel: Bayes Analysis (P(I|A), true/false alarm rates)
        +-- Rich Panel: Windows Security Model (UAC, integrity, admin)
        +-- JSON dump (signed) to --report path
```

---

## 6. Protection Model (Chapter 14 mapping)

Each concept maps to a concrete module. This is the *substance* of the
project, not a reference.

| Ch.14 concept | Module | Implementation |
|---|---|---|
| Access matrix (§14.10) | `protection/access_matrix.py` | `AccessMatrix` keyed by (domain, object) -> set(rights). Sparse, queried both ways. |
| Access-list view (per-object) | `access_matrix.py` | `rights_for_object(obj) -> dict[domain, set[rights]]` |
| Capability-list view (per-domain) | `protection/capability.py` | `Capability` opaque object; `capabilities_for_domain(dom) -> list[Capability]` |
| Unforgeable capabilities (Ex 14.10) | `capability.py` | `__init__` only callable by `Kernel`; `__repr__` redacted; no `__copy__`; equality by identity only |
| Protection domains | `protection/domain.py` | `Domain(name, capabilities)`; `ActiveDomain` context manager for switching |
| Least privilege (Ex 14.23) | `domain.py` + policy | Each signal domain holds only the rights its signal needs (need-to-know, Ex 14.19/14.20) |
| Domain switching (§14.10) | `domain.py` | `with ActiveDomain("hash_signal"): signal.run()`; audit logs the switch |
| Stack inspection (§14.9.2, Fig 14.9) | `protection/stack_inspection.py` | `do_privileged()` annotates the current frame; `check_permission()` walks the stack for annotation or denial |
| Declarative protection (§14.9.1) | `protection/policy_bindings.py` | `@requires_capability("NETWORK_CALL")` decorator; enforced at import (load-time) and call (runtime) |
| Revocation (Ex 14.7, 14.8) | `protection/revocation.py` | `revoke(domain, object)` removes rights at runtime; ref-counted objects deleted when zero rights remain |
| RBAC roles (Solaris, §14.10) | `security/policy.py` | `roles:` in policy.yaml maps roles to domain lists; `grant_role(user, role)` |
| Type safety / unforgeable refs (§14.9.2) | `capability.py` | Capabilities are Python objects with no public constructor; only the `Kernel` singleton mints them. Document Ex 14.21 (what if annotations mutable — we prevent it). |

### Stack inspection semantics (Fig 14.9 analogue)

```
pipeline_core.gui():              # no NETWORK_CALL right
    hash_signal.get(url):         # in hash_signal domain, HAS right
        do_privileged {           # annotates frame
            network.open(host)
        }
    # get() succeeds: check_permission finds doPrivileged frame
    network.open(addr)            # direct call from gui()
    # FAILS: check_permission walks stack, hits gui() frame with no right
    # -> AccessControlException
```

---

## 7. Security Defenses (Chapter 15 mapping)

| Ch.15 concept | Module | Implementation |
|---|---|---|
| One-time / challenge-response auth (§5.4) | `security/auth.py` | `challenge()` -> random `ch`; user returns `H(pw, ch)`; verify. Never transmit `pw`. |
| Two-factor (§5.4) | `auth.py` | Admin ops require code-book OTP + PIN. "Something you have" + "something you know". |
| S/Key code book (§5.4) | `auth.py` | Generate N single-use passwords; cross off on use; protect the book. |
| Security policy (§6.1) | `security/policy.py` | `policy.yaml` is the living document; loaded at startup; drives access matrix + roles + weights + firewall. |
| Vulnerability self-scan (§6.2) | `security/selfscan.py` | `--selfscan` checks: setuid binaries, dir perms, PATH danger, checksum changes (reuses integrity), rogue listeners. |
| Signature detection (§6.3) | `signals/yara_signatures.py` | YARA rule scan -> known family signatures. |
| Anomaly detection (§6.3) | `signals/pe_heuristics.py` | Entropy/packer/import anomalies -> deviation from normal. |
| Bayes P(I\|A) (§6.3) | `core/verdict.py` | Compute from measured true-alarm and false-alarm rates per the text formula. Report in output. |
| Tripwire integrity (§6.4) | `security/integrity.py` | Baseline DB of hashes; detect added/deleted/changed; warn on shrinking logs. |
| Audit logging (§6.5) | `security/audit.py` | Append-only JSONL of every access + auth event. Anomaly hooks for strange-hour. |
| Egress firewall (§7) | `security/firewall.py` | Allow-list (host/port/scheme) from policy; NETWORK_CALL capability routes through it. |
| Application proxy (§7) | `firewall.py` | Inspect MalwareBazaar HTTP response; block malformed JSON / unexpected fields. |
| DMZ domain (§7) | `domain.py` | Untrusted samples analyzed in an isolated domain; cannot reach `reports_dir` or `audit_log` directly. |
| TCSEC C2 (§8) | `security/classifier_tcsec.py` | Individual-level ACL (per-user rights), selective audit, object-reuse protection (cleared on release). TCB = protection core. |
| Windows security-model reader (§9) | `signals/windows_model.py` | Parse PE manifest: requestedExecutionLevel (UAC), integrity level, admin requirement. Report in verdict. |
| Signed reports (§10) | `security/crypto.py` | HMAC-SHA256 over JSON; optional Ed25519. `--verify-report` validates. |
| Salted credentials (Ex 15.3/4) | `crypto.py` | PBKDF2-HMAC with random salt; salt stored alongside hash; no plaintext passwords. |

---

## 8. PE Feature Schema (heuristic signal)

Extracted from each sample by `signals/pe_heuristics.py`:

```
PEFeatures {
  is_pe:              bool
  architecture:       str       # x86 / x64 / unknown
  subsystem:          str       # GUI / CONSOLE / ...
  compile_timestamp:  float
  imphash:            str
  sections: [
    { name: str, vsize: int, raw_size: int, entropy: float, is_packed: bool }
  ]
  imports: [str]                # API names
  suspicious_imports: [str]     # subset flagged by heuristic
  has_manifest:        bool
  uac_level:           str      # asInvoker / requireAdmin / highestAvailable
  integrity_level:     str      # untrusted/low/medium/high/system or "none"
  requires_admin:      bool
  packer_detected:     str      # "UPX" / "none" / "unknown"
  max_section_entropy: float
  entropy_anomaly:     bool
}
```

Suspicious import sets (flagged):
- Process injection: `VirtualAllocEx`, `WriteProcessMemory`,
  `CreateRemoteThread`, `NtUnmapViewOfSection`, `QueueUserAPC`
- Crypto: `CryptAcquireContext`, `BCryptOpenAlgorithmProvider`
  (ransomware indicator when combined with high file-write imports)
- Networking: `WSAStartup`, `InternetOpen`, `URLDownloadToFile`
- Anti-analysis: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`

---

## 9. Scoring Math

### 9.1 Verdict aggregation (Stage 5)

Each signal returns `(verdict, confidence)` where verdict in
`{benign, suspicious, malicious, unknown}` and confidence in `[0,1]`.

```
score = sum( weight[s] * signal_value(s) * confidence[s]
             for s in signals )
where signal_value = {benign:0, unknown:0, suspicious:0.5, malicious:1}

final_verdict =
  "malicious"  if score >= malicious_threshold      # 0.60
  "suspicious" if score >= suspicious_threshold      # 0.30
  "benign"     otherwise
```

Weights from `policy.yaml` (§3.3). `unknown` signals contribute 0
(neither clears nor condemns).

### 9.2 Bayes false-alarm analysis (Ch.15 §6.3)

```
P(I|A) = P(I) * P(A|I) / ( P(I)*P(A|I) + P(~I)*P(A|~I) )
```

peSentinel reports `P(I|A)` alongside each verdict using:
- `P(I)` = `policy.bayes.assumed_intrusion_rate` (default 0.00002)
- `P(A|I)` = measured true-alarm rate (malicious samples flagged)
- `P(A|~I)` = measured false-alarm rate (benign samples flagged)

Rates are tracked across the session in `core/verdict.py` and
reported in the Bayes panel. Exercise 15.15 is encoded as a unit test.

---

## 10. Edge Cases & Race Conditions

> Filled in by the refinement pass (see §12). Each item is a required
> behavior, not a nice-to-have.

### 10.1 Sample edge cases
- **MZ header but not valid PE:** `pe_heuristics` returns
  `is_pe=False`; pipeline skips PE signals, runs only hash reputation;
  verdict notes "not a valid PE". Never crash on a truncated header.
- **Corrupted PE header:** `pefile` raises; caught and recorded as
  `unknown` with reason "parse_error". High entropy in a corrupt
  header alone is NOT a verdict.
- **MSI files:** treated as PE only if they contain an embedded PE;
  otherwise string-scan fallback (Stage 4). Flagged as
  "msi_non_pe_fallback".
- **Empty / zero-byte file:** hash still computed (SHA-256 of empty
  is well-known); reputation query returns not-found; verdict
  "benign" with low confidence + note "empty file".
- **File too large (>256 MB):** PE parse skipped (DoS guard);
  reputation-only path. Logged as "oversize_skip".
- **Symlink / hardlink sample:** resolve to real path; record both
  paths in audit log to prevent evasion via link indirection.

### 10.2 Protection-core race conditions
- **Concurrent domain switches:** v1 is single-threaded so no data
  race. Document this. If Stage 7 adds threading, `ActiveDomain`
  becomes thread-local and the access matrix gains a `Lock`.
- **Revocation during a signal run:** if a capability is revoked
  mid-signal, the signal's *next* access check fails with
  `AccessControlException`; the signal must handle it gracefully
  (return `unknown`, not crash). This is the Ex 14.7/14.8 scenario.
- **Capability forgery attempt:** if any code outside `Kernel` tries
  to construct a `Capability`, raise `CapabilityForgeError` and audit
  it as `authz_deny` with reason "forgery_attempt".

### 10.3 Network edge cases
- **Offline / DNS failure / timeout:** `hash_reputation` returns
  `unknown` with reason; never `benign`. Verdict notes offline mode.
  `--offline` flag skips the call entirely.
- **MalwareBazaar rate-limit / 5xx:** exponential backoff (max 3
  retries, 1s/2s/4s); then `unknown`. Do not hammer the API.
- **Unexpected response shape:** firewall/proxy validates JSON
  schema before passing to the signal; malformed -> `unknown` +
  audit `authz_deny` reason "malformed_response".
- **Sample hash collision (SHA-256):** negligible, but reputation
  match must be cross-checked by reporting the matched signature
  name; a hash-only verdict is always `suspicious`, never
  `malicious`, unless corroborated.

### 10.4 Integrity / Tripwire edge cases
- **Baseline missing on first run:** `--init-baseline` required; if
  missing, scan proceeds but logs "no_baseline" and integrity signal
  returns `unknown`.
- **Baseline tampered (shrinking file / changed hash):** integrity
  signal returns `suspicious` with reason "rules_tampered"; YARA
  results are flagged as untrusted.
- **Log file that legitimately grows:** integrity monitor ignores
  `audit_log` and `audit.jsonl` mtime/hash (they are append-only by
  design); only flags *shrinking* logs (per the Tripwire box).

### 10.5 Auth edge cases
- **Wrong OTP 3x:** lock out the admin op for the session; audit
  `auth_failure` x3 + `authz_deny`. Do not lock the whole tool
  (detection still runs unprivileged).
- **Code book exhausted:** refuse admin op; audit; require
  regeneration.
- **`doPrivileged` without the right:** `check_permission` throws
  `AccessControlException` (mirrors Java semantics exactly).

---

## 11. Security Notes

- **Samples are untrusted.** peSentinel never executes, maps, or
  loads a sample as code. Only `pefile`/`lief` parse (read-only).
  No `subprocess` on a sample. No `mmap` with exec.
- **Path traversal:** sample path and report path are normalized and
  confined to the operator-provided paths; reports cannot overwrite
  `policy.yaml`, the integrity DB, or source files.
- **Audit log integrity:** append-only; the `reporter` domain has
  `WRITE` but no `DELETE`/`OVERWRITE` right (enforced by access
  matrix). A separate signed-hash chain (Stage 5 crypto) detects
  tampering.
- **Secrets:** no secrets in code. `policy.yaml` holds no passwords
  (only salted hashes if any). `.env` holds optional VirusTotal key
  (out of v1). `.env.example` documents placeholders.
- **Supply chain:** YARA rules are vendored at a pinned commit; no
  live download. `awesome-lists` CSVs vendored similarly.
- **DoS:** file-size cap (§10.1), rate-limit on API, no recursive
  archive extraction in v1.
- **TCB:** the `protection/` package is the Trusted Computing Base
  (Ch.15 §8). It must not import from `signals/` or `security/`
  (no circular trust). `mypy --strict` enforces boundary types.
- **Ex 14.21 (mutable stack annotations):** the doPrivileged
  annotation is stored in a frame-local that user code cannot
  reach (no public API to mutate it); documented + tested.
- **Ex 14.24 (least-privilege still fails):** a signal with
  `READ sample` + `NETWORK_CALL` could exfiltrate the sample bytes.
  This is documented as a known limitation; the firewall allow-list
  limits exfiltration to MalwareBazaar only, and the DMZ domain
  prevents reaching `reports_dir` from the sample domain.

---

## 12. Refinement pass (2026-06-19)

> Self-review of the draft for edge cases, race conditions, and
> missing security controls. Findings integrated into §10 and §11
> above. Summary of what was added by refinement:

1. **Added §10.1 sample-size DoS guard** — original draft had no
   upper bound; a 2GB sample could OOM the parser. Added 256MB cap.
2. **Added §10.1 symlink indirection** — samples could evade audit
   via links; now resolved + both paths logged.
3. **Added §10.3 hash-collision cross-check** — SHA-256 match alone
   is `suspicious`, not `malicious`, without a corroborating
   signature name. Prevents over-trusting reputation.
4. **Added §10.4 shrinking-log detection** — the Tripwire box
   explicitly calls out shrinking logs; was missing. Now monitored.
5. **Added §10.2 revocation-mid-signal graceful handling** —
   revoking a capability while a signal runs must not crash the
   pipeline; signal returns `unknown`.
6. **Added §10.2 capability forgery audit event** — `authz_deny`
   with reason `forgery_attempt`; was implicit, now explicit +
   tested.
7. **Added §11 TCB import-direction rule** — `protection/` must not
   import `signals/` or `security/`; prevents circular trust. Enforced
   by `mypy --strict` and a lint test.
8. **Added §10.5 code-book exhaustion + 3x lockout** — auth
   edge cases were under-specified.
9. **Added §10.3 malformed-response schema validation** — the proxy
   must validate MalwareBazaar JSON shape, not just pass bytes.
10. **Added §11 path-traversal confinement** — report paths cannot
    overwrite policy/integrity/source.
11. **Clarified §9.1 `unknown` contributes 0** — original draft was
    ambiguous whether unknown clears or condemns; it does neither.
12. **Added §10.4 no-baseline graceful path** — integrity signal
    returns `unknown` (not crash) when baseline absent.

---

## 13. Open questions (none blocking Stage 1)

- Q: SQLite vs JSONL for audit log at scale? -> decide in Stage 6
  when self-scan measures audit growth.
- Q: Ed25519 key storage? -> Stage 5; default to a generated keypair
  in `data/keys/` (gitignored), with `--import-key` for external.
- Q: Windows-model reader for .dll/.msi manifests (not just .exe)?
  -> Stage 3; `lief` exposes manifest for DLLs/MSI where present.
