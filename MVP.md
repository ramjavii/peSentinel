# peSentinel — MVP Plan

## Overview

peSentinel is a command-line malware analyzer for Windows PE files
(`.exe`, `.dll`, `.msi`, `.bin`). Its *application* is malware detection
(hash reputation, YARA signatures, PE heuristics), but its *substance*
is a miniature operating-system protection and security system that
implements the core concepts of **Chapter 14 (Protection)** and
**Chapter 15 (Security)** of the OS course text. Detection signals run
as least-privilege subjects inside an access-control kernel; security
defenses (authentication, policy, auditing, firewalling, integrity
checking, vulnerability self-scan, TCSEC classification) wrap the
kernel and its outputs. The project is broad-but-shallower: every
selected chapter concept is present, working, and tested, but not
production-hardened.

Audience: an Operating Systems course project that must demonstrate
mastery of protection and security mechanisms, with a real, useful
detection tool as the worked application.

## Tech Stack

- **Language:** Python 3.11+
- **PE parsing:** `pefile` + `lief` (headers, imports, sections,
  resources, imphash, manifest/UAC)
- **Signature engine:** `yara-python` (community rule packs)
- **Hash reputation:** `requests` -> MalwareBazaar API (free, no key)
- **ML (deferred):** not in scope for v1; PE heuristics serve as the
  anomaly-detection signal instead
- **CLI:** `typer` + `rich` (TUI, tables, panels)
- **Crypto:** `cryptography` (HMAC-signed reports, salted hashing)
- **Config:** `pyyaml` (policy.yaml)
- **Tests:** `pytest` + `pytest-cov`
- **Lint / format:** `ruff` + `ruff format`
- **Type checking:** `mypy` (strict on the protection core)
- **Packaging:** `pyproject.toml` (PEP 621), `pip install -e .`
- **Deployment target:** Linux dev host (analysis of Windows samples);
  Python venv recommended

## Features

### Detection (the application)
- [ ] Hash a sample (SHA-256) and query MalwareBazaar for known-malware reputation
- [ ] Parse Windows PE files: headers, imports, sections, resources, imphash
- [ ] Compute per-section entropy and flag high-entropy / packed sections
- [ ] Detect common packers (UPX et al.) via section-name and entropy heuristics
- [ ] Flag suspicious Win32 imports (process injection, crypto, networking)
- [ ] Report imphash anomalies and section-name anomalies
- [ ] Scan samples with vendored YARA community rule packs
- [ ] Map YARA matches to malware family + severity
- [ ] Read PE manifest for UAC requestedExecutionLevel, integrity level, admin requirement (Ch.15 §9)
- [ ] Combine all signals into a weighted verdict: benign | suspicious | malicious
- [ ] Produce a confidence score and a human-readable evidence list
- [ ] Compute and report Bayes P(I|A) from measured true/false-alarm rates (Ch.15 §6.3)
- [ ] Emit a JSON report and a Rich-rendered terminal report
- [ ] Support single-file and batch/folder scanning

### Protection core — Chapter 14 (the TCB)
- [ ] Access matrix model: objects x domains x rights, separable policy from mechanism
- [ ] Access-list view (per-object) of the access matrix
- [ ] Capability-list view (per-domain) of the access matrix
- [ ] Mint unforgeable capability objects (opaque, kernel-only creation)
- [ ] Protection domains with per-domain least-privilege capability sets
- [ ] Domain switching as the pipeline dispatches each signal
- [ ] Stack inspection: privileged ops require a doPrivileged-style annotation on the call stack
- [ ] Declarative protection via decorators / type annotations (@requires_capability)
- [ ] Enforcement at load time (compiler-style) and runtime (kernel-style)
- [ ] Revocation of capabilities at runtime
- [ ] Reference-counted object deletion when all rights are removed (Ex 14.8)
- [ ] RBAC: map domains to roles (Scanner, ReputationLookup, Reporter) via policy file
- [ ] Demonstrate need-to-know principle (each signal sees only what it needs)

### Security defenses — Chapter 15
- [ ] One-time / challenge-response authentication: H(pw, ch) for privileged ops (§5.4)
- [ ] Two-factor authentication for admin operations (something you have + know)
- [ ] S/Key-style code book of single-use passwords (§5.4)
- [ ] Security policy file (policy.yaml) as living document driving the access matrix (§6.1)
- [ ] Vulnerability self-scan (--selfscan): setuid, dir perms, PATH, checksum changes, rogue listeners (§6.2)
- [ ] Signature-based detection via YARA (§6.3)
- [ ] Anomaly-based detection via PE heuristics (§6.3)
- [ ] Bayes false-alarm analysis reported in output (§6.3)
- [ ] Tripwire integrity DB for rules, model, and binary; added/deleted/changed detection (§6.4)
- [ ] Audit logging of every access decision, auth success/failure, authz deny (§6.5)
- [ ] Egress firewall: allow-list for network capability (MalwareBazaar host/port only) (§7)
- [ ] Application-proxy-style inspection of HTTP responses (§7)
- [ ] DMZ-style domain for untrusted samples (§7)
- [ ] TCSEC self-classification targeting C2 (individual ACL + selective audit + object reuse) (§8)
- [ ] Document the Trusted Computing Base (TCB) = protection core (§8)
- [ ] HMAC / asymmetric-signed JSON reports (§10)
- [ ] Salted hashing of any stored credentials (Ex 15.3/15.4)

## Implementation Stages

### Stage 1 — Protection Core + Hash Reputation Signal
The Chapter 14 access-control kernel is built first so every later
signal is sandboxed from day one. A single detection signal (hash
reputation via MalwareBazaar) exercises the kernel end-to-end.

- [x] Project scaffolding: pyproject.toml, src/pesentinel package layout, venv, ruff/pytest config
- [x] `protection/access_matrix.py`: AccessMatrix class (objects x domains x rights)
- [x] `protection/capability.py`: unforgeable Capability objects, kernel-only minting
- [x] `protection/domain.py`: Domain class, domain switching, active-domain tracking
- [x] `protection/stack_inspection.py`: doPrivileged annotation + call-stack walk
- [x] `protection/policy_bindings.py`: @requires_capability decorator (declarative protection)
- [x] `protection/revocation.py`: runtime revoke + ref-counted object deletion
- [x] `signals/hash_reputation.py`: SHA-256 + MalwareBazaar query, runs in a least-priv domain
- [x] `core/pipeline.py`: orchestrate domain switch -> signal -> collect verdict
- [x] `core/verdict.py`: minimal verdict struct (benign/suspicious/malicious + evidence)
- [x] `core/report.py`: Rich terminal report for a single signal
- [x] `cli.py`: Typer entrypoint with --file flag
- [x] Unit tests for every protection-core module
- [x] Integration test: scan a benign sample through the full pipeline

### Stage 2 — Policy, Audit, Authentication
The access matrix is driven by a policy file; privileged capabilities
require authentication; every decision is audited. This is where
Chapter 15's defenses begin wrapping the Chapter 14 kernel.

- [x] `security/policy.py`: load policy.yaml -> populate access matrix + RBAC roles
- [x] policy.yaml schema: objects, domains, rights, roles, thresholds, allow-listed hosts
- [x] `security/auth.py`: challenge-response H(pw, ch) + two-factor for admin ops
- [x] `security/auth.py`: S/Key code book generation and verification
- [x] Capability grant tied to successful authentication
- [x] `security/audit.py`: structured audit log of access decisions + auth events
- [x] Audit hooks in the protection core (every check -> audit record)
- [x] Anomaly hooks for strange-hour scans (audit flag)
- [x] Tests: policy load, auth success/failure, audit record contents
- [x] Integration test: privileged op fails without auth, succeeds with

### Stage 3 — PE Heuristics + Windows Security-Model Reader
The anomaly-detection signal (Ch.15 §6.3) is added, plus parsing of
the exact Windows security objects described in §15.9.

- [x] `signals/pe_heuristics.py`: parse PE with pefile/lief
- [x] Per-section entropy computation + high-entropy flag
- [x] Packer detection (UPX and common packers via section names + entropy)
- [x] Suspicious Win32 import detection (injection/crypto/networking API sets)
- [x] imphash computation + anomaly flag
- [x] Section-name anomaly detection
- [x] `signals/windows_model.py`: read PE manifest for requestedExecutionLevel (UAC)
- [x] `signals/windows_model.py`: extract integrity level, admin requirement
- [x] Surface UAC/integrity/admin in the verdict report
- [x] Tests: benign PE vs packed PE vs high-import-suspicion PE (fixture hashes, no real samples)
- [x] Integration test: heuristics signal runs in its own least-priv domain

### Stage 4 — YARA Signatures + Tripwire Integrity
The signature-detection signal (Ch.15 §6.3) is added. The rule
database is guarded by a Tripwire-style integrity checker (§6.4), and
the Bayes false-alarm math is wired into reporting.

- [x] `signals/yara_signatures.py`: load + compile vendored rule packs with yara-python
- [x] Vendor a starter set of community YARA rules (awesome-yara / yara-forge subset)
- [x] Scan sample, collect matches, map to family + severity
- [x] `security/integrity.py`: Tripwire baseline DB (hash of rules + model + binary)
- [x] `security/integrity.py`: detect added / deleted / changed files vs baseline
- [x] `--init-baseline` CLI command to create the integrity DB
- [x] Integrity check runs before every scan; warns if rules tampered
- [x] Bayes P(I|A) computation in `core/verdict.py` from measured alarm rates
- [x] Report P(I|A) in the JSON + terminal output
- [x] Tests: YARA match on a synthetic rule, integrity tamper detection, Bayes math (Ex 15.15)

### Stage 5 — Scoring Engine + Firewall + Signed Reports
Signals are combined into a final weighted verdict. Network egress is
firewalled. Reports are cryptographically signed.

- [x] `signals/scorer.py`: weighted aggregation of all signal outputs -> final verdict
- [x] Scoring weights defined in policy.yaml (tunable)
- [x] Confidence score from agreement/disagreement of signals
- [x] `security/firewall.py`: egress allow-list (MalwareBazaar host/port only)
- [x] `security/firewall.py`: application-proxy-style HTTP response inspection
- [x] DMZ-style domain isolation for untrusted samples
- [x] NETWORK_CALL capability enforced through the firewall
- [x] `security/crypto.py`: HMAC-SHA256 signing of JSON reports
- [x] `security/crypto.py`: optional asymmetric signing (Ed25519)
- [x] `security/crypto.py`: salted hashing of stored credentials (Ex 15.3/15.4)
- [x] `--verify-report` CLI command to validate a signed report
- [x] Tests: firewall blocks disallowed host, signed report verifies, tampered report fails

### Stage 6 — Vulnerability Self-Scan + TCSEC Classification
peSentinel turns its defenses on itself, and formally classifies its
own security level per the DoD TCSEC.

- [ ] `security/selfscan.py`: scan own install for the §6.2 checklist
- [ ] Detect setuid binaries in the install path
- [ ] Check directory permissions on data/, src/, config
- [ ] Check PATH for dangerous entries
- [ ] Detect checksum changes to shipped rules (reuses integrity.py)
- [ ] Detect unexpected network listeners
- [ ] `--selfscan` CLI command, report findings + auto-fix where safe
- [ ] `security/classifier_tcsec.py`: evaluate self against TCSEC divisions
- [ ] Document TCB = protection core; target C2 (individual ACL + audit + object reuse)
- [ ] TCSEC classification report in docs/
- [ ] Tests: selfscan flags a planted setuid file + a planted world-writable dir

### Stage 7 — Hardening, Batch Scan, Docs, Release
Polish, performance, and the chapter-mapping documentation that ties
every section of Ch.14/15 to the code that implements it.

- [ ] `--folder` batch scan with parallel signal execution
- [ ] Progress reporting (Rich) for batch scans
- [ ] Performance: cache compiled YARA rules, cache MalwareBazaar results per session
- [ ] `docs/chapter_mapping.md`: cross-reference each Ch.14/15 section to source files
- [ ] `docs/architecture.md`: final system tree + data flow
- [ ] README.md with install + usage examples
- [ ] `ruff` clean, `mypy` clean on protection core, `pytest` full green
- [ ] Package build (`python -m build`) + version tag

## Current Stage

Current Stage: 6 — Vulnerability Self-Scan + TCSEC Classification

## Notes & Decisions

### 2026-06-19 — Project kickoff
- **Approach:** Hybrid detection (hash + YARA + heuristics), not ML-only.
  ML deferred entirely; PE heuristics serve as the anomaly-detection
  signal so Ch.15 §6.3's signature-vs-anomaly duality is satisfied
  without a trained model.
- **File scope:** Windows PE only (.exe, .dll, .msi, .bin). Other
  formats out of scope.
- **Online lookups:** MalwareBazaar API (free, no key). VirusTotal
  optional, not in v1.
- **Interface:** CLI only (Typer + Rich). No web UI in v1.
- **Course alignment:** Broad-but-shallower coverage of Ch.14 + Ch.15.
  Every selected concept implemented at demonstrative level, tested,
  but not production-hardened.
- **Ch.14 concepts implemented:** access matrix, access-list +
  capability-list views, protection domains, least privilege, stack
  inspection, declarative protection, revocation, RBAC.
- **Ch.15 concepts implemented:** OTP/challenge auth, security policy,
  vulnerability self-scan, signature + anomaly detection, Bayes
  analysis, Tripwire integrity, audit logging, egress firewall, TCSEC
  C2 self-classification, Windows security-model reader, signed reports.
- **Source repos studied:** mathur99/RansomwareDetection (ML pipeline
  ref), CYB3RMX/Qu1cksc0pe (architecture ref), mthcht/awesome-lists
  (detection data feed), VirusTotal/yara (signature engine). None
  implement OS-protection concepts; peSentinel wraps their detection
  ideas inside a protection kernel.
- **Stage ordering rationale:** Protection core first so every later
  signal is sandboxed from day one (least privilege by construction,
  not retrofit).
