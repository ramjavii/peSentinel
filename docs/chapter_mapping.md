# peSentinel — Chapter Mapping

> Cross-reference: each Chapter 14/15 concept → the source file that
> implements it. This is the grading artifact for the OS course.

## Chapter 14 — Protection

| Concept | Source | How |
|---|---|---|
| **Access matrix** (§14.10) | `protection/access_matrix.py` | `AccessMatrix` class: sparse (domain, object) → set(Right). Policy vs mechanism separated. |
| **Access-list view** (per-object, Ex 14.1) | `protection/access_matrix.py:rights_for_object()` | Returns `{domain: set(Right)}` for a given object. |
| **Capability-list view** (per-domain, Ex 14.1) | `protection/access_matrix.py:capabilities_for_domain()` | Returns unforgeable `Capability` objects for a domain. |
| **Unforgeable capabilities** (Ex 14.10) | `protection/capability.py` | `Capability` class: private constructor, `__copy__`/`__deepcopy__` raise `CapabilityForgeError`. Only `Kernel.mint()` creates them. |
| **Protection domains** (§14.10) | `protection/domain.py` | `ActiveDomain` context manager sets/restores the active domain. |
| **Least privilege** (Ex 14.23) | `protection/domain.py` + policy | Each signal domain holds only the rights it needs (need-to-know, Ex 14.19/14.20). |
| **Domain switching** (§14.10) | `core/pipeline.py` | Pipeline does `with kernel.enter_domain(sig.domain): sig.analyze(path)`. |
| **Stack inspection** (§14.9.2, Fig 14.9) | `protection/stack_inspection.py` | `do_privileged()` annotates frame; `check_permission()` walks the stack for annotation or denial. |
| **Declarative protection** (§14.9.1) | `protection/policy_bindings.py` | `@requires_capability(obj, right)` decorator: load-time declaration + runtime enforcement. |
| **Revocation** (Ex 14.7) | `protection/revocation.py` | `revoke(domain, obj, right)` removes rights at runtime. |
| **Ref-counted deletion** (Ex 14.8) | `protection/revocation.py` | `is_orphaned(obj)` when all rights removed; `reclaim()` cleans up. |
| **RBAC roles** (Solaris, §14.10) | `security/policy.py:domains_for_role()` | `roles:` in policy.yaml maps roles → domain lists. |
| **Type safety / unforgeable refs** (§14.9.2) | `protection/capability.py` | Capabilities are opaque Python objects with no public constructor. Ex 14.21 defense: frame annotation set only by `do_privileged()`, no public API to forge. |
| **Need-to-know** (Ex 14.19) | `data/policy.yaml` | `hash_signal` sees only `sample_file` + `network`; `yara_signal` sees only `sample_file` + `rules_dir`. |
| **Ex 14.24** (least-priv still fails) | `spec.md §11` | Documented: a signal with READ + NETWORK_CALL could exfiltrate the sample. Firewall limits to MalwareBazaar only. |

## Chapter 15 — Security

| Concept | Source | How |
|---|---|---|
| **One-time / challenge-response auth** (§5.4) | `security/auth.py:challenge()` + `compute_response()` + `verify()` | `H(pw, ch)` = HMAC-SHA256(pw, ch). Password never transmitted. |
| **Two-factor authentication** (§5.4) | `security/auth.py:AuthService.authenticate_admin()` | PIN (something you know) + OTP from codebook (something you have). |
| **S/Key code book** (§5.4) | `security/auth.py:CodeBook` | Hash chain of N single-use passwords. `use_next()` pops + marks used. |
| **3x lockout** (spec §10.5) | `security/auth.py:AuthService` | After `max_attempts` failures, locks admin ops for the session. |
| **Security policy** (§6.1) | `security/policy.py` + `data/policy.yaml` | Living document driving access matrix, RBAC roles, scoring weights, firewall, auth, Bayes. |
| **Vulnerability self-scan** (§6.2) | `security/selfscan.py` | Checks §6.2 checklist: setuid, dir perms, PATH, checksum changes. |
| **Signature-based detection** (§6.3) | `signals/yara_signatures.py` | YARA rule scan → known family signatures. |
| **Anomaly detection** (§6.3) | `signals/pe_heuristics.py` | Entropy/packer/import/section anomalies → deviation from normal. |
| **Bayes P(I\|A)** (§6.3) | `core/verdict.py:bayes_pia()` | Computes P(I\|A) from true/false-alarm rates. Textbook example + Ex 15.15 as tests. |
| **Tripwire integrity** (§6.4) | `security/integrity.py` | `IntegrityDB`: baseline of SHA-256 signatures. Detects added/deleted/changed/shrinking files. |
| **Audit logging** (§6.5) | `security/audit.py:JsonlAuditSink` | Append-only JSONL of every access decision + auth event. `is_strange_hour()` anomaly hook. |
| **Egress firewall** (§7) | `security/firewall.py:EgressFirewall` | Allow-list of (host, port, scheme) from policy. NETWORK_CALL routes through it. |
| **Application proxy** (§7) | `security/firewall.py:validate_response()` | Validates MalwareBazaar JSON schema before passing to signal. |
| **DMZ domain isolation** (§7) | `data/policy.yaml` + `protection/domain.py` | Untrusted samples analyzed in isolated domain; cannot reach `reports_dir` directly. |
| **TCSEC C2** (§8) | `security/classifier_tcsec.py` | Self-classification: C1 group ACL ✓, C2 individual ACL ✓, selective audit ✓, TCB self-protection ✓, object reuse ✓. B1 labels out of scope. |
| **TCB documentation** (§8) | `security/classifier_tcsec.py:tcb_description` | TCB = `protection/` package. No imports from signals/security/core (enforced by `test_tcb_boundary.py`). |
| **Windows security-model reader** (§15.9) | `signals/windows_model.py` | Reads PE manifest: UAC requestedExecutionLevel, integrity level, admin requirement, DLL hardening flags. |
| **Signed reports** (§10) | `security/crypto.py:hmac_sign()` + `sign_report()` | HMAC-SHA256 over JSON report. `verify_signed_report()` validates. |
| **Asymmetric signing** (§10) | `security/crypto.py:ed25519_sign()` | Ed25519 for non-repudiation. |
| **Salted credentials** (Ex 15.3/15.4) | `security/crypto.py:salted_hash()` | PBKDF2-HMAC with random salt. No plaintext password storage. |

## Test coverage by concept

| Test file | Concepts verified |
|---|---|
| `test_capability.py` | Unforgeable capabilities, forge attempt, copy blocked (Ex 14.10) |
| `test_access_matrix.py` | Access matrix, access-list/capability-list views (Ex 14.1) |
| `test_domain.py` | Domain switching, audit of switches |
| `test_stack_inspection.py` | doPrivileged, stack walk, Fig 14.9 analogue |
| `test_policy_bindings.py` | Declarative protection decorator (§14.9.1) |
| `test_revocation.py` | Runtime revoke, orphan tracking (Ex 14.7/14.8) |
| `test_tcb_boundary.py` | TCB boundary: protection/ imports nothing from signals/security/core |
| `test_policy.py` | Policy file load + apply (§6.1) |
| `test_audit.py` | Audit log write/read, strange-hour (§6.5) |
| `test_auth.py` | Challenge-response, codebook, two-factor, lockout (§5.4) |
| `test_integrity.py` | Tripwire baseline, tamper detection (§6.4) |
| `test_bayes.py` | Bayes P(I\|A), textbook + Ex 15.15 (§6.3) |
| `test_firewall.py` | Egress allow-list, proxy validation (§7) |
| `test_crypto.py` | HMAC, Ed25519, salted hash, signed reports (§10) |
| `test_scorer.py` | Weighted aggregation, floor logic (§9.1) |
| `test_selfscan.py` | Setuid, world-writable, checksum change (§6.2) |
| `test_tcsec.py` | C2 requirements met, B1 not met (§8) |
| `test_integration_stage1.py` | End-to-end pipeline through protection kernel |
