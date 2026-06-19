# Stage 1 — Implementation Plan

> feature-loop Phase 2. Pre-approved by user ("start implementing
> until finish, loop if needed").

## Micro-feature

Stage 1 = "Protection Core + Hash Reputation Signal" (MVP.md).
This is the foundation; all later stages build on it. Treated as one
cohesive unit because the protection core must exist before the
signal can be sandboxed by it.

## 1. System entry points & file targets

New files (greenfield — no existing source):

```
pyproject.toml                                  # PEP 621 packaging + tool config
src/pesentinel/__init__.py                       # package marker + version
src/pesentinel/protection/
  __init__.py
  types.py            # Right/Verdict/Event enums, exceptions
  capability.py       # Capability + Kernel (unforgeable minting)
  access_matrix.py    # AccessMatrix (objects x domains x rights)
  domain.py           # Domain + ActiveDomain context manager
  stack_inspection.py # do_privileged + check_permission
  policy_bindings.py  # @requires_capability decorator
  revocation.py       # revoke + ref-counted object deletion
  kernel.py           # ProtectionKernel facade (the TCB API)
src/pesentinel/signals/
  __init__.py
  hash_reputation.py  # SHA-256 + MalwareBazaar query (least-priv)
src/pesentinel/core/
  __init__.py
  verdict.py          # SignalResult + Verdict dataclasses
  pipeline.py         # orchestrate domain switch -> signal
  report.py           # Rich terminal report
src/pesentinel/cli.py  # Typer entrypoint (--file)
tests/
  __init__.py
  conftest.py                       # fixtures
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
  test_tcb_boundary.py              # enforce protection/ imports nothing from signals/security
  test_integration_stage1.py        # end-to-end benign sample through pipeline
```

## 2. Precise logical modifications

### pyproject.toml
- PEP 621 metadata: name=pesentinel, version=0.1.0, python>=3.11
- deps: requests, typer, rich, pyyaml, cryptography
- dev deps (optional): pytest, pytest-cov, ruff, mypy
- [tool.ruff]: line-length=88, target py311
- [tool.pytest]: testpaths=["tests"]
- [tool.mypy]: strict path = src/pesentinel/protection
- [project.scripts]: pesentinel = "pesentinel.cli:app"

### protection/types.py
- `Right(IntEnum)`: READ, WRITE, EXECUTE, NETWORK_CALL, SCAN
- `Verdict(Enum)`: BENIGN, SUSPICIOUS, MALICIOUS, UNKNOWN
- `EventKind(Enum)`: ACCESS_CHECK, AUTH_SUCCESS, AUTH_FAILURE, AUTHZ_DENY, CAPABILITY_GRANT, CAPABILITY_REVOKE, DOMAIN_SWITCH
- `AccessControlException(Exception)` — expected control flow
- `CapabilityForgeError(AccessControlException)`

### protection/capability.py
- `Capability` frozen dataclass: (domain, obj, right) — opaque
  - `__repr__` redacts internals
  - `__copy__`/`__deepcopy__` raise CapabilityForgeError
  - no public constructor; minted only via `Kernel.mint()`
- `Kernel` singleton: holds access matrix + audit hook
  - `mint(domain, obj, right) -> Capability` (only minting path)
  - `check(capability) -> bool` (verify it's real + not revoked)

### protection/access_matrix.py
- `AccessMatrix`: dict[(domain,obj)] -> frozenset[Right]
  - `grant(domain, obj, rights)`, `revoke(domain, obj, rights)`
  - `rights_for_object(obj) -> dict[domain, set]` (access-list view)
  - `capabilities_for_domain(dom) -> list[Capability]` (capability-list view)
  - `has_right(domain, obj, right) -> bool`

### protection/domain.py
- `Domain` frozen dataclass: name + capability set
- `ActiveDomain` context manager: sets thread-local active domain,
  audits DOMAIN_SWITCH on enter/exit, restores previous on exit

### protection/stack_inspection.py
- `do_privileged()` context manager: annotates current frame
  (`_do_privileged_marker` in frame locals); audits
- `check_permission(kernel, obj, right)`:
  - walk `inspect.stack()` from newest to oldest
  - if a frame has `_do_privileged_marker` AND its domain has the
    right -> allow (return)
  - if a frame's domain LACKS the right -> raise AccessControlException
  - if stack exhausted -> raise AccessControlException (deny by default)
- Frame annotation is a frame-local set by the context manager; user
  code cannot reach it (no public API to set it) — Ex 14.21 defense

### protection/policy_bindings.py
- `@requires_capability(obj, right)` decorator
  - at call time: resolve active domain, check right via kernel
  - on deny: raise AccessControlException (audited)
  - declarative protection per spec §6 / Ch.14 §9.1

### protection/revocation.py
- `RevocationRegistry`: tracks per-object reference counts
  - `revoke(kernel, domain, obj, right)`: remove right, audit
  - `release(obj)`: decrement refcount; if 0 rights remain across all
    domains -> mark object for deletion (Ex 14.8)
  - `is_orphaned(obj) -> bool`

### protection/kernel.py
- `ProtectionKernel`: the facade / TCB API
  - owns `AccessMatrix`, `RevocationRegistry`, active-domain state
  - `grant(domain, obj, rights)`, `revoke(...)`, `check(obj, right)`
  - `enter_domain(name)` / `exit_domain()` via ActiveDomain
  - `do_privileged()` passthrough
  - audit hook (set in Stage 2; for Stage 1 a no-op/null logger)
  - This is what signals/core import — NOT the internal modules directly

### signals/hash_reputation.py
- `HashReputationSignal`:
  - `__init__(kernel)`: declares it needs READ(sample_file) +
    NETWORK_CALL(network) — but actual rights come from its domain
    assignment in policy (Stage 2); for Stage 1 the pipeline grants
    them programmatically
  - `analyze(path: Path) -> SignalResult`:
    - compute SHA-256 of file
    - if offline -> return UNKNOWN("offline")
    - POST to MalwareBazaar (try/except timeout)
    - parse response -> MALICIOUS if known, BENIGN if not found,
      UNKNOWN on error
  - network call wrapped in `do_privileged()` + `@requires_capability`

### core/verdict.py
- `SignalResult` dataclass: signal_name, verdict, confidence,
  evidence (list[str]), reason
- `AggregatedVerdict` dataclass: final_verdict, confidence,
  signal_results (list), bayes_pia (None in Stage 1)

### core/pipeline.py
- `Pipeline`:
  - `__init__(kernel, signals)`: register signals with their domains
  - `run(path: Path) -> AggregatedVerdict`:
    - for each signal: `with kernel.enter_domain(sig.domain): result = sig.analyze(path)`
    - collect SignalResults
    - (Stage 5 adds scoring; Stage 1 just lists results + a trivial
      verdict: any MALICIOUS -> MALICIOUS, else BENIGN)
  - catches AccessControlException -> records as UNKNOWN("denied")

### core/report.py
- `render_report(verdict: AggregatedVerdict) -> None`:
  - Rich Panel: verdict + confidence
  - Rich Table: per-signal results
  - Rich Panel: protection trace (domain switches) — from audit log

### cli.py
- Typer app: `pesentinel --file <path> [--report <out>] [--offline]`
  - builds kernel, registers hash_reputation signal in hash_signal
    domain, runs pipeline, renders report
  - top-level try/except -> rich error to stderr, exit non-zero

## 3. Test suites that verify success

- Unit tests per module (listed in file tree above)
- `test_tcb_boundary.py`: import-scan asserting protection/ does not
  import signals/ or security/
- `test_integration_stage1.py`: feed a benign fixture (small text
  file named .exe — NOT a real PE, just to test the pipeline path
  since Stage 1 hash reputation works on any file's hash), assert
  pipeline returns a verdict with the hash_reputation signal result,
  offline mode returns UNKNOWN, mocked MalwareBazaar returns
  MALICIOUS for a known-bad hash fixture
- No real network calls: mock `requests.post` or use `--offline`
- Commands: `pytest`, `ruff check .`, `ruff format --check .`,
  `mypy src/pesentinel/protection`

## 4. Risk areas

- **yara-python install** may need system libyara — but NOT needed
  for Stage 1 (only hash reputation). Defer to Stage 4. pyproject
  lists it but we don't import it yet; install may fail — if so,
  make yara-python an optional/Stage-4 dep. LOW risk for Stage 1.
- **lief / pefile** — same, not needed for Stage 1. List in
  pyproject but don't import. Defer to Stage 3.
- **mypy --strict on protection/** — strict mode catches missing
  types; ensure all public functions annotated. MEDIUM risk.
- **stack_inspection with inspect.stack()** — Python introspection
  can be slow; acceptable for v1 (single-threaded, small stacks).
  The frame-local marker approach is standard. MEDIUM risk — needs
  careful testing that the marker survives the walk.
- **MVP conflict**: none — Stage 1 is the first stage, nothing
  exists yet.
- **Unwired modules**: none — all new.

## 5. Fallback strategy

If a module proves too complex (e.g. stack_inspection edge cases),
reduce to a simplified check (active-domain-only check without full
stack walk) and document the simplification in the code + tests.
Revert via `git checkout` — the kickoff commit is the safe baseline.

## 6. MVP file impact

Stage 1 features are listed in MVP.md under "Stage 1" (all `- [ ]`).
On completion, Phase 4 flips all Stage 1 checkboxes to `- [x]` and
advances `Current Stage:` to "2 — Policy, Audit, Authentication".

Commit message: `feat(protection): Stage 1 — protection core + hash reputation signal`
