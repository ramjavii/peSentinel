# peSentinel

A Windows-PE malware analyzer whose *application* is malware detection
(hash reputation, YARA signatures, PE heuristics), but whose *substance*
is a miniature operating-system protection and security system
implementing the core concepts of **Chapter 14 (Protection)** and
**Chapter 15 (Security)** of the OS course text.

## Quick start

```bash
# Create a venv and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Scan a single file (offline mode)
pesentinel scan --file sample.exe --offline

# Scan with network reputation lookup
pesentinel scan --file sample.exe

# Batch scan a directory
pesentinel batch --folder ./samples --offline

# Write a JSON report
pesentinel scan --file sample.exe --report report.json --offline
```

## What it does

peSentinel runs four detection signals, each sandboxed inside a
least-privilege protection domain:

1. **Hash reputation** — SHA-256 → MalwareBazaar API lookup
2. **PE heuristics** — per-section entropy, packer detection,
   suspicious Win32 imports, imphash (anomaly detection)
3. **Windows security-model reader** — UAC level, integrity level,
   admin requirement from the PE manifest
4. **YARA signatures** — community rule pack scanning (signature
   detection)

Signals are combined into a weighted verdict:
`benign | suspicious | malicious` with a confidence score and
Bayes P(I|A) false-alarm analysis.

## Chapter coverage

- **Ch.14:** access matrix, capabilities, protection domains, least
  privilege, stack inspection (doPrivileged), declarative protection,
  revocation, RBAC
- **Ch.15:** OTP/challenge auth, security policy, vulnerability
  self-scan, signature + anomaly detection, Bayes analysis, Tripwire
  integrity, audit logging, egress firewall, TCSEC C2
  self-classification, Windows security-model reader, signed reports

See `docs/chapter_mapping.md` for the full concept → source mapping.

## Project structure

```
src/pesentinel/
  protection/   # Ch.14 TCB (access matrix, capabilities, domains, stack inspection)
  security/     # Ch.15 defenses (policy, audit, auth, firewall, integrity, selfscan, crypto, TCSEC)
  signals/      # detection signals (hash, heuristics, YARA, windows_model, scorer)
  core/         # pipeline, verdict, report
  cli.py        # Typer entrypoint
data/
  policy.yaml   # the living security document
  rules/        # YARA rule packs
tests/          # 155+ tests
docs/
  architecture.md
  chapter_mapping.md
```

## Testing

```bash
.venv/bin/pytest -q          # run all tests
.venv/bin/ruff check .       # lint
.venv/bin/ruff format --check .  # format check
.venv/bin/mypy src/pesentinel/protection  # strict typecheck on TCB
```
