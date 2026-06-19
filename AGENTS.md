# AGENTS.md — peSentinel agent instructions

opencode loads this file on every session via `opencode.json`.
Follow these rules when writing or modifying code.

## Tech Stack Enforcement

- **Language:** Python 3.11+. No other languages.
- **PE parsing:** Use `pefile` and `lief` only. Do not add other PE
  parsers.
- **Signature engine:** Use `yara-python` only. Do not shell out to
  the `yara` CLI.
- **HTTP client:** Use `requests` (sync). No async frameworks in v1.
- **CLI:** Use `typer` + `rich`. Do not add other TUI libraries.
- **Config:** Use `pyyaml` for `policy.yaml`. No `.toml` for runtime
  config (pyproject.toml is packaging only).
- **Crypto:** Use the `cryptography` library. No hand-rolled crypto.
- **Tests:** `pytest` + `pytest-cov`. No other test runner.
- **Lint/format:** `ruff` + `ruff format`. Do not use black or flake8.
- **Types:** `mypy --strict` on `src/pesentinel/protection/`. Default
  `mypy` elsewhere. Do not add `# type: ignore` in the protection
  core without a justification comment.
- **No external UI libraries** other than `rich`.
- **No new top-level dependencies** without updating pyproject.toml
  AND justifying in the commit message.

## Code Style Preferences

- Prefer functional style with dataclasses for value objects.
- Use `pathlib.Path` for all filesystem paths. No raw `os.path`.
- Use `from __future__ import annotations` at the top of every module
  for deferred annotation evaluation.
- Use `async`/`await` only if explicitly required (not in v1); prefer
  sync code.
- Prefer explicit `raise` with typed exceptions over returning
  sentinel values like `-1` or `None` for errors. `None` is allowed
  only for genuinely optional values.
- Use `enum.Enum` / `enum.IntEnum` for fixed value sets (rights,
  verdicts, event types).
- Module layout: one primary class or function family per file.
- Keep functions under ~60 lines; refactor longer ones.
- No star imports (`from x import *`).

## TCB Boundary Rules (critical)

- The `src/pesentinel/protection/` package is the **Trusted Computing
  Base** (Ch.15 §8). It MUST NOT import from `signals/` or `security/`.
- `signals/` and `security/` MAY import from `protection/`.
- This prevents circular trust. A lint test enforces it
  (`tests/test_tcb_boundary.py`).

## Error Handling Rules

- Every entry point (`cli.py`, `core/pipeline.py`) must catch
  top-level exceptions and report them via `rich` to stderr, then
  exit non-zero. Never dump a raw traceback to the user.
- Every network call must be wrapped in try/except with a timeout.
  Network failures yield `unknown` signal results, never crashes.
- Every PE parse must catch `pefile.PEFormatError` and `lief`
  exceptions; record `unknown` + reason, continue the pipeline.
- Access-control denials (`AccessControlException`) are EXPECTED
  control flow, not errors. Audit them, do not crash.
- Log all unexpected exceptions to the audit log with a stack summary.

## Testing Rules

- Every new module in `protection/` MUST ship with unit tests in the
  same PR/commit.
- Every new signal MUST ship with at least one integration test using
  a fixture (synthetic PE or hash fixture, never a real malware
  sample).
- Tests must not make real network calls. Mock `requests` or use
  `--offline` in tests.
- Run `ruff check` and `ruff format --check` and `pytest` before
  every commit. Use the `/test` and `/lint` slash commands.

## Auto-Updating Docs Rule

Whenever you create a new feature, directory, or API route, you must
immediately update `/docs/architecture.md` with a summary of the
change and an updated tree structure of the files you touched. This
is not optional — a stale architecture doc corrupts the next planning
session.

## Conventional Commits

Use Conventional Commits: `<type>(<scope>): <description>`.
Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`,
`ci`. Scope = module name (e.g. `protection`, `signals`, `security`).
