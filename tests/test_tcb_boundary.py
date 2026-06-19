from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROTECTION_DIR = (
    Path(__file__).resolve().parents[1] / "src" / "pesentinel" / "protection"
)
FORBIDDEN_PREFIXES = (
    "pesentinel.signals",
    "pesentinel.security",
    "pesentinel.core",  # protection must not depend on core either
)


def _imports_in(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_protection_directory_exists() -> None:
    assert PROTECTION_DIR.is_dir(), f"missing protection dir: {PROTECTION_DIR}"


@pytest.mark.parametrize(
    "src",
    sorted(PROTECTION_DIR.glob("*.py")),
    ids=lambda p: p.name,
)
def test_protection_does_not_import_forbidden(src: Path) -> None:
    """The TCB (protection/) must not import from signals/, security/,
    or core/ (AGENTS.md, spec §11). This prevents circular trust."""
    if src.name == "__init__.py":
        return
    for imp in _imports_in(src):
        for bad in FORBIDDEN_PREFIXES:
            assert not imp.startswith(bad), (
                f"{src.name} imports forbidden {imp} (TCB boundary violation)"
            )
