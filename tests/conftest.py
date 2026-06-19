from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from pesentinel.protection.kernel import ProtectionKernel


@pytest.fixture(autouse=True)
def reset_kernel() -> Any:
    """Reset the kernel singleton before and after each test."""
    ProtectionKernel.reset_instance()
    yield
    ProtectionKernel.reset_instance()


@pytest.fixture
def kernel() -> ProtectionKernel:
    k = ProtectionKernel()
    ProtectionKernel._instance = k  # so @requires_capability sees it
    return k


@pytest.fixture
def benign_sample(tmp_path: Path) -> Path:
    """A small non-PE file whose hash is NOT in MalwareBazaar."""
    p = tmp_path / "sample.exe"
    p.write_bytes(b"This is a benign test file, not real malware.")
    return p


@pytest.fixture
def empty_sample(tmp_path: Path) -> Path:
    p = tmp_path / "empty.exe"
    p.write_bytes(b"")
    return p


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
