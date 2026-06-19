from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Any

import pytest

from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.security.policy import AuthConfig, PolicyConfig, ScoringConfig


@pytest.fixture(autouse=True)
def reset_kernel() -> Any:
    """Reset the kernel singleton before and after each test."""
    ProtectionKernel.reset_instance()
    yield
    ProtectionKernel.reset_instance()


@pytest.fixture
def kernel() -> ProtectionKernel:
    k = ProtectionKernel()
    ProtectionKernel._instance = k
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


@pytest.fixture
def benign_pe(tmp_path: Path) -> Path:
    """A minimal valid PE32 file (hand-crafted, no malware)."""
    return _make_minimal_pe(tmp_path / "benign.exe")


@pytest.fixture
def non_pe_file(tmp_path: Path) -> Path:
    p = tmp_path / "notpe.bin"
    p.write_bytes(b"This is not a PE file at all.")
    return p


@pytest.fixture
def high_entropy_file(tmp_path: Path) -> Path:
    """A file with high-entropy content but not a valid PE."""
    p = tmp_path / "packed.bin"
    p.write_bytes(os.urandom(4096))
    return p


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def default_policy() -> PolicyConfig:
    return PolicyConfig(
        objects=[],
        domains={},
        roles={},
        scoring=ScoringConfig(),
        firewall_allow=[],
        auth=AuthConfig(),
    )


def _make_minimal_pe(path: Path) -> Path:
    """Create a minimal valid PE32 executable for testing.

    Hand-crafted PE with just headers and a .text section containing
    NOPs — no imports, no functionality, not real malware.
    """
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    pe_signature = b"PE\x00\x00"
    machine = 0x014C
    num_sections = 1
    time_date_stamp = 0
    ptr_to_symbol_table = 0
    num_symbols = 0
    opt_header_size = 224
    characteristics = 0x0102
    file_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        time_date_stamp,
        ptr_to_symbol_table,
        num_symbols,
        opt_header_size,
        characteristics,
    )
    magic = 0x10B
    optional_header = struct.pack("<H", magic) + b"\x00" * (opt_header_size - 2)
    section_name = b".text\x00\x00\x00"
    virtual_size = 16
    virtual_address = 0x1000
    raw_size = 512
    raw_offset = 0x200
    section_data = b"\x90" * 16 + b"\x00" * (raw_size - 16)
    section_header = struct.pack(
        "<8sIIIIII",
        section_name,
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
    )
    pe_data = dos_header + pe_signature + file_header + optional_header + section_header
    pad = b"\x00" * (raw_offset - len(pe_data))
    pe_data = pe_data + pad + section_data
    path.write_bytes(pe_data)
    return path
