from __future__ import annotations

from pesentinel.security.crypto import (
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    hmac_sign,
    hmac_verify,
    salted_hash,
    sign_report,
    verify_signed_report,
)


def test_hmac_sign_verify_roundtrip() -> None:
    key = b"secret-key"
    data = b"report payload"
    sig = hmac_sign(data, key)
    assert hmac_verify(data, sig, key)


def test_hmac_wrong_key_fails() -> None:
    sig = hmac_sign(b"data", b"key1")
    assert not hmac_verify(b"data", sig, b"key2")


def test_hmac_tampered_data_fails() -> None:
    sig = hmac_sign(b"original", b"key")
    assert not hmac_verify(b"tampered", sig, b"key")


def test_salted_hash_deterministic() -> None:
    salt = b"random-salt"
    h1 = salted_hash("password", salt)
    h2 = salted_hash("password", salt)
    assert h1 == h2


def test_salted_hash_different_salts_differ() -> None:
    h1 = salted_hash("password", b"salt1")
    h2 = salted_hash("password", b"salt2")
    assert h1 != h2


def test_ed25519_sign_verify() -> None:
    private, public = generate_ed25519_keypair()
    data = b"test report"
    sig = ed25519_sign(data, private)
    assert ed25519_verify(data, sig, public)


def test_ed25519_wrong_data_fails() -> None:
    private, public = generate_ed25519_keypair()
    sig = ed25519_sign(b"original", private)
    assert not ed25519_verify(b"tampered", sig, public)


def test_sign_report_roundtrip() -> None:
    key = b"signing-key"
    report = {"verdict": "malicious", "sha256": "abc"}
    signed = sign_report(report, key)
    assert verify_signed_report(signed, key)


def test_sign_report_tampered_fails() -> None:
    key = b"signing-key"
    report = {"verdict": "malicious", "sha256": "abc"}
    signed = sign_report(report, key)
    signed["payload"]["verdict"] = "benign"
    assert not verify_signed_report(signed, key)


def test_sign_report_missing_fields_fails() -> None:
    assert not verify_signed_report({}, b"key")
