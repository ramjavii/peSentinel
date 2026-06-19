from __future__ import annotations

from pesentinel.protection.domain import NullAuditSink
from pesentinel.security.auth import (
    AuthService,
    CodeBook,
    challenge,
    compute_response,
    verify,
)


def test_challenge_response_roundtrip() -> None:
    ch = challenge()
    pw = "secret"
    resp = compute_response(pw, ch)
    assert verify(pw, ch, resp)


def test_wrong_response_fails() -> None:
    ch = challenge()
    assert not verify("secret", ch, "wrong")


def test_different_challenges_yield_different_responses() -> None:
    ch1 = challenge()
    ch2 = challenge()
    assert ch1 != ch2
    assert compute_response("pw", ch1) != compute_response("pw", ch2)


def test_codebook_generate_and_use() -> None:
    book = CodeBook.generate(b"seed", 5)
    assert book.remaining() == 5
    assert not book.is_exhausted()
    first = book.use_next()
    assert first is not None
    assert book.remaining() == 4
    assert book.use_next() != first


def test_codebook_exhaustion() -> None:
    book = CodeBook.generate(b"seed", 2)
    book.use_next()
    book.use_next()
    assert book.is_exhausted()
    assert book.use_next() is None


def test_auth_service_success() -> None:
    pin = "1234"
    pin_hash = AuthService.hash_pin(pin, b"pesentinel-salt")
    book = CodeBook.generate(b"seed", 10)
    otp = book.entries[0]
    # codebook is consumed by authenticate, so use a fresh book whose
    # first entry matches what we pass
    book2 = CodeBook.generate(b"seed", 10)
    otp = book2.entries[0]
    svc = AuthService(NullAuditSink(), pin_hash, book2)
    result = svc.authenticate_admin(pin, otp)
    assert result.success


def test_auth_service_wrong_pin() -> None:
    pin = "1234"
    pin_hash = AuthService.hash_pin(pin, b"pesentinel-salt")
    book = CodeBook.generate(b"seed", 10)
    otp = book.entries[0]
    svc = AuthService(NullAuditSink(), pin_hash, book)
    result = svc.authenticate_admin("wrong", otp)
    assert not result.success
    assert not svc.is_locked()


def test_auth_service_wrong_otp() -> None:
    pin = "1234"
    pin_hash = AuthService.hash_pin(pin, b"pesentinel-salt")
    book = CodeBook.generate(b"seed", 10)
    svc = AuthService(NullAuditSink(), pin_hash, book)
    result = svc.authenticate_admin(pin, "wrong-otp")
    assert not result.success


def test_auth_service_lockout_after_max_attempts() -> None:
    pin = "1234"
    pin_hash = AuthService.hash_pin(pin, b"pesentinel-salt")
    book = CodeBook.generate(b"seed", 10)
    svc = AuthService(NullAuditSink(), pin_hash, book, max_attempts=3)
    for _ in range(3):
        svc.authenticate_admin("wrong", "wrong")
    assert svc.is_locked()
    # Even correct creds fail when locked
    result = svc.authenticate_admin(pin, book.entries[0])
    assert not result.success
    assert "locked" in result.reason
