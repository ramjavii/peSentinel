from __future__ import annotations

import dataclasses
import hashlib
import hmac
import secrets

from pesentinel.protection.domain import AuditSink
from pesentinel.protection.types import EventKind


def challenge() -> str:
    """Generate a random challenge ``ch`` (Ch.15 §5.4)."""
    return secrets.token_hex(16)


def compute_response(password: str, ch: str) -> str:
    """Compute H(pw, ch) — the one-time authenticator (§5.4).

    Uses HMAC-SHA256 so the password is never transmitted; only the
    response is sent. Each challenge yields a different response.
    """
    return hmac.new(password.encode(), ch.encode(), hashlib.sha256).hexdigest()


def verify(password: str, ch: str, response: str) -> bool:
    """Verify a challenge-response pair (§5.4)."""
    expected = compute_response(password, ch)
    return hmac.compare_digest(expected, response)


@dataclasses.dataclass(slots=True)
class CodeBook:
    """S/Key-style code book of single-use passwords (§5.4).

    A hash chain: each entry is derived from the previous. Used once
    and then crossed off. The user protects the book; the system
    stores only a verification anchor.
    """

    entries: list[str]
    _index: int = 0

    @classmethod
    def generate(cls, seed: bytes, n: int) -> CodeBook:
        """Generate ``n`` single-use passwords from a seed (hash chain)."""
        entries: list[str] = []
        current = seed
        for _ in range(n):
            current = hashlib.sha256(current).digest()
            entries.append(current.hex())
        return cls(entries=entries)

    def use_next(self) -> str | None:
        """Pop the next single-use password. Returns None if exhausted."""
        if self._index >= len(self.entries):
            return None
        entry = self.entries[self._index]
        self._index += 1
        return entry

    def is_exhausted(self) -> bool:
        return self._index >= len(self.entries)

    def remaining(self) -> int:
        return len(self.entries) - self._index


@dataclasses.dataclass(slots=True)
class TwoFactorResult:
    success: bool
    reason: str


class AuthService:
    """Authentication service wrapping the protection kernel (§5.4).

    Two-factor for admin ops: PIN (something you know) + OTP from a
    code book (something you have). Locks out after ``max_attempts``
    failures (spec §10.5).
    """

    def __init__(
        self,
        audit: AuditSink,
        pin_hash: str,
        codebook: CodeBook,
        max_attempts: int = 3,
    ) -> None:
        self._audit = audit
        self._pin_hash = pin_hash
        self._codebook = codebook
        self._max_attempts = max_attempts
        self._failures = 0
        self._locked = False

    @staticmethod
    def hash_pin(pin: str, salt: bytes) -> str:
        """Salted hash of a PIN (Ex 15.3/15.4 — no plaintext storage)."""
        return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 100_000).hex()

    def authenticate_admin(self, pin: str, otp: str) -> TwoFactorResult:
        """Two-factor authentication for admin operations (§5.4)."""
        if self._locked:
            self._audit_auth(False, "locked out")
            return TwoFactorResult(False, "locked out after too many failures")

        pin_ok = hmac.compare_digest(
            self._pin_hash,
            AuthService.hash_pin(pin, b"pesentinel-salt"),
        )
        expected_otp = self._codebook.use_next()
        otp_ok = expected_otp is not None and hmac.compare_digest(expected_otp, otp)

        if pin_ok and otp_ok:
            self._failures = 0
            self._audit_auth(True, "two-factor success")
            return TwoFactorResult(True, "authenticated")

        self._failures += 1
        reason = "invalid PIN or OTP"
        if self._failures >= self._max_attempts:
            self._locked = True
            reason = f"locked out after {self._failures} failures"
        self._audit_auth(False, reason)
        return TwoFactorResult(False, reason)

    def is_locked(self) -> bool:
        return self._locked

    def _audit_auth(self, success: bool, reason: str) -> None:
        event = EventKind.AUTH_SUCCESS if success else EventKind.AUTH_FAILURE
        self._audit.record(
            event,
            "admin",
            "admin",
            "",
            "",
            "allow" if success else "deny",
            reason,
        )
