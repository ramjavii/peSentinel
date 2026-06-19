from __future__ import annotations

import hashlib
import hmac
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def hmac_sign(data: bytes, key: bytes) -> str:
    """HMAC-SHA256 signing (Ch.15 §10)."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(data: bytes, signature: str, key: bytes) -> bool:
    """Verify an HMAC-SHA256 signature."""
    expected = hmac_sign(data, key)
    return hmac.compare_digest(expected, signature)


def salted_hash(password: str, salt: bytes, iterations: int = 100_000) -> str:
    """PBKDF2 salted hashing of credentials (Ex 15.3/15.4)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair for asymmetric signing (§10)."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return private, public


def ed25519_sign(data: bytes, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(data)


def ed25519_verify(data: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


def sign_report(report_dict: dict[str, object], key: bytes) -> dict[str, object]:
    """Sign a report dict with HMAC and return a signed wrapper."""
    payload = json.dumps(report_dict, sort_keys=True).encode()
    sig = hmac_sign(payload, key)
    return {"payload": report_dict, "hmac_signature": sig}


def verify_signed_report(signed: dict[str, object], key: bytes) -> bool:
    """Verify a signed report wrapper."""
    payload = signed.get("payload")
    sig = signed.get("hmac_signature")
    if payload is None or sig is None:
        return False
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    return hmac_verify(payload_bytes, str(sig), key)
