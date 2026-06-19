from __future__ import annotations

import hashlib
from pathlib import Path

import requests

from pesentinel.core.verdict import SignalResult
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.policy_bindings import requires_capability
from pesentinel.protection.types import Right, Verdict

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
_REQUEST_TIMEOUT = 15


class HashReputationSignal:
    """Hash-based reputation signal (Stage 1).

    Computes SHA-256 of the sample and queries MalwareBazaar. Runs
    inside the ``hash_signal`` protection domain, which holds
    ``READ(sample_file)`` and ``NETWORK_CALL(network)`` rights (least
    privilege, Ch.14 Ex 14.23).
    """

    name = "hash_reputation"
    domain = "hash_signal"

    def __init__(self, kernel: ProtectionKernel, offline: bool = False) -> None:
        self._kernel = kernel
        self._offline = offline

    def analyze(self, path: Path) -> SignalResult:
        digest = self._sha256(path)
        if self._offline:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[f"sha256={digest}"],
                reason="offline mode; reputation skipped",
            )
        try:
            return self._query(digest)
        except Exception as exc:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[f"sha256={digest}"],
                reason=f"reputation query failed: {exc}",
            )

    @requires_capability("sample_file", Right.READ)
    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @requires_capability("network", Right.NETWORK_CALL)
    def _query(self, digest: str) -> SignalResult:
        resp = requests.post(
            MALWAREBAZAAR_URL,
            data={"query": "get_info", "hash": digest},
            headers={"User-Agent": "peSentinel/0.1.0"},
            timeout=_REQUEST_TIMEOUT,
        )
        payload = resp.json()

        if "error" in payload:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[f"sha256={digest}"],
                reason=(
                    f"MalwareBazaar API error: {payload['error']}"
                    f" (HTTP {resp.status_code})"
                ),
            )

        status = payload.get("query_status", "")
        if status == "ok":
            data = payload.get("data", [])
            family = ""
            if data and isinstance(data, list):
                family = data[0].get("signature_name", "") or "unknown"
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.MALICIOUS,
                confidence=0.9,
                evidence=[f"sha256={digest}", f"family={family}"],
                reason="hash found in MalwareBazaar",
            )
        if status == "hash_not_found":
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.BENIGN,
                confidence=0.4,
                evidence=[f"sha256={digest}"],
                reason="hash not in MalwareBazaar (not proof of benign)",
            )
        return SignalResult(
            signal_name=self.name,
            verdict=Verdict.UNKNOWN,
            confidence=0.0,
            evidence=[f"sha256={digest}"],
            reason=f"unexpected response status: {status}",
        )
