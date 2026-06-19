from __future__ import annotations

import hashlib
import os
from pathlib import Path

import requests

from pesentinel.core.verdict import SignalResult
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.policy_bindings import requires_capability
from pesentinel.protection.types import Right, Verdict

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"
_REQUEST_TIMEOUT = 15
_VT_MALICIOUS_THRESHOLD = 3


class HashReputationSignal:
    """Hash-based reputation signal (Stage 1).

    Computes SHA-256 of the sample and queries a reputation provider.
    If a VirusTotal API key is set in the environment
    (VIRUSTOTAL_API_KEY), uses VirusTotal API v3. Otherwise falls
    back to MalwareBazaar. Runs inside the ``hash_signal`` protection
    domain (READ sample_file + NETWORK_CALL network).
    """

    name = "hash_reputation"
    domain = "hash_signal"

    def __init__(self, kernel: ProtectionKernel, offline: bool = False) -> None:
        self._kernel = kernel
        self._offline = offline
        self._vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    @property
    def provider(self) -> str:
        return "virustotal" if self._vt_key else "malwarebazaar"

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
            if self._vt_key:
                return self._query_virustotal(digest)
            return self._query_malwarebazaar(digest)
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
    def _query_virustotal(self, digest: str) -> SignalResult:
        resp = requests.get(
            VIRUSTOTAL_URL + digest,
            headers={"x-apikey": self._vt_key},
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.BENIGN,
                confidence=0.4,
                evidence=[f"sha256={digest}"],
                reason="hash not in VirusTotal (not proof of benign)",
            )
        if resp.status_code == 429:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[f"sha256={digest}"],
                reason="VirusTotal rate limit (429); free tier is 4 req/min",
            )
        if resp.status_code != 200:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.UNKNOWN,
                confidence=0.0,
                evidence=[f"sha256={digest}"],
                reason=f"VirusTotal API error (HTTP {resp.status_code})",
            )
        payload = resp.json()
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        name = attrs.get("popular_threat_classification", {}).get(
            "suggested_threat_label", "unknown"
        )

        if malicious >= _VT_MALICIOUS_THRESHOLD:
            confidence = min(0.5 + malicious / max(total, 1) * 0.5, 0.95)
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.MALICIOUS,
                confidence=confidence,
                evidence=[
                    f"sha256={digest}",
                    f"detections={malicious}/{total}",
                    f"label={name}",
                ],
                reason=f"{malicious} engines flagged as malicious",
            )
        if suspicious >= 2 or malicious >= 1:
            return SignalResult(
                signal_name=self.name,
                verdict=Verdict.SUSPICIOUS,
                confidence=0.5,
                evidence=[
                    f"sha256={digest}",
                    f"detections={malicious}mal/{suspicious}susp/{total}",
                ],
                reason=f"{malicious} malicious, {suspicious} suspicious",
            )
        return SignalResult(
            signal_name=self.name,
            verdict=Verdict.BENIGN,
            confidence=0.6,
            evidence=[f"sha256={digest}", f"detections=0/{total}"],
            reason=f"0 detections out of {total} engines",
        )

    @requires_capability("network", Right.NETWORK_CALL)
    def _query_malwarebazaar(self, digest: str) -> SignalResult:
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
