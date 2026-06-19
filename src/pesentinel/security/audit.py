from __future__ import annotations

import dataclasses
import datetime
import json
import threading
from pathlib import Path

from pesentinel.protection.types import EventKind


@dataclasses.dataclass(slots=True)
class AuditRecordData:
    ts: float
    event: str
    domain: str
    subject: str
    obj: str
    right: str
    decision: str
    reason: str
    stack_annot: bool


class JsonlAuditSink:
    """Append-only JSONL audit sink (Ch.15 §6.5).

    Implements the ``AuditSink`` Protocol defined in
    ``protection/domain.py`` without importing from protection/ (the
    Protocol is structural — satisfies the TCB boundary).
    """

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        event: EventKind,
        domain: str,
        subject: str,
        obj: str,
        right: str,
        decision: str,
        reason: str,
        stack_annot: bool = False,
    ) -> None:
        ts = datetime.datetime.now(datetime.UTC).timestamp()
        line = json.dumps(
            {
                "ts": ts,
                "event": event.value,
                "domain": domain,
                "subject": subject,
                "object": obj,
                "right": right,
                "decision": decision,
                "reason": reason,
                "stack_annot": stack_annot,
            }
        )
        with self._lock, open(self._path, "a") as fh:
            fh.write(line + "\n")

    def read_all(self) -> list[AuditRecordData]:
        """Read all audit records back (for the protection-trace panel
        and anomaly detection)."""
        if not self._path.exists():
            return []
        records: list[AuditRecordData] = []
        with open(self._path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                records.append(
                    AuditRecordData(
                        ts=d["ts"],
                        event=d["event"],
                        domain=d["domain"],
                        subject=d["subject"],
                        obj=d["object"],
                        right=d["right"],
                        decision=d["decision"],
                        reason=d["reason"],
                        stack_annot=d["stack_annot"],
                    )
                )
        return records


def is_strange_hour(ts: float, low: int = 8, high: int = 20) -> bool:
    """Flag scans outside normal working hours (audit anomaly hook,
    Ch.15 §6.5)."""
    hour = datetime.datetime.fromtimestamp(ts, datetime.UTC).hour
    return hour < low or hour >= high
