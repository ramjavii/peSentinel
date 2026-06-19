from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path


@dataclasses.dataclass(slots=True)
class FileSignature:
    """Tripwire-style file signature (Ch.15 §6.4)."""

    path: str
    hash: str
    size: int
    mtime: float


@dataclasses.dataclass(slots=True)
class IntegrityReport:
    """Result of comparing current state to baseline (§6.4)."""

    changed: list[str]
    added: list[str]
    deleted: list[str]
    is_clean: bool

    @property
    def is_tampered(self) -> bool:
        return bool(self.changed or self.added or self.deleted)


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _signature(path: Path, root: Path) -> FileSignature:
    rel = str(path.relative_to(root))
    stat = path.stat()
    return FileSignature(
        path=rel,
        hash=_hash_file(path),
        size=stat.st_size,
        mtime=stat.st_mtime,
    )


class IntegrityDB:
    """Tripwire integrity database (Ch.15 §6.4).

    Stores SHA-256 signatures of monitored files in a baseline JSON.
    On subsequent runs, detects added/deleted/changed files. The
    baseline must be protected from tampering (stored in a
    gitignored path; ideally write-protected).
    """

    def __init__(self, baseline_path: Path, root: Path) -> None:
        self._baseline_path = baseline_path
        self._root = root

    def init_baseline(self, monitored_dirs: list[Path]) -> int:
        """Create the baseline DB from the monitored directories.

        Returns the number of files recorded."""
        sigs: dict[str, dict[str, object]] = {}
        count = 0
        for d in monitored_dirs:
            if not d.is_dir():
                continue
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    sig = _signature(p, self._root)
                    sigs[sig.path] = {
                        "hash": sig.hash,
                        "size": sig.size,
                        "mtime": sig.mtime,
                    }
                    count += 1
        self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self._baseline_path.write_text(json.dumps(sigs, indent=2))
        return count

    def verify(self, monitored_dirs: list[Path]) -> IntegrityReport:
        """Compare current state to baseline. Returns a report of
        changed/added/deleted files (§6.4)."""
        if not self._baseline_path.exists():
            return IntegrityReport(changed=[], added=[], deleted=[], is_clean=False)
        baseline: dict[str, dict[str, object]] = json.loads(
            self._baseline_path.read_text()
        )
        current: dict[str, FileSignature] = {}
        for d in monitored_dirs:
            if not d.is_dir():
                continue
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    sig = _signature(p, self._root)
                    current[sig.path] = sig

        changed: list[str] = []
        added: list[str] = []
        deleted: list[str] = []

        for path_str, sig in current.items():
            if path_str not in baseline:
                added.append(path_str)
            elif sig.hash != baseline[path_str].get("hash"):
                changed.append(path_str)

        for path_str in baseline:
            if path_str not in current:
                deleted.append(path_str)

        # Shrinking log detection (Tripwire box, §6.4): if a file's
        # current size < baseline size, flag as suspicious shrinkage
        for path_str, sig in current.items():
            if path_str in baseline:
                bsize = baseline[path_str].get("size", 0)
                if sig.size < bsize:
                    changed.append(f"{path_str} (shrinking)")

        return IntegrityReport(
            changed=sorted(set(changed)),
            added=sorted(added),
            deleted=sorted(deleted),
            is_clean=not (changed or added or deleted),
        )
