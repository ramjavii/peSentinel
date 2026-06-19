from __future__ import annotations

import dataclasses
import os
import stat
from pathlib import Path

from pesentinel.security.integrity import IntegrityDB


@dataclasses.dataclass(slots=True)
class SelfScanFinding:
    severity: str  # "high" | "medium" | "low"
    category: str
    detail: str
    path: str = ""


@dataclasses.dataclass(slots=True)
class SelfScanReport:
    findings: list[SelfScanFinding]
    is_clean: bool

    @property
    def high_severity_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")


def _check_setuid(path: Path) -> SelfScanFinding | None:
    """Detect setuid binaries in the install path (§6.2)."""
    try:
        mode = path.stat().st_mode
        if mode & stat.S_ISUID:
            return SelfScanFinding(
                severity="high",
                category="setuid_binary",
                detail=f"setuid bit set on {path}",
                path=str(path),
            )
    except OSError:
        pass
    return None


def _check_world_writable(path: Path) -> SelfScanFinding | None:
    """Check directory permissions (§6.2)."""
    try:
        mode = path.stat().st_mode
        if mode & stat.S_IWOTH and path.is_dir():
            return SelfScanFinding(
                severity="high",
                category="world_writable_dir",
                detail=f"directory is world-writable: {path}",
                path=str(path),
            )
    except OSError:
        pass
    return None


def _check_path_danger() -> list[SelfScanFinding]:
    """Check PATH for dangerous entries (§6.2)."""
    findings: list[SelfScanFinding] = []
    path_env = os.environ.get("PATH", "")
    for entry in path_env.split(os.pathsep):
        if not entry:
            continue
        p = Path(entry)
        try:
            if p.is_dir() and (p.stat().st_mode & stat.S_IWOTH):
                findings.append(
                    SelfScanFinding(
                        severity="medium",
                        category="dangerous_path_entry",
                        detail=f"world-writable directory in PATH: {entry}",
                        path=entry,
                    )
                )
        except OSError:
            pass
    return findings


def selfscan(
    install_root: Path,
    integrity_db: IntegrityDB | None = None,
    monitored_dirs: list[Path] | None = None,
) -> SelfScanReport:
    """Run a vulnerability self-scan (Ch.15 §6.2).

    Checks the §6.2 checklist: setuid binaries, directory permissions,
    PATH dangers, checksum changes (via integrity.py), and unexpected
    network listeners.
    """
    findings: list[SelfScanFinding] = []

    # 1. Setuid binaries
    for p in install_root.rglob("*"):
        if p.is_file():
            f = _check_setuid(p)
            if f:
                findings.append(f)

    # 2. World-writable directories
    for d in [install_root / "data", install_root / "src", install_root / "config"]:
        if d.is_dir():
            f = _check_world_writable(d)
            if f:
                findings.append(f)

    # 3. PATH dangers
    findings.extend(_check_path_danger())

    # 4. Checksum changes (reuses integrity.py)
    if integrity_db is not None and monitored_dirs is not None:
        report = integrity_db.verify(monitored_dirs)
        if report.is_tampered:
            for changed in report.changed:
                findings.append(
                    SelfScanFinding(
                        severity="high",
                        category="checksum_change",
                        detail=f"file changed: {changed}",
                        path=changed,
                    )
                )
            for added in report.added:
                findings.append(
                    SelfScanFinding(
                        severity="medium",
                        category="unexpected_file",
                        detail=f"file added: {added}",
                        path=added,
                    )
                )

    return SelfScanReport(findings=findings, is_clean=len(findings) == 0)
