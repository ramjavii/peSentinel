from __future__ import annotations

import dataclasses


@dataclasses.dataclass(slots=True)
class TCSECFinding:
    requirement: str
    met: bool
    evidence: str


@dataclasses.dataclass(slots=True)
class TCSECReport:
    """TCSEC self-classification (Ch.15 §8).

    Evaluates peSentinel against the DoD Trusted Computer System
    Evaluation Criteria. The TCB is the protection/ package.
    """

    target_level: str
    achieved_level: str
    findings: list[TCSECFinding]
    tcb_description: str

    @property
    def all_met(self) -> bool:
        return all(f.met for f in self.findings)


def classify_tcsec() -> TCSECReport:
    """Evaluate peSentinel against TCSEC divisions (§8).

    Target: C2 (discretionary protection + accountability).
    C2 requirements (from the text):
      1. Individual-level access control (per-user ACL)
      2. Selective auditing of user actions
      3. TCB protects itself from modification
      4. Object reuse protection (no info from prior user)
    """
    findings = [
        TCSECFinding(
            requirement="C1: named-group access control",
            met=True,
            evidence="AccessMatrix grants rights per domain (group analogue)",
        ),
        TCSECFinding(
            requirement="C2: individual-level access control",
            met=True,
            evidence="RBAC roles map individuals to domains with per-object rights",
        ),
        TCSECFinding(
            requirement="C2: selective auditing of user actions",
            met=True,
            evidence="JsonlAuditSink records every access decision + auth event",
        ),
        TCSECFinding(
            requirement="C2: TCB self-protection",
            met=True,
            evidence="protection/ package has no imports from signals/security/core "
            "(enforced by test_tcb_boundary.py); mypy --strict on TCB",
        ),
        TCSECFinding(
            requirement="C2: object reuse protection",
            met=True,
            evidence="RevocationRegistry ref-counts objects; orphaned objects "
            "are reclaimed when all rights removed (Ex 14.8)",
        ),
        TCSECFinding(
            requirement="B1: sensitivity labels (mandatory access control)",
            met=False,
            evidence="peSentinel does not implement sensitivity labels — "
            "out of scope for C2 target",
        ),
    ]

    c2_met = all(f.met for f in findings if f.requirement.startswith("C2"))
    c1_met = all(f.met for f in findings if f.requirement.startswith("C1"))
    achieved = "C2" if c2_met else ("C1" if c1_met else "D")

    return TCSECReport(
        target_level="C2",
        achieved_level=achieved,
        findings=findings,
        tcb_description=(
            "The Trusted Computing Base (TCB) is the src/pesentinel/protection/ "
            "package. It contains the access matrix, capability system, domain "
            "switching, stack inspection, declarative protection decorators, and "
            "revocation registry. The TCB does not import from signals/, security/, "
            "or core/ — enforcing the no-circular-trust boundary."
        ),
    )
