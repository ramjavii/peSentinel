from __future__ import annotations

from pesentinel.security.classifier_tcsec import classify_tcsec


def test_tcsec_target_is_c2() -> None:
    report = classify_tcsec()
    assert report.target_level == "C2"


def test_tcsec_achieves_c2() -> None:
    report = classify_tcsec()
    assert report.achieved_level == "C2"


def test_tcsec_c2_findings_met() -> None:
    report = classify_tcsec()
    c2_findings = [f for f in report.findings if f.requirement.startswith("C2")]
    assert len(c2_findings) >= 4
    assert all(f.met for f in c2_findings)


def test_tcsec_b1_not_met() -> None:
    report = classify_tcsec()
    b1 = [f for f in report.findings if f.requirement.startswith("B1")]
    assert len(b1) >= 1
    assert not b1[0].met


def test_tcsec_tcb_description() -> None:
    report = classify_tcsec()
    assert "protection" in report.tcb_description.lower()
    assert "TCB" in report.tcb_description or "Trusted" in report.tcb_description


def test_tcsec_all_findings_have_evidence() -> None:
    report = classify_tcsec()
    for f in report.findings:
        assert f.evidence
        assert f.requirement
