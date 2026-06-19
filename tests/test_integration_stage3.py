from __future__ import annotations

from pathlib import Path

from pesentinel.core.pipeline import Pipeline
from pesentinel.protection.kernel import ProtectionKernel
from pesentinel.protection.types import Right, Verdict
from pesentinel.signals.pe_heuristics import PEHeuristicsSignal
from pesentinel.signals.windows_model import WindowsModelSignal


def test_pipeline_runs_heuristics_and_windows_model(
    kernel: ProtectionKernel, benign_pe: Path
) -> None:
    kernel.grant("heuristic_signal", "sample_file", Right.READ)
    kernel.grant("pipeline_core", "sample_file", Right.READ)
    heur = PEHeuristicsSignal(kernel)
    wsm = WindowsModelSignal(kernel)
    pipe = Pipeline(kernel, [heur, wsm])
    v = pipe.run(benign_pe)
    assert len(v.signal_results) == 2
    names = {r.signal_name for r in v.signal_results}
    assert names == {"pe_heuristics", "windows_model"}


def test_pipeline_non_pe_file(kernel: ProtectionKernel, non_pe_file: Path) -> None:
    kernel.grant("heuristic_signal", "sample_file", Right.READ)
    kernel.grant("pipeline_core", "sample_file", Right.READ)
    heur = PEHeuristicsSignal(kernel)
    pipe = Pipeline(kernel, [heur])
    v = pipe.run(non_pe_file)
    assert v.signal_results[0].verdict == Verdict.UNKNOWN
