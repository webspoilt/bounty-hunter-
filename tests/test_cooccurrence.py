"""Tests for CWE Co-occurrence calculations and risk hypothesis generation."""
from __future__ import annotations

import pytest
from bb.intel.cooccurrence import CooccurrenceEngine
from bb.intel.risk_hypotheses import generate_hypotheses_for_weaknesses


def test_cooccurrence_calculations_and_lift():
    engine = CooccurrenceEngine(min_sample_size=3, min_cooccurrence=2)

    # 10 applications:
    # 5 have both CWE-862 (Missing Authz) and CWE-639 (IDOR)
    for i in range(5):
        engine.record_report(f"app-{i}", ["CWE-862", "CWE-639"])

    # 3 have only CWE-862
    for i in range(5, 8):
        engine.record_report(f"app-{i}", ["CWE-862"])

    # 2 have only CWE-89 (SQLi)
    for i in range(8, 10):
        engine.record_report(f"app-{i}", ["CWE-89"])

    metrics = engine.compute_metrics()

    # Pair (CWE-862, CWE-639)
    # Total apps = 10
    # count(CWE-862) = 8, P(A) = 0.8
    # count(CWE-639) = 5, P(B) = 0.5
    # count(both) = 5, P(A,B) = 0.5
    # P(B|A) = 5/8 = 0.625
    # Lift = 0.5 / (0.8 * 0.5) = 1.25
    pair_metric = metrics.get(("CWE-862", "CWE-639"))
    assert pair_metric is not None
    assert pair_metric.count_both == 5
    assert pair_metric.prob_b_given_a == 0.625
    assert pair_metric.lift == 1.25
    assert pair_metric.is_significant is True


def test_risk_hypothesis_generation():
    engine = CooccurrenceEngine(min_sample_size=1, min_cooccurrence=1)
    engine.record_report("rep-1", ["CWE-862", "CWE-639"])
    engine.record_report("rep-2", ["CWE-862", "CWE-639"])

    hyps = generate_hypotheses_for_weaknesses(["CWE-862"], engine, min_lift=1.0)
    assert len(hyps) >= 1
    assert hyps[0].target_cwe == "CWE-639"
    assert len(hyps[0].recommended_checks) >= 1
