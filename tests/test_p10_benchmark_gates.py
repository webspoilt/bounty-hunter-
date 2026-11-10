"""Comprehensive Test Suite for Strategic P10 (Benchmark, Discovery Quality & Release Gates).

Verifies:
1. Versioned vulnerability benchmark dataset (20 ground-truth cases across 10 categories).
2. Controlled local multi-tenant benchmark server lifecycle.
3. Discovery quality evaluation:
   - True positives detected accurately with evidence verification
   - Secure negative controls properly rejected (zero false positives)
   - Ambiguous / indeterminate cases honestly classified as inconclusive
   - Precision = 1.0, Recall = 1.0, F1 = 1.0 on benchmark ground truth
4. Independent verification and evidence consistency check.
5. Production release gates evaluation (PASS decision with all 5 gates satisfied).
6. Pilot readiness checklist verification (preconditions for controlled real-world pilot).
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from bb.benchmark import (
    BenchmarkCategory,
    BenchmarkDataset,
    BenchmarkHarness,
    EvaluationMetrics,
    ExpectedVerdict,
    GroundTruthTestCase,
    LocalBenchmarkServer,
)
from bb.benchmark.release_gates import (
    GateStatus,
    PilotReadinessChecklist,
    ProductionReleaseGate,
    ReleaseGateResult,
)
from bb.store import Store


@pytest.fixture(scope="module")
def benchmark_server():
    server = LocalBenchmarkServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def tmp_store(tmp_path):
    return Store(tmp_path / "p10_eval.db")


# =========================================================================
# 1. Dataset Integrity & Category Completeness
# =========================================================================

def test_benchmark_dataset_completeness():
    """Verify ground truth dataset covers all 10 required vulnerability categories."""
    dataset = BenchmarkDataset()
    assert dataset.version() == "1.0.0-p10-standard"
    cases = dataset.list_cases()
    assert len(cases) == 20

    # Ensure all 10 categories are represented
    covered_categories = {c.category for c in cases}
    assert len(covered_categories) == 10
    assert covered_categories == {
        BenchmarkCategory.BOLA_IDOR,
        BenchmarkCategory.BFLA,
        BenchmarkCategory.PROPERTY_AUTHZ,
        BenchmarkCategory.AUTH_SESSION,
        BenchmarkCategory.MULTI_TENANT,
        BenchmarkCategory.BUSINESS_LOGIC,
        BenchmarkCategory.INJECTION,
        BenchmarkCategory.INFO_EXPOSURE,
        BenchmarkCategory.MISCONFIG,
        BenchmarkCategory.VULN_COMPONENT,
    }

    # Verify counts: 10 vulnerable, 7 secure controls, 3 ambiguous
    counts = dataset.count_by_verdict()
    assert counts["VULNERABLE"] == 10
    assert counts["SECURE"] == 7
    assert counts["AMBIGUOUS"] == 3


# =========================================================================
# 2. Local Benchmark Server & End-to-End Discovery Quality
# =========================================================================

def test_end_to_end_benchmark_discovery_and_verification(benchmark_server, tmp_store):
    """Run full benchmark evaluation and verify discovery precision, recall, and safety."""
    harness = BenchmarkHarness(benchmark_server, tmp_store)
    metrics = harness.run_benchmark(config_mode="standard_multi_worker")

    # Discovery quality checks
    assert metrics.total_cases_evaluated == 20
    assert metrics.ground_truth_vulnerable == 10
    assert metrics.ground_truth_secure == 7
    assert metrics.ground_truth_ambiguous == 3

    assert metrics.true_positives == 10
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.true_negatives == 7
    assert metrics.inconclusive_count == 3

    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0

    # Verification quality checks
    assert metrics.independent_reproductions == 10
    assert metrics.negative_control_rejections == 7
    assert metrics.evidence_consistency_rate == 1.0

    # Safety checks
    assert metrics.scope_violations == 0
    assert metrics.budget_overruns == 0
    assert metrics.unauthorized_writes == 0
    assert metrics.killswitch_violations == 0


# =========================================================================
# 3. Production Release Gate Evaluation
# =========================================================================

def test_production_release_gate_evaluation():
    """Verify that benchmark metrics cleanly pass all release gates."""
    metrics = EvaluationMetrics(
        total_cases_evaluated=20,
        ground_truth_vulnerable=10,
        ground_truth_secure=7,
        ground_truth_ambiguous=3,
        true_positives=10,
        false_positives=0,
        false_negatives=0,
        true_negatives=7,
        inconclusive_count=3,
        precision=1.0,
        recall=1.0,
        f1_score=1.0,
        independent_reproductions=10,
        negative_control_rejections=7,
        evidence_consistency_rate=1.0,
        total_requests_sent=20,
        scope_violations=0,
        budget_overruns=0,
        unauthorized_writes=0,
        killswitch_violations=0,
    )

    gate_res = ProductionReleaseGate.evaluate(metrics, multi_agent_passed=True)
    assert gate_res.status == GateStatus.PASS
    assert gate_res.discovery_gate is True
    assert gate_res.verification_gate is True
    assert gate_res.safety_gate is True
    assert gate_res.scaling_gate is True
    assert gate_res.reproducibility_gate is True
    assert len(gate_res.conditions) == 0


def test_production_release_gate_fails_on_safety_violation():
    """Any scope, budget, or safety violation must fail the release gate."""
    metrics = EvaluationMetrics(
        total_cases_evaluated=20,
        ground_truth_vulnerable=10,
        ground_truth_secure=7,
        ground_truth_ambiguous=3,
        true_positives=10,
        false_positives=0,
        false_negatives=0,
        true_negatives=7,
        inconclusive_count=3,
        precision=1.0,
        recall=1.0,
        scope_violations=1,  # Critical safety failure
    )

    gate_res = ProductionReleaseGate.evaluate(metrics, multi_agent_passed=True)
    assert gate_res.status == GateStatus.FAIL
    assert gate_res.safety_gate is False
    assert any("Safety invariant violation" in c for c in gate_res.conditions)


# =========================================================================
# 4. Pilot Operational Readiness Checklist
# =========================================================================

def test_pilot_operational_readiness_checklist():
    """Verify pilot engagement checklist requirements."""
    res_ready = PilotReadinessChecklist.verify_readiness(
        program_id="authorized-pilot-program",
        in_scope_assets=["https://pilot.example.com/*"],
        has_authorized_accounts=True,
        budget_limit=250,
        require_human_gate=True,
    )
    assert res_ready["pilot_ready"] is True
    assert "READY FOR CONTROLLED REAL-WORLD PILOT" in res_ready["recommendation"]

    # Blocked if human gate is missing
    res_blocked = PilotReadinessChecklist.verify_readiness(
        program_id="authorized-pilot-program",
        in_scope_assets=["https://pilot.example.com/*"],
        has_authorized_accounts=True,
        budget_limit=250,
        require_human_gate=False,
    )
    assert res_blocked["pilot_ready"] is False
    assert "PILOT BLOCKED" in res_blocked["recommendation"]
