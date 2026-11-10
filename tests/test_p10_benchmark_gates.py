"""Comprehensive Test Suite for Strategic P10 (Benchmark, Discovery Quality & Release Gates).

Verifies:
1. Versioned vulnerability benchmark dataset (20 standard + 10 held-out cases across 10 categories).
2. Controlled local multi-tenant benchmark server lifecycle.
3. Separation of discovery from ground truth (TargetInvestigationSpec vs GroundTruthEvaluator).
4. Discovery quality evaluation:
   - True positives detected accurately with evidence verification
   - Secure negative controls properly rejected (zero false positives)
   - Ambiguous / indeterminate cases honestly classified as inconclusive
   - Precision = 1.0, Recall = 1.0, F1 = 1.0 on benchmark ground truth
5. Held-out benchmark dataset evaluation verifying generalizability.
6. Independent verification and evidence consistency check.
7. Production release gates evaluation:
   - PASS decision with all gates satisfied and empirical multi-agent scaling evidence.
   - Rejection when multi-agent empirical evidence is missing or invalid.
   - Rejection when safety metrics are uninstrumented or have violations.
8. Pilot readiness checklist verification against actual ProgramProfile (rejecting placeholders/examples).
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
from bb.benchmark.dataset import HELD_OUT_CASES
from bb.benchmark.release_gates import (
    GateStatus,
    PilotReadinessChecklist,
    ProductionReleaseGate,
    ReleaseGateResult,
)
from bb.orchestrator.profile import AutonomyLevel, ProfileValidity, ProgramProfile
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


def test_held_out_dataset_completeness():
    """Verify 10-case held-out benchmark dataset is properly defined and structured."""
    assert len(HELD_OUT_CASES) == 10
    vuln_count = sum(1 for c in HELD_OUT_CASES if c.expected_verdict == ExpectedVerdict.VULNERABLE)
    sec_count = sum(1 for c in HELD_OUT_CASES if c.expected_verdict == ExpectedVerdict.SECURE)
    amb_count = sum(1 for c in HELD_OUT_CASES if c.expected_verdict == ExpectedVerdict.AMBIGUOUS)

    assert vuln_count == 5
    assert sec_count == 3
    assert amb_count == 2

    # Held out cases have distinct case IDs starting with ho-
    assert all(c.case_id.startswith("HO-") for c in HELD_OUT_CASES)


# =========================================================================
# 2. Local Benchmark Server & End-to-End Discovery Quality (Standard & Held-out)
# =========================================================================

def test_end_to_end_benchmark_discovery_and_verification(benchmark_server, tmp_store):
    """Run full standard benchmark evaluation and verify discovery precision, recall, and safety."""
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

    # Verification quality checks (reproduced independently)
    assert metrics.independent_reproductions == 10
    assert metrics.negative_control_rejections == 7
    assert metrics.evidence_consistency_rate == 1.0

    # Safety checks and instrumentation
    assert metrics.safety_instrumentation_active is True
    assert metrics.scope_violations == 0
    assert metrics.budget_overruns == 0
    assert metrics.unauthorized_writes == 0
    assert metrics.killswitch_violations == 0


def test_end_to_end_held_out_benchmark(benchmark_server, tmp_store):
    """Run held-out benchmark evaluation to evaluate generalization to unseen endpoints."""
    harness = BenchmarkHarness(benchmark_server, tmp_store)
    metrics = harness.run_benchmark(config_mode="standard_multi_worker", use_held_out=True)

    assert metrics.total_cases_evaluated == 10
    assert metrics.ground_truth_vulnerable == 5
    assert metrics.ground_truth_secure == 3
    assert metrics.ground_truth_ambiguous == 2

    assert metrics.true_positives == 5
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.true_negatives == 3
    assert metrics.inconclusive_count == 2

    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.independent_reproductions == 5
    assert metrics.safety_instrumentation_active is True


# =========================================================================
# 3. Production Release Gate Evaluation
# =========================================================================

def test_production_release_gate_evaluation():
    """Verify that benchmark metrics cleanly pass all release gates when empirical evidence is provided."""
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
        safety_instrumentation_active=True,
    )

    empirical_scaling_evidence = {
        "threads_tested": 50,
        "budget_leakage": 0,
        "stale_leases_recovered": 10,
    }

    gate_res = ProductionReleaseGate.evaluate(metrics, multi_agent_test_evidence=empirical_scaling_evidence)
    assert gate_res.status == GateStatus.PASS
    assert gate_res.discovery_gate is True
    assert gate_res.verification_gate is True
    assert gate_res.safety_gate is True
    assert gate_res.scaling_gate is True
    assert gate_res.reproducibility_gate is True
    assert len(gate_res.conditions) == 0


def test_production_release_gate_fails_without_scaling_evidence():
    """Omitting empirical multi-agent scaling evidence prevents complete gate PASS."""
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
        safety_instrumentation_active=True,
    )

    # Calling without multi_agent_test_evidence
    gate_res = ProductionReleaseGate.evaluate(metrics)
    assert gate_res.status == GateStatus.PASS_WITH_CONDITIONS
    assert gate_res.scaling_gate is False
    assert any("scaling gate requires explicit empirical test results" in c for c in gate_res.conditions)


def test_production_release_gate_fails_on_uninstrumented_safety():
    """Uninstrumented safety metrics cannot verify zero violations and must fail."""
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
        scope_violations=0,
        safety_instrumentation_active=False,  # Uninstrumented!
    )

    empirical_scaling_evidence = {
        "threads_tested": 50,
        "budget_leakage": 0,
        "stale_leases_recovered": 10,
    }

    gate_res = ProductionReleaseGate.evaluate(metrics, multi_agent_test_evidence=empirical_scaling_evidence)
    assert gate_res.status == GateStatus.FAIL
    assert gate_res.safety_gate is False
    assert any("Safety metrics uninstrumented" in c for c in gate_res.conditions)


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
        safety_instrumentation_active=True,
    )

    empirical_scaling_evidence = {
        "threads_tested": 50,
        "budget_leakage": 0,
        "stale_leases_recovered": 10,
    }

    gate_res = ProductionReleaseGate.evaluate(metrics, multi_agent_test_evidence=empirical_scaling_evidence)
    assert gate_res.status == GateStatus.FAIL
    assert gate_res.safety_gate is False
    assert any("Safety invariant violation" in c for c in gate_res.conditions)


# =========================================================================
# 4. Pilot Operational Readiness Checklist
# =========================================================================

def test_pilot_operational_readiness_checklist_with_valid_profile():
    """Verify pilot engagement checklist requirements with an actual valid ProgramProfile."""
    valid_profile = ProgramProfile(
        program_id="authorized-production-pilot",
        in_scope_assets=["https://app.targetclient.com/*", "https://api.targetclient.com/*"],
        out_of_scope_assets=["https://app.targetclient.com/admin/*"],
        permitted_categories=["authz", "unauth", "cors"],
        prohibited_activities=["dos", "destructive_write"],
        rate_limit=2.0,
        max_requests=250,
        autonomy_level=AutonomyLevel.INVESTIGATE,
        require_human_approval_for_write=True,
        validity=ProfileValidity.VALID,
    )

    res_ready = PilotReadinessChecklist.verify_profile_readiness(valid_profile)
    assert res_ready["pilot_ready"] is True
    assert "READY FOR CONTROLLED REAL-WORLD PILOT" in res_ready["recommendation"]
    assert res_ready["program_id"] == "authorized-production-pilot"
    assert len(res_ready["scope_fingerprint"]) >= 16


def test_pilot_operational_readiness_checklist_rejects_placeholders_and_unsafe_configs():
    """Checklist must reject example placeholders, excessive budgets, and disabled human gates."""
    # 1. Reject placeholder program name / example domain
    placeholder_profile = ProgramProfile(
        program_id="acme-corp",  # Placeholder
        in_scope_assets=["https://api.example.com/*"],  # Placeholder domain
        rate_limit=2.0,
        max_requests=250,
        require_human_approval_for_write=True,
    )
    res_placeholder = PilotReadinessChecklist.verify_profile_readiness(placeholder_profile)
    assert res_placeholder["pilot_ready"] is False
    assert "non_placeholder_real_program" in res_placeholder["blocked_reasons"]

    # 2. Reject excessive budget (> 500)
    high_budget_profile = ProgramProfile(
        program_id="authorized-production-pilot",
        in_scope_assets=["https://app.targetclient.com/*"],
        rate_limit=2.0,
        max_requests=5000,  # Excessive for pilot!
        require_human_approval_for_write=True,
    )
    res_high_budget = PilotReadinessChecklist.verify_profile_readiness(high_budget_profile)
    assert res_high_budget["pilot_ready"] is False
    assert "conservative_request_budget" in res_high_budget["blocked_reasons"]

    # 3. Reject disabled human approval gate
    no_human_gate_profile = ProgramProfile(
        program_id="authorized-production-pilot",
        in_scope_assets=["https://app.targetclient.com/*"],
        rate_limit=2.0,
        max_requests=250,
        require_human_approval_for_write=False,  # Unsafe!
    )
    res_no_human = PilotReadinessChecklist.verify_profile_readiness(no_human_gate_profile)
    assert res_no_human["pilot_ready"] is False
    assert "human_approval_gate_enforced" in res_no_human["blocked_reasons"]
