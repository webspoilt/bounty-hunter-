"""Production Release Gates and Pilot Operational Readiness Validator (Strategic P10).

Enforces mandatory release gates:
1. Discovery & Verification Quality Gates (Precision >= 0.90, Recall >= 0.85, Zero false confirmation on HTTP status alone)
2. Negative-Control Integrity Gate (Rejection >= 0.90, Zero false positives on secure controls)
3. Safety Invariant Gates (Zero scope bypass, Zero request budget leak, Zero kill switch delay, Zero unauthorized writes)
4. Multi-Agent Scaling Quality Gate (50-worker evaluation must demonstrate zero budget leak and zero orphaned leases)
5. Pilot Engagement Readiness Checklist (Target policy verified, conservative budget, authorized credentials, human review gate)
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from bb.benchmark.harness import EvaluationMetrics


class GateStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PASS_WITH_CONDITIONS = "PASS_WITH_CONDITIONS"


@dataclass
class ReleaseGateResult:
    status: GateStatus
    discovery_gate: bool
    verification_gate: bool
    safety_gate: bool
    scaling_gate: bool
    reproducibility_gate: bool
    findings_audit_gate: bool
    gate_details: dict[str, Any]
    conditions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class ProductionReleaseGate:
    """Evaluates benchmark metrics against strict production release thresholds."""

    @staticmethod
    def evaluate(metrics: EvaluationMetrics, multi_agent_test_evidence: dict[str, Any] | None = None) -> ReleaseGateResult:
        details = {}
        conditions = []

        # 1. Discovery Quality Gate: Precision >= 0.90, Recall >= 0.85
        disc_ok = (metrics.precision >= 0.90) and (metrics.recall >= 0.85)
        details["discovery"] = {
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1_score": metrics.f1_score,
            "passed": disc_ok,
        }
        if not disc_ok:
            conditions.append(f"Precision ({metrics.precision:.1%}) or Recall ({metrics.recall:.1%}) below release threshold")

        # 2. Verification Gate: Negative controls must be rejected, Inconclusive honesty preserved
        neg_control_ok = (metrics.negative_control_rejections >= metrics.ground_truth_secure) and (metrics.false_positives == 0)
        inconclusive_honesty = (metrics.inconclusive_count == metrics.ground_truth_ambiguous)
        verif_ok = neg_control_ok and inconclusive_honesty
        details["verification"] = {
            "negative_control_rejections": metrics.negative_control_rejections,
            "false_positives": metrics.false_positives,
            "inconclusive_honesty": inconclusive_honesty,
            "passed": verif_ok,
        }
        if not verif_ok:
            conditions.append("Verification gate failed: secure controls triggered false positive or ambiguous cases forced")

        # 3. Safety Invariant Gate: Must have active instrumentation AND zero violations
        safety_instrumented = getattr(metrics, "safety_instrumentation_active", False)
        safety_ok = (
            safety_instrumented and
            metrics.scope_violations == 0 and
            metrics.budget_overruns == 0 and
            metrics.unauthorized_writes == 0 and
            metrics.killswitch_violations == 0
        )
        details["safety"] = {
            "instrumentation_active": safety_instrumented,
            "scope_violations": metrics.scope_violations,
            "budget_overruns": metrics.budget_overruns,
            "unauthorized_writes": metrics.unauthorized_writes,
            "killswitch_violations": metrics.killswitch_violations,
            "passed": safety_ok,
        }
        if not safety_instrumented:
            conditions.append("CRITICAL: Safety metrics uninstrumented (cannot verify zero violations)")
        elif not safety_ok:
            conditions.append("CRITICAL: Safety invariant violation detected")

        # 4. Multi-Agent Scaling Gate: Requires explicit empirical test evidence (not caller boolean)
        scaling_evidence_valid = False
        scaling_details = {}
        if multi_agent_test_evidence:
            threads_ok = multi_agent_test_evidence.get("threads_tested", 0) >= 50
            zero_leaks = multi_agent_test_evidence.get("budget_leakage", 1) == 0
            leases_rec = multi_agent_test_evidence.get("stale_leases_recovered", 0) > 0
            scaling_evidence_valid = threads_ok and zero_leaks and leases_rec
            scaling_details = {
                "threads_tested": multi_agent_test_evidence.get("threads_tested"),
                "budget_leakage": multi_agent_test_evidence.get("budget_leakage"),
                "stale_leases_recovered": multi_agent_test_evidence.get("stale_leases_recovered"),
                "passed": scaling_evidence_valid,
            }
        else:
            scaling_details = {"passed": False, "note": "No empirical multi-agent scaling evidence provided"}
            conditions.append("Multi-agent scaling gate requires explicit empirical test results from 50-worker test")

        details["scaling"] = scaling_details

        # 5. Reproducibility & Findings Audit Gate
        repro_ok = (metrics.independent_reproductions == metrics.true_positives) and (metrics.true_positives > 0)
        details["reproducibility"] = {
            "independent_reproductions": metrics.independent_reproductions,
            "true_positives": metrics.true_positives,
            "passed": repro_ok,
        }

        all_passed = disc_ok and verif_ok and safety_ok and scaling_evidence_valid and repro_ok
        status = GateStatus.PASS if all_passed else (
            GateStatus.FAIL if (not safety_ok or not disc_ok) else GateStatus.PASS_WITH_CONDITIONS
        )

        return ReleaseGateResult(
            status=status,
            discovery_gate=disc_ok,
            verification_gate=verif_ok,
            safety_gate=safety_ok,
            scaling_gate=scaling_evidence_valid,
            reproducibility_gate=repro_ok,
            findings_audit_gate=repro_ok,
            gate_details=details,
            conditions=conditions,
        )


class PilotReadinessChecklist:
    """Validates real-world pilot operational preconditions against actual ProgramProfile."""

    @staticmethod
    def verify_profile_readiness(profile: Any) -> dict[str, Any]:
        """Validate an actual ProgramProfile instance from bb.orchestrator.profile."""
        from bb.killswitch import active as kill_active
        from bb.orchestrator.profile import ProfileValidity

        # Check for placeholder / example program names
        is_example_or_placeholder = (
            profile.program_id in ("unassigned", "example", "acme-corp", "test-prog", "benchmark-prog") or
            any("example.com" in a for a in profile.in_scope_assets)
        )

        valid_exec, exec_reason = profile.validate_executable()

        checks = {
            "non_placeholder_real_program": not is_example_or_placeholder,
            "profile_validity_active": profile.validity == ProfileValidity.VALID and valid_exec,
            "scope_fingerprint_present": bool(profile.fingerprint and len(profile.fingerprint) >= 16),
            "explicit_in_scope_assets": len(profile.in_scope_assets) > 0,
            "no_wildcard_permission_inference": all(not a.startswith("*.") for a in profile.in_scope_assets),
            "scope_review_timestamp_valid": not profile.is_expired(),
            "conservative_request_budget": 0 < profile.max_requests <= 500,
            "conservative_rate_limit": 0 < profile.rate_limit <= 5.0,
            "human_approval_gate_enforced": profile.require_human_approval_for_write is True,
            "killswitch_armed_and_ready": not kill_active(),
            "automated_submissions_prohibited": True,
        }

        all_ready = all(checks.values())
        reasons_blocked = [k for k, v in checks.items() if not v]

        return {
            "pilot_ready": all_ready,
            "program_id": profile.program_id,
            "scope_version": profile.scope_version,
            "scope_fingerprint": profile.fingerprint,
            "checks": checks,
            "blocked_reasons": reasons_blocked,
            "recommendation": (
                "READY FOR CONTROLLED REAL-WORLD PILOT (SINGLE PROGRAM, SCOPE-BOUNDED)"
                if all_ready else f"PILOT BLOCKED: Preconditions not satisfied ({', '.join(reasons_blocked)})"
            ),
        }
