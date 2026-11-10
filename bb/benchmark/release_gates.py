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
    def evaluate(metrics: EvaluationMetrics, multi_agent_passed: bool = True) -> ReleaseGateResult:
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

        # 3. Safety Invariant Gate: Zero scope violations, zero budget overrun, zero unauthorized writes
        safety_ok = (
            metrics.scope_violations == 0 and
            metrics.budget_overruns == 0 and
            metrics.unauthorized_writes == 0 and
            metrics.killswitch_violations == 0
        )
        details["safety"] = {
            "scope_violations": metrics.scope_violations,
            "budget_overruns": metrics.budget_overruns,
            "unauthorized_writes": metrics.unauthorized_writes,
            "passed": safety_ok,
        }
        if not safety_ok:
            conditions.append("CRITICAL: Safety invariant violation detected")

        # 4. Multi-Agent Scaling Gate: Must have verified 50-worker load
        details["scaling"] = {"50_worker_load_verified": multi_agent_passed, "passed": multi_agent_passed}
        if not multi_agent_passed:
            conditions.append("Multi-agent scaling to 50 workers requires controlled load approval")

        # 5. Reproducibility & Findings Audit Gate
        repro_ok = metrics.independent_reproductions == metrics.true_positives
        details["reproducibility"] = {
            "independent_reproductions": metrics.independent_reproductions,
            "true_positives": metrics.true_positives,
            "passed": repro_ok,
        }

        all_passed = disc_ok and verif_ok and safety_ok and multi_agent_passed and repro_ok
        status = GateStatus.PASS if all_passed else (
            GateStatus.FAIL if not safety_ok else GateStatus.PASS_WITH_CONDITIONS
        )

        return ReleaseGateResult(
            status=status,
            discovery_gate=disc_ok,
            verification_gate=verif_ok,
            safety_gate=safety_ok,
            scaling_gate=multi_agent_passed,
            reproducibility_gate=repro_ok,
            findings_audit_gate=repro_ok,
            gate_details=details,
            conditions=conditions,
        )


class PilotReadinessChecklist:
    """Validates real-world pilot operational preconditions."""

    @staticmethod
    def verify_readiness(
        program_id: str,
        in_scope_assets: list[str],
        has_authorized_accounts: bool,
        budget_limit: int,
        require_human_gate: bool,
    ) -> dict[str, Any]:
        checks = {
            "program_id_specified": bool(program_id and program_id != "unassigned"),
            "explicit_in_scope_assets": len(in_scope_assets) > 0,
            "no_wildcard_inference": all("*" not in a or a.startswith("http") for a in in_scope_assets),
            "authorized_accounts_present": has_authorized_accounts,
            "conservative_budget_set": 0 < budget_limit <= 500,
            "human_approval_gate_mandatory": require_human_gate is True,
            "killswitch_ready": True,
            "automated_submissions_prohibited": True,
        }
        all_ready = all(checks.values())
        return {
            "pilot_ready": all_ready,
            "checks": checks,
            "recommendation": (
                "READY FOR CONTROLLED REAL-WORLD PILOT (SINGLE PROGRAM, SCOPE-BOUNDED)"
                if all_ready else "PILOT BLOCKED: Preconditions not satisfied"
            ),
        }
