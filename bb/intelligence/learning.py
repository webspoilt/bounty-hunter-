"""Adaptive Learning from Hypothesis Outcomes.

Mathematical Rigor & Ground-Truth Separation:
1. Empirical Success Probability (Laplace smoothed):
       p_success = (confirmed + 1) / (decided + 2)
   where decided = confirmed + rejected.
   - Duplicates do NOT count as confirmed or rejected; they are tracked as duplicate_count.
   - Inconclusive results do NOT count as negative ground truth.
   - Unreviewed model outputs NEVER modify ground-truth priors.

2. Evidence Quality Metric:
       evidence_quality = confirmed / max(confirmed + rejected, 1)

3. Estimated Resource Cost:
       avg_requests_cost = total_requests / max(total_executions, 1)
       avg_latency_ms = total_duration_ms / max(total_executions, 1)

4. Cost-Adjusted Research Priority:
       cost_factor = 1.0 / (1.0 + log10(max(avg_requests_cost, 1.0)))
       cost_adjusted_priority = p_success * cost_factor

Integrates with existing `bb/feedback.py` and `bb/metrics.py`.
"""
from __future__ import annotations

import math
import re
from typing import Sequence

from bb.intelligence.models import HypothesisOutcomeRecord, IntelligenceRecord
from bb.intelligence.store import IntelligenceStore
from bb.intelligence.versions import (
    STATE_RELEVANT,
    evaluate_intelligence_relevance,
)

MIN_DECIDED_HYPOTHESES = 3


def compute_hypothesis_priors(
    intel_store: IntelligenceStore,
    program: str | None = None,
) -> dict[str, dict]:
    """Computes exact empirical success priors, evidence quality, and resource costs.

    Outcomes:
    - confirmed: Verified finding approved by researcher or independent 2-role verification.
    - rejected: Verified false positive disproven by verification or researcher.
    - duplicate: Valid reproduction of an existing finding; does NOT increment confirmed count.
    - inconclusive: Ambiguous test; isolated and neutral (does NOT bias as negative ground truth).
    - unreviewed: Untriaged model output; strictly ignored from ground-truth updates.
    """
    outcomes = intel_store.get_hypothesis_outcomes(program=program, limit=1000)

    by_class: dict[str, dict] = {}

    for o in outcomes:
        cls_name = o.vuln_class or "unknown"
        if cls_name not in by_class:
            by_class[cls_name] = {
                "total": 0,
                "confirmed": 0,
                "rejected": 0,
                "duplicate": 0,
                "inconclusive": 0,
                "unreviewed": 0,
                "total_requests": 0,
                "total_duration_ms": 0.0,
            }

        s = by_class[cls_name]
        s["total"] += 1
        s["total_requests"] += o.requests_cost
        s["total_duration_ms"] += o.duration_ms

        has_review = o.researcher_review in ("approved", "rejected")
        is_verified = o.verification_result in ("confirmed", "rejected")

        # Ground-truth filtering
        if o.result in ("inconclusive", "unknown"):
            s["inconclusive"] += 1
        elif not (has_review or is_verified):
            s["unreviewed"] += 1
        elif o.result == "duplicate" or o.final_report_outcome == "duplicate":
            s["duplicate"] += 1
        elif o.result == "confirmed" or o.verification_result == "confirmed":
            s["confirmed"] += 1
        elif o.result == "rejected" or o.verification_result == "rejected":
            s["rejected"] += 1

    priors: dict[str, dict] = {}
    for cls_name, s in by_class.items():
        # Decided excludes duplicates and inconclusive
        decided = s["confirmed"] + s["rejected"]
        total_exec = max(s["total"], 1)
        avg_reqs = round(s["total_requests"] / total_exec, 1)
        avg_lat = round(s["total_duration_ms"] / total_exec, 1)

        if decided < MIN_DECIDED_HYPOTHESES:
            priors[cls_name] = {
                "empirical_prior": 0.5,
                "weight": 0.5,  # legacy compatibility alias
                "evidence_quality": 0.0,
                "estimated_requests_cost": avg_reqs,
                "estimated_latency_ms": avg_lat,
                "cost_adjusted_priority": 0.5,
                "decided": decided,
                "confirmed": s["confirmed"],
                "rejected": s["rejected"],
                "duplicate": s["duplicate"],
                "inconclusive": s["inconclusive"],
                "unreviewed": s["unreviewed"],
                "neutral": True,
                "note": "insufficient ground-truth outcomes (<3 decided)",
            }
            continue

        # Mathematical Formula 1: Laplace smoothed success prior
        # p_success = (confirmed + 1) / (decided + 2)
        p_success = (s["confirmed"] + 1) / (decided + 2)

        # Mathematical Formula 2: Evidence Quality
        evidence_quality = s["confirmed"] / max(decided, 1)

        # Mathematical Formula 3: Cost-Adjusted Research Priority
        # Separates resource cost from empirical success probability
        cost_penalty = 1.0 / (1.0 + math.log10(max(avg_reqs, 1.0)))
        cost_adjusted = p_success * cost_penalty

        notes = []
        if s["confirmed"] == 0:
            notes.append(f"0 confirmed, {s['rejected']} verified false positives")
        if s["duplicate"] >= 1:
            notes.append(f"{s['duplicate']} duplicates recorded")
        if s["confirmed"] >= 2:
            notes.append(f"{s['confirmed']} verified findings (high yield)")

        priors[cls_name] = {
            "empirical_prior": round(p_success, 3),
            "weight": round(p_success, 3),  # compatibility alias
            "evidence_quality": round(evidence_quality, 3),
            "estimated_requests_cost": avg_reqs,
            "estimated_latency_ms": avg_lat,
            "cost_adjusted_priority": round(cost_adjusted, 3),
            "decided": decided,
            "confirmed": s["confirmed"],
            "rejected": s["rejected"],
            "duplicate": s["duplicate"],
            "inconclusive": s["inconclusive"],
            "unreviewed": s["unreviewed"],
            "neutral": False,
            "note": "; ".join(notes) if notes else "balanced empirical performance",
        }

    return priors


def rank_hypotheses_with_intelligence(
    hypotheses: list[dict],
    intel_store: IntelligenceStore,
    program: str | None = None,
) -> list[dict]:
    """Ranks hypotheses based on multi-dimensional intelligence relevance and empirical priors.

    Enforces:
    - Intelligence record must be verified 'relevant' across product, component, version,
      and vulnerability class to grant a confidence bonus.
    - Class mismatches, product mismatches, and version-match-only records yield NO bonus.
    - Separates empirical success probability from cost adjustments.
    """
    from bb.models import sev_rank

    priors = compute_hypothesis_priors(intel_store, program=program)

    def score_hypo(h: dict) -> float:
        sev = h.get("severity", "medium")
        base = sev_rank(sev) * 10.0

        vuln_cls = h.get("vuln_class", "unknown")
        prior_info = priors.get(vuln_cls, {})
        prior_weight = prior_info.get("empirical_prior", 0.5)

        # Target context for multi-dimensional relevance
        target_ctx = {
            "vendor": h.get("vendor"),
            "product": h.get("product"),
            "component": h.get("component"),
            "version": h.get("version"),
            "vuln_class": vuln_cls,
            "attack_surface": h.get("attack_surface", "web_application"),
            "cwe_id": h.get("cwe_id"),
        }

        # Evaluate Supporting Intelligence Multi-Dimensionally
        intel_records = h.get("supporting_intelligence", [])
        intel_bonus = 0.0
        relevance_evaluations = []

        for item in intel_records:
            rec = None
            if isinstance(item, IntelligenceRecord):
                rec = item
            elif isinstance(item, dict) and item.get("id"):
                rec = intel_store.get_record(item["id"])

            if rec:
                state, reason = evaluate_intelligence_relevance(rec, target_ctx)
                relevance_evaluations.append({"id": rec.id, "state": state, "reason": reason})

                # Only genuine multi-dimensional relevance yields an intelligence bonus!
                if state == STATE_RELEVANT:
                    if rec.source in ("nvd", "cve", "advisory"):
                        intel_bonus += 3.0
                    else:
                        intel_bonus += 1.5
                # version_match_only, class_mismatch, product_mismatch -> 0 bonus!

        # Compute total rank score
        multiplier = 0.5 + prior_weight
        total_score = (base + intel_bonus) * multiplier

        h["meta"] = h.get("meta") or {}
        h["meta"]["intel_rank_score"] = round(total_score, 2)
        h["meta"]["feedback_prior"] = prior_weight
        h["meta"]["cost_adjusted_priority"] = prior_info.get("cost_adjusted_priority", 0.5)
        h["meta"]["intelligence_relevance"] = relevance_evaluations
        return total_score

    # Deterministic tie-breaking on endpoint and hypothesis_id
    return sorted(
        hypotheses,
        key=lambda h: (score_hypo(h), h.get("endpoint", ""), h.get("hypothesis_id", "")),
        reverse=True,
    )
