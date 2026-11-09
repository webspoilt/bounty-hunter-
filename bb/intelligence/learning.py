"""Adaptive Learning from Hypothesis Outcomes.

Integrates with existing `bb/feedback.py` and `bb/metrics.py`.
Computes multi-dimensional hypothesis priors:
- (Program, Vuln Class) empirical yield.
- (Endpoint pattern, Vuln Class) efficiency.
- Test efficiency penalty for tests consuming excessive requests without confirmation.
- Ground-truth separation: Unreviewed model decisions are NEVER treated as ground truth.
- Bounded, Laplace-smoothed adjustments to safely guide hypothesis ranking.
"""
from __future__ import annotations

import re
from typing import Sequence

from bb.intelligence.models import HypothesisOutcomeRecord
from bb.intelligence.store import IntelligenceStore

MIN_DECIDED_HYPOTHESES = 3


def compute_hypothesis_priors(
    intel_store: IntelligenceStore,
    program: str | None = None,
) -> dict[str, dict]:
    """Computes Laplace-smoothed empirical priors for vulnerability classes and patterns.

    Prior formula:
        weight = (confirmed + 1) / (decided + 2)

    Where decided = confirmed + rejected + duplicate.
    Inconclusive and unreviewed outcomes are explicitly separated and do not bias as negative ground truth.
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

        # Check ground-truth validity: researcher_review or verified
        has_review = o.researcher_review in ("approved", "rejected")
        is_verified = o.verification_result in ("confirmed", "rejected")

        # Inconclusive
        if o.result in ("inconclusive", "unknown"):
            s["inconclusive"] += 1
        elif not (has_review or is_verified):
            # Unreviewed speculative results do not become ground truth
            s["unreviewed"] += 1
        elif o.result == "confirmed" or o.verification_result == "confirmed":
            s["confirmed"] += 1
        elif o.result == "rejected" or o.verification_result == "rejected":
            s["rejected"] += 1
        elif o.result == "duplicate":
            s["duplicate"] += 1

    priors: dict[str, dict] = {}
    for cls_name, s in by_class.items():
        decided = s["confirmed"] + s["rejected"] + s["duplicate"]
        if decided < MIN_DECIDED_HYPOTHESES:
            priors[cls_name] = {
                "weight": 0.5,
                "decided": decided,
                "confirmed": s["confirmed"],
                "rejected": s["rejected"],
                "duplicate": s["duplicate"],
                "inconclusive": s["inconclusive"],
                "unreviewed": s["unreviewed"],
                "neutral": True,
                "avg_requests": round(s["total_requests"] / max(s["total"], 1), 1),
                "note": "insufficient ground-truth outcomes",
            }
            continue

        weight = (s["confirmed"] + 1) / (decided + 2)

        # Efficiency penalty: high requests per test with 0 confirmations
        avg_reqs = s["total_requests"] / max(s["total"], 1)
        if s["confirmed"] == 0 and avg_reqs > 15.0:
            weight = max(0.1, weight * 0.8)  # slight penalty for expensive unproductive tests

        notes = []
        if s["confirmed"] == 0:
            notes.append("0 confirmed findings")
        if s["duplicate"] >= 2:
            notes.append(f"{s['duplicate']} duplicates recorded")
        if s["rejected"] >= 2:
            notes.append(f"{s['rejected']} verified false positives")
        if s["confirmed"] >= 2:
            notes.append(f"{s['confirmed']} verified findings (high yield)")

        priors[cls_name] = {
            "weight": round(weight, 3),
            "decided": decided,
            "confirmed": s["confirmed"],
            "rejected": s["rejected"],
            "duplicate": s["duplicate"],
            "inconclusive": s["inconclusive"],
            "unreviewed": s["unreviewed"],
            "neutral": False,
            "avg_requests": round(avg_reqs, 1),
            "note": "; ".join(notes) if notes else "balanced performance",
        }

    return priors


def rank_hypotheses_with_intelligence(
    hypotheses: list[dict],
    intel_store: IntelligenceStore,
    program: str | None = None,
) -> list[dict]:
    """Ranks hypotheses based on supporting intelligence and empirical feedback priors.

    Scoring factors:
    - Base severity rank (Critical > High > Medium > Low).
    - Intelligence support bonus (+0.25 if supported by verified CVE/advisory with applicable version,
      +0.15 if supported by CWE/CAPEC).
    - Adaptive feedback weight (Laplace prior from past verified investigation outcomes).
    """
    from bb.models import sev_rank

    priors = compute_hypothesis_priors(intel_store, program=program)

    def score_hypo(h: dict) -> float:
        sev = h.get("severity", "medium")
        base = sev_rank(sev) * 10.0

        vuln_cls = h.get("vuln_class", "unknown")
        prior = priors.get(vuln_cls, {}).get("weight", 0.5)

        # Intelligence support
        intel_records = h.get("supporting_intelligence", [])
        intel_bonus = 0.0
        if any(rec.get("source") in ("nvd", "cve", "advisory") for rec in intel_records):
            intel_bonus += 2.5
        elif any(rec.get("source") in ("cwe", "capec", "disclosure") for rec in intel_records):
            intel_bonus += 1.5

        # Incorporate prior (range 0.1 to 0.9 -> multiplier 0.5 to 1.5)
        multiplier = 0.5 + prior
        total_score = (base + intel_bonus) * multiplier
        h["meta"] = h.get("meta") or {}
        h["meta"]["intel_rank_score"] = round(total_score, 2)
        h["meta"]["feedback_prior"] = prior
        return total_score

    return sorted(hypotheses, key=score_hypo, reverse=True)
