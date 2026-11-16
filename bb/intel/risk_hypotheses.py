"""Architectural risk hypothesis generation and security assessment checklists."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from bb.intel.cooccurrence import CooccurrenceEngine, CooccurrenceMetric
from bb.intel.ingestion.cwe import get_cwe_details


@dataclass
class AssessmentHypothesis:
    """Actionable assessment recommendation based on observed architecture or prior findings."""
    hypothesis_id: str
    target_cwe: str
    target_name: str
    rationale: str
    confidence_lift: float
    recommended_checks: List[str] = field(default_factory=list)


def generate_hypotheses_for_weaknesses(
    observed_cwes: List[str],
    cooccurrence_engine: CooccurrenceEngine,
    min_lift: float = 1.2,
) -> List[AssessmentHypothesis]:
    """Given a set of confirmed or observed CWEs, produce hypotheses for related weaknesses."""
    hypotheses: List[AssessmentHypothesis] = []
    seen_targets = set(c.upper() for c in observed_cwes)

    for cwe in observed_cwes:
        assoc = cooccurrence_engine.get_associated_weaknesses(cwe, min_lift=min_lift)
        for m in assoc:
            if m.cwe_b in seen_targets:
                continue
            details = get_cwe_details(m.cwe_b)
            target_name = details["name"] if details else m.cwe_b

            rationale = (
                f"Observed {m.cwe_a}. Historical dataset indicates that applications with {m.cwe_a} "
                f"exhibit {m.cwe_b} with P(B|A)={m.prob_b_given_a * 100:.1f}% and Lift={m.lift:.2f}."
            )

            # Standard checklist recommendations based on CWE
            recs: List[str] = []
            if m.cwe_b in ("CWE-639", "CWE-862"):
                recs.extend([
                    "Verify horizontal tenant boundary checks on all REST path parameters.",
                    "Audit role-based authorization decorator coverage across administrative routes.",
                ])
            elif m.cwe_b in ("CWE-89", "CWE-79"):
                recs.extend([
                    "Audit database abstraction layers for unparameterized raw string formatting.",
                    "Verify context-aware output encoding across user-controlled response templates.",
                ])
            elif m.cwe_b == "CWE-918":
                recs.extend([
                    "Inspect avatar/webhook fetchers for loopback and cloud metadata (169.254.169.254) access.",
                ])
            else:
                recs.append(f"Execute targeted verification tests for weakness {m.cwe_b}.")

            hyp = AssessmentHypothesis(
                hypothesis_id=f"HYP-{m.cwe_a}-{m.cwe_b}",
                target_cwe=m.cwe_b,
                target_name=target_name,
                rationale=rationale,
                confidence_lift=m.lift,
                recommended_checks=recs,
            )
            hypotheses.append(hyp)
            seen_targets.add(m.cwe_b)

    hypotheses.sort(key=lambda h: h.confidence_lift, reverse=True)
    return hypotheses
