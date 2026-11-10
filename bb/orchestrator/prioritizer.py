"""Continuous Research Prioritizer (Strategic P9).

Combines:
- Empirical feedback (Laplace priors)
- P6 Security Intelligence (CVE CVSS/KEV, CWE, CAPEC, advisories)
- P8 Specialist role coverage
- Target endpoint and parameter coverage
- Historical duplicates and verification outcomes
- Resource and request costs
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Sequence

from bb import feedback
from bb.intelligence.models import IntelligenceRecord
from bb.orchestrator.specialists import SpecialistRole, SpecialistWorkerRegistry
from bb.orchestrator.task_protocol import TaskProtocol
from bb.store import Store
from bb.swarm import Task


@dataclass
class ResearchPriorityScore:
    task_fingerprint: str
    target: str
    kind: str
    specialist_role: str
    base_priority: int
    laplace_prior: float
    intel_boost: float
    coverage_score: float
    duplicate_penalty: float
    composite_score: float
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_fingerprint": self.task_fingerprint,
            "target": self.target,
            "kind": self.kind,
            "specialist_role": self.specialist_role,
            "composite_score": round(self.composite_score, 4),
            "laplace_prior": round(self.laplace_prior, 3),
            "intel_boost": round(self.intel_boost, 3),
            "coverage_score": round(self.coverage_score, 3),
            "duplicate_penalty": round(self.duplicate_penalty, 3),
            "explanation": self.explanation,
        }


class ContinuousPrioritizer:
    """Computes multidimensional continuous research priorities."""

    def __init__(self, store: Store, program: str):
        self.store = store
        self.program = program
        self.specialists = SpecialistWorkerRegistry()

    def rank_backlog(
        self,
        tasks: Sequence[Task | TaskProtocol],
        intel_records: Sequence[IntelligenceRecord] | None = None,
    ) -> list[tuple[Task | TaskProtocol, ResearchPriorityScore]]:
        """Rank investigation backlog deterministically. Highest composite score first."""
        priors = feedback.class_priors(self.store, program=self.program)

        # Build quick lookup for historical outcomes and duplicates
        outcomes_rows = self.store.conn.execute(
            "SELECT f.bug_class, o.status, COUNT(*) as cnt FROM findings f "
            "JOIN outcomes o ON f.id = o.finding_id GROUP BY f.bug_class, o.status"
        ).fetchall()
        dup_by_class: dict[str, int] = {}
        total_by_class: dict[str, int] = {}
        for r in outcomes_rows:
            bc = r["bug_class"] or "unknown"
            cnt = r["cnt"]
            total_by_class[bc] = total_by_class.get(bc, 0) + cnt
            if r["status"] == "duplicate":
                dup_by_class[bc] = dup_by_class.get(bc, 0) + cnt

        # Technology / CVE intel keywords
        intel_keywords: set[str] = set()
        if intel_records:
            for rec in intel_records:
                intel_keywords.update(t.lower() for t in rec.cwe_ids)
                intel_keywords.update(rec.id.lower().split("-"))

        ranked: list[tuple[Task | TaskProtocol, ResearchPriorityScore]] = []

        for t in tasks:
            kind = t.kind.lower()
            role = self.specialists.select_role_for_task(kind)

            # 1. Base priority from task (1-10 scale, default 5 -> normalized 0.1-1.0)
            base_p = getattr(t, "priority", 5)
            norm_base = max(0.1, min(1.0, (11 - base_p) / 10.0))

            # 2. Laplace prior from program outcomes
            class_prior_data = priors.get(kind, {"weight": 0.5})
            laplace = float(class_prior_data.get("weight", 0.5))

            # 3. Security Intelligence boost
            intel_boost = 0.0
            reasons = []
            if intel_records:
                for rec in intel_records:
                    if kind in ("authz", "idor") and any("284" in w or "285" in w or "639" in w for w in rec.cwe_ids):
                        intel_boost = max(intel_boost, 0.4)
                        reasons.append(f"matched access-control intel ({rec.id})")
                    elif kind == "cors" and any("942" in w for w in rec.cwe_ids):
                        intel_boost = max(intel_boost, 0.3)
                        reasons.append(f"matched CORS intel ({rec.id})")
                    elif kind == "graphql" and "graphql" in rec.title.lower():
                        intel_boost = max(intel_boost, 0.35)
                        reasons.append("matched GraphQL advisory")

            # 4. Coverage score (bonus for unvisited endpoints / routes)
            coverage_score = 0.5
            target_str = t.target
            seen_exchanges = self.store.conn.execute(
                "SELECT COUNT(*) FROM exchanges WHERE url LIKE ?",
                (f"%{target_str[:50]}%",)
            ).fetchone()[0]
            if seen_exchanges == 0:
                coverage_score = 0.9
                reasons.append("fresh unexplored surface")
            elif seen_exchanges < 3:
                coverage_score = 0.7
            else:
                coverage_score = 0.3
                reasons.append("previously explored surface")

            # 5. Duplicate history penalty
            dup_pen = 0.0
            tot = total_by_class.get(kind, 0)
            if tot >= 3:
                dup_rate = dup_by_class.get(kind, 0) / tot
                if dup_rate > 0.3:
                    dup_pen = min(0.5, dup_rate * 0.5)
                    reasons.append(f"high duplicate history ({dup_rate:.0%})")

            # Composite formula:
            # Score = 0.25 * base + 0.30 * laplace + 0.25 * intel + 0.20 * coverage - dup_penalty
            comp = (
                0.25 * norm_base +
                0.30 * laplace +
                0.25 * intel_boost +
                0.20 * coverage_score -
                dup_pen
            )
            comp = max(0.01, min(1.0, comp))

            expl = "; ".join(reasons) if reasons else "baseline heuristic prioritization"
            score_obj = ResearchPriorityScore(
                task_fingerprint=t.fingerprint,
                target=target_str,
                kind=kind,
                specialist_role=role.role_id,
                base_priority=base_p,
                laplace_prior=laplace,
                intel_boost=intel_boost,
                coverage_score=coverage_score,
                duplicate_penalty=dup_pen,
                composite_score=comp,
                explanation=expl,
            )
            ranked.append((t, score_obj))

        ranked.sort(key=lambda pair: pair[1].composite_score, reverse=True)
        return ranked
