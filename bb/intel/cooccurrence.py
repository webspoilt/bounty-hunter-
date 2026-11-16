"""CWE Co-occurrence calculations, conditional probability P(B|A), Lift(A,B), and statistical gating."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import math
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CooccurrenceMetric:
    """Statistical association metric between two weaknesses A and B."""
    cwe_a: str
    cwe_b: str
    count_a: int
    count_b: int
    count_both: int
    prob_b_given_a: float  # P(B|A)
    prob_a_given_b: float  # P(A|B)
    lift: float            # P(A,B) / (P(A) * P(B))
    is_significant: bool   # Satisfies minimum sample size gate


class CooccurrenceEngine:
    """Calculates weakness co-occurrences and architectural risk metrics."""

    def __init__(self, min_sample_size: int = 5, min_cooccurrence: int = 2):
        self.min_sample_size = min_sample_size
        self.min_cooccurrence = min_cooccurrence
        # Report or system item -> set of CWEs observed
        self.entity_cwes: Dict[str, Set[str]] = defaultdict(set)

    def record_observation(self, entity_id: str, cwe_id: str) -> None:
        """Record an observed CWE on an entity (e.g. program or repository)."""
        if cwe_id:
            self.entity_cwes[entity_id].add(cwe_id.upper().strip())

    def record_report(self, report_id: str, cwes: List[str]) -> None:
        """Record multiple CWEs related to a single report or assessment."""
        for cwe in cwes:
            if cwe:
                self.entity_cwes[report_id].add(cwe.upper().strip())

    def compute_metrics(self) -> Dict[Tuple[str, str], CooccurrenceMetric]:
        """Compute P(B|A), Lift, and sample-size gating across all pairs."""
        total_entities = len(self.entity_cwes)
        if total_entities == 0:
            return {}

        cwe_counts: Dict[str, int] = defaultdict(int)
        pair_counts: Dict[Tuple[str, str], int] = defaultdict(int)

        for entity_id, cwes in self.entity_cwes.items():
            cwe_list = sorted(list(cwes))
            for cwe in cwe_list:
                cwe_counts[cwe] += 1
            for i in range(len(cwe_list)):
                for j in range(len(cwe_list)):
                    if i != j:
                        pair_counts[(cwe_list[i], cwe_list[j])] += 1

        results: Dict[Tuple[str, str], CooccurrenceMetric] = {}

        for (a, b), count_both in pair_counts.items():
            count_a = cwe_counts[a]
            count_b = cwe_counts[b]

            p_a = count_a / total_entities
            p_b = count_b / total_entities
            p_both = count_both / total_entities

            p_b_given_a = count_both / count_a if count_a > 0 else 0.0
            p_a_given_b = count_both / count_b if count_b > 0 else 0.0

            # Lift = P(A,B) / (P(A) * P(B))
            lift = (p_both / (p_a * p_b)) if (p_a * p_b) > 0 else 1.0

            # Statistical gating: require minimum samples to prevent noise on rare events
            is_sig = (count_a >= self.min_sample_size and count_both >= self.min_cooccurrence)

            metric = CooccurrenceMetric(
                cwe_a=a,
                cwe_b=b,
                count_a=count_a,
                count_b=count_b,
                count_both=count_both,
                prob_b_given_a=round(p_b_given_a, 4),
                prob_a_given_b=round(p_a_given_b, 4),
                lift=round(lift, 4),
                is_significant=is_sig,
            )
            results[(a, b)] = metric

        return results

    def get_associated_weaknesses(self, cwe_id: str, min_lift: float = 1.2) -> List[CooccurrenceMetric]:
        """Find associated weaknesses when cwe_id is observed, ordered by Lift."""
        target = cwe_id.upper().strip()
        metrics = self.compute_metrics()
        candidates: List[CooccurrenceMetric] = []
        for (a, b), m in metrics.items():
            if a == target and m.lift >= min_lift:
                candidates.append(m)
        candidates.sort(key=lambda m: (m.is_significant, m.lift, m.prob_b_given_a), reverse=True)
        return candidates
