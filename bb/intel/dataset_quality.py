"""Dataset quality assessment: duplicate rates, CWE accuracy, and leakage checks."""
from __future__ import annotations

from typing import Any, Dict, List
from bb.intel.knowledge_base import KnowledgeBase


class DatasetQualityAuditor:
    """Audits dataset quality metrics, label consistency, and leakage."""

    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    def audit(self) -> Dict[str, Any]:
        """Perform comprehensive data quality audit."""
        st = self.kb.stats()
        total = st["total_reports"]

        with self.kb._get_connection() as conn:
            cur = conn.cursor()

            # Null CWE count
            cur.execute("SELECT COUNT(*) FROM reports WHERE cwe_id IS NULL OR cwe_id = ''")
            missing_cwe = cur.fetchone()[0]

            # Short text count (< 50 chars)
            cur.execute("SELECT COUNT(*) FROM reports WHERE LENGTH(summary) + LENGTH(vulnerability_details) < 50")
            insufficient_length = cur.fetchone()[0]

            # Ineligible records flagged as training eligible (leakage audit)
            cur.execute("SELECT COUNT(*) FROM reports WHERE training_eligible = 1 AND (source LIKE '%hackerone%' OR license = 'h1_disclosed_rag_only')")
            training_leakage_violations = cur.fetchone()[0]

        cwe_completeness = ((total - missing_cwe) / total * 100.0) if total > 0 else 100.0
        sufficient_content_rate = ((total - insufficient_length) / total * 100.0) if total > 0 else 100.0

        return {
            "total_records": total,
            "training_eligible_count": st["training_eligible_reports"],
            "rag_only_count": st["rag_only_reports"],
            "missing_cwe_count": missing_cwe,
            "cwe_completeness_pct": round(cwe_completeness, 2),
            "sufficient_content_pct": round(sufficient_content_rate, 2),
            "training_leakage_violations": training_leakage_violations,
            "audit_passed": training_leakage_violations == 0,
        }
