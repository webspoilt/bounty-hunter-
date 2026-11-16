"""Finding enrichment with historical context, CWE definitions, and similar reports."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from bb.intel.knowledge_base import KnowledgeBase
from bb.intel.ingestion.cwe import get_cwe_details
from bb.intel.retrieval import HybridRetriever


class FindingContextEnricher:
    """Enriches raw scanner or agent findings with historical context."""

    def __init__(self, kb: Optional[KnowledgeBase] = None):
        self.kb = kb or KnowledgeBase()
        self.retriever = HybridRetriever(kb=self.kb)

    def enrich(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Add CWE hierarchy, historical precedents, and remediation guidance to finding."""
        enriched = dict(finding)
        cwe_id = finding.get("cwe_id")

        if cwe_id:
            cwe_info = get_cwe_details(cwe_id)
            if cwe_info:
                enriched["cwe_canonical_name"] = cwe_info.get("name")
                enriched["owasp_2025"] = cwe_info.get("owasp_2025")
                enriched["cwe_description"] = cwe_info.get("description")

        # Find historical precedents
        title = finding.get("title", "")
        vuln_type = finding.get("type", "")
        hits = self.retriever.search(query=f"{title} {vuln_type}", cwe_id=cwe_id, limit=3)
        enriched["historical_precedents"] = [
            {
                "report_id": h["report"].report_id,
                "title": h["report"].title,
                "bounty": h["report"].bounty_amount,
                "source_url": h["report"].source_url,
            }
            for h in hits
        ]

        return enriched
