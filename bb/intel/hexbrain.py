"""High-level HexBrain engine adapter integrating with Bounty Hunter architecture."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from bb.intel.hexbrain_client import HexBrainClient
from bb.intel.hexbrain_models import HexBrainReport, HexBrainTechnique
from bb.intel.hexbrain_search import build_search_query

logger = logging.getLogger(__name__)


class HexBrainEngine:
    """HexBrain Intelligence engine facade providing unified querying and diagnostics."""

    def __init__(self, client: Optional[HexBrainClient] = None):
        self.client = client if client is not None else HexBrainClient()

    def status(self) -> Dict[str, Any]:
        """Check operational status of the HexBrain integration."""
        diag = self.client.test_connection()
        return {
            "engine": "hexbrain",
            "api_configured": bool(self.client.api_key),
            "status": diag["status"],
            "message": diag["message"],
            "dataset_stats": diag["dataset_stats"],
            "base_url": self.client.base_url,
        }

    def search(
        self,
        query: str,
        cwe: Optional[str] = None,
        vuln_type: Optional[str] = None,
        technology: Optional[str] = None,
        program: Optional[str] = None,
        limit: int = 10,
    ) -> List[HexBrainReport]:
        """Execute a normalized search query."""
        sq = build_search_query(
            raw_query=query,
            cwe=cwe,
            vuln_type=vuln_type,
            technology=technology,
            program=program,
            limit=limit,
        )
        return self.client.search_reports(
            query=sq.query,
            cwe_id=sq.cwe_id,
            vulnerability_type=sq.vulnerability_type,
            technology=sq.technology,
            program=sq.program,
            limit=sq.limit,
            offset=sq.offset,
        )

    def get_techniques_for_weakness(self, cwe_id: str) -> List[HexBrainTechnique]:
        """Retrieve technique guidance for a given CWE weakness."""
        return self.client.get_techniques(cwe_id=cwe_id)
