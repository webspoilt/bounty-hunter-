"""Hybrid retrieval engine combining exact metadata, CWE filters, FTS5 BM25, and semantic ranking."""
from __future__ import annotations

import logging
import sqlite3
from typing import Any, Dict, List, Optional

from bb.intel.hexbrain_models import HexBrainReport
from bb.intel.knowledge_base import KnowledgeBase
from bb.intel.hexbrain_search import build_search_query, normalize_cwe_id

logger = logging.getLogger(__name__)


class HybridRetriever:
    """Hybrid search combining SQLite relational filters and FTS5 ranking."""

    def __init__(self, kb: Optional[KnowledgeBase] = None):
        self.kb = kb or KnowledgeBase()

    def search(
        self,
        query: str,
        cwe_id: Optional[str] = None,
        technology: Optional[str] = None,
        program: Optional[str] = None,
        training_only: bool = False,
        limit: int = 10,
        use_live_hexbrain: bool = True,
    ) -> List[Dict[str, Any]]:
        """Perform hybrid retrieval across vulnerability knowledge base and live HexBrain API."""
        sq = build_search_query(
            raw_query=query,
            cwe=cwe_id,
            technology=technology,
            program=program,
            limit=limit,
            training_eligible=training_only,
        )

        with self.kb._get_connection() as conn:
            cursor = conn.cursor()

            # If full-text query term exists, use FTS5 join
            clean_terms = sq.query.replace('"', "").replace("'", "").strip()
            
            if clean_terms:
                # FTS5 query with BM25 rank
                # Sanitize tokens for FTS5 syntax
                fts_query = " OR ".join(f'"{term}"' for term in clean_terms.split() if len(term) > 1)
                if not fts_query:
                    fts_query = f'"{clean_terms}"'

                sql = """
                    SELECT r.*, fts.rank AS search_rank
                    FROM reports_fts fts
                    JOIN reports r ON fts.report_id = r.report_id
                    WHERE reports_fts MATCH ?
                """
                params: List[Any] = [fts_query]

                if sq.cwe_id:
                    sql += " AND r.cwe_id = ?"
                    params.append(sq.cwe_id)

                if sq.program:
                    sql += " AND r.program_handle = ?"
                    params.append(sq.program)

                if sq.require_training_eligible:
                    sql += " AND r.training_eligible = 1"

                sql += " ORDER BY fts.rank ASC LIMIT ?"
                params.append(sq.limit)

                try:
                    cursor.execute(sql, params)
                    rows = cursor.fetchall()
                except sqlite3.OperationalError as e:
                    logger.warning("FTS5 query failed (%s), falling back to LIKE filter", e)
                    rows = []
            else:
                rows = []

            # Fallback to exact/LIKE query if FTS yielded no results or query was empty
            if not rows:
                sql = "SELECT r.*, 0.0 AS search_rank FROM reports r WHERE 1=1"
                params = []

                if sq.cwe_id:
                    sql += " AND r.cwe_id = ?"
                    params.append(sq.cwe_id)

                if sq.program:
                    sql += " AND r.program_handle = ?"
                    params.append(sq.program)

                if sq.technology:
                    sql += " AND r.technologies_json LIKE ?"
                    params.append(f'%"{sq.technology}"%')

                if sq.require_training_eligible:
                    sql += " AND r.training_eligible = 1"

                if clean_terms:
                    sql += " AND (r.title LIKE ? OR r.summary LIKE ?)"
                    params.extend([f"%{clean_terms}%", f"%{clean_terms}%"])

                sql += " ORDER BY r.bounty_amount DESC LIMIT ?"
                params.append(sq.limit)

                cursor.execute(sql, params)
                rows = cursor.fetchall()

            results: List[Dict[str, Any]] = []
            for row in rows:
                rep = self.kb._row_to_report(row)
                rank = float(row["search_rank"]) if "search_rank" in row.keys() else 0.0
                results.append({
                    "report": rep,
                    "score": rank,
                    "source_provenance": "local_sqlite_kb",
                })

            # Live HexBrain integration: if live results enabled and we have budget, enrich
            if use_live_hexbrain and len(results) < sq.limit:
                try:
                    from bb.intel.hexbrain_client import HexBrainClient
                    client = HexBrainClient()
                    if client.api_key:
                        hex_reports = client.search_reports(
                            query=sq.query,
                            cwe_id=sq.cwe_id,
                            program=sq.program,
                            limit=sq.limit - len(results),
                        )
                        for h_rep in hex_reports:
                            # Index into local KB for persistent caching and future FTS
                            self.kb.store_report(h_rep)
                            results.append({
                                "report": h_rep,
                                "score": 0.5,
                                "source_provenance": "live_hexbrain_api",
                            })
                except Exception as e:
                    logger.debug("Live HexBrain retrieval fallback skipped: %s", e)

            return results
