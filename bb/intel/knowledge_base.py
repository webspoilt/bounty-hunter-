"""Persistent SQLite-backed Vulnerability Knowledge Base with FTS5 full-text indexing."""
from __future__ import annotations

import json
import logging
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from bb.config import DATA
from bb.intel.hexbrain_models import HexBrainReport, HexBrainTechnique
from bb.intel.chunking import VulnerabilityChunk, chunk_vulnerability_report
from bb.intel.hexbrain_search import normalize_cwe_id

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """Persistent local vulnerability knowledge base with SQLite relational store and FTS5 search."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path is not None else (DATA / "vulnerability_kb.db")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            # 1. Reports metadata table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    cwe_id TEXT,
                    cwe_title TEXT,
                    vulnerability_type TEXT,
                    severity TEXT,
                    bounty_amount REAL,
                    disclosed_at TEXT,
                    program_handle TEXT,
                    program_name TEXT,
                    summary TEXT,
                    vulnerability_details TEXT,
                    reproduction_steps TEXT,
                    impact TEXT,
                    remediation TEXT,
                    technologies_json TEXT,
                    tags_json TEXT,
                    license TEXT,
                    training_eligible INTEGER,
                    created_at REAL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rep_cwe ON reports (cwe_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rep_program ON reports (program_handle)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rep_training ON reports (training_eligible)")

            # 2. Semantic chunks table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chunks (
                    chunk_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    section TEXT NOT NULL,
                    content TEXT NOT NULL,
                    cwe_id TEXT,
                    technologies_json TEXT,
                    training_eligible INTEGER,
                    FOREIGN KEY (report_id) REFERENCES reports (report_id) ON DELETE CASCADE
                )
                """
            )

            # 3. Techniques table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS techniques (
                    technique_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    cwe_id TEXT,
                    vulnerability_type TEXT,
                    description TEXT,
                    payload_examples_json TEXT,
                    source TEXT,
                    confidence REAL,
                    metadata_json TEXT
                )
                """
            )

            # 4. FTS5 Full-Text Search virtual table for reports
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS reports_fts USING fts5(
                    report_id UNINDEXED,
                    title,
                    summary,
                    vulnerability_details,
                    reproduction_steps,
                    impact,
                    tokenize='porter'
                )
                """
            )

            conn.commit()

    def store_report(self, report: HexBrainReport) -> None:
        """Insert or replace report and index its chunks and FTS5 records."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO reports (
                    report_id, title, source, source_url, cwe_id, cwe_title,
                    vulnerability_type, severity, bounty_amount, disclosed_at,
                    program_handle, program_name, summary, vulnerability_details,
                    reproduction_steps, impact, remediation, technologies_json,
                    tags_json, license, training_eligible, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.report_id,
                    report.title,
                    report.source,
                    report.source_url,
                    report.cwe_id,
                    report.cwe_title,
                    report.vulnerability_type,
                    report.severity,
                    report.bounty_amount,
                    report.disclosed_at,
                    report.program_handle,
                    report.program_name,
                    report.summary,
                    report.vulnerability_details,
                    report.reproduction_steps,
                    report.impact,
                    report.remediation,
                    json.dumps(report.technologies),
                    json.dumps(report.tags),
                    report.license,
                    1 if report.training_eligible else 0,
                    now,
                ),
            )

            # Delete old FTS entry and insert new
            cursor.execute("DELETE FROM reports_fts WHERE report_id = ?", (report.report_id,))
            cursor.execute(
                """
                INSERT INTO reports_fts (report_id, title, summary, vulnerability_details, reproduction_steps, impact)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    report.report_id,
                    report.title,
                    report.summary,
                    report.vulnerability_details,
                    report.reproduction_steps,
                    report.impact,
                ),
            )

            # Insert semantic chunks
            cursor.execute("DELETE FROM chunks WHERE report_id = ?", (report.report_id,))
            chunks = chunk_vulnerability_report(report)
            for ch in chunks:
                cursor.execute(
                    """
                    INSERT INTO chunks (chunk_id, report_id, section, content, cwe_id, technologies_json, training_eligible)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ch.chunk_id,
                        ch.report_id,
                        ch.section,
                        ch.content,
                        ch.cwe_id,
                        json.dumps(ch.technologies),
                        1 if ch.training_eligible else 0,
                    ),
                )

            conn.commit()

    def store_technique(self, tech: HexBrainTechnique) -> None:
        """Store exploit technique or methodology pattern."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO techniques (
                    technique_id, name, cwe_id, vulnerability_type, description,
                    payload_examples_json, source, confidence, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tech.technique_id,
                    tech.name,
                    tech.cwe_id,
                    tech.vulnerability_type,
                    tech.description,
                    json.dumps(tech.payload_examples),
                    tech.source,
                    tech.confidence,
                    json.dumps(tech.metadata),
                ),
            )
            conn.commit()

    def get_report(self, report_id: str) -> Optional[HexBrainReport]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_report(row)

    def count_reports(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM reports")
            return cursor.fetchone()[0]

    def count_chunks(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM chunks")
            return cursor.fetchone()[0]

    def count_techniques(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM techniques")
            return cursor.fetchone()[0]

    def stats(self) -> Dict[str, Any]:
        """Aggregate knowledge base statistics."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM reports")
            total_reports = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM reports WHERE training_eligible = 1")
            training_eligible = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT cwe_id) FROM reports WHERE cwe_id IS NOT NULL")
            distinct_cwes = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT program_handle) FROM reports WHERE program_handle IS NOT NULL")
            distinct_programs = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM chunks")
            total_chunks = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM techniques")
            total_techniques = cur.fetchone()[0]

            return {
                "total_reports": total_reports,
                "training_eligible_reports": training_eligible,
                "rag_only_reports": total_reports - training_eligible,
                "distinct_cwes": distinct_cwes,
                "distinct_programs": distinct_programs,
                "total_chunks": total_chunks,
                "total_techniques": total_techniques,
                "db_path": str(self.db_path),
            }

    @staticmethod
    def _row_to_report(row: sqlite3.Row) -> HexBrainReport:
        return HexBrainReport(
            report_id=row["report_id"],
            title=row["title"],
            source=row["source"],
            source_url=row["source_url"],
            cwe_id=row["cwe_id"],
            cwe_title=row["cwe_title"],
            vulnerability_type=row["vulnerability_type"] or "generic",
            severity=row["severity"] or "unknown",
            bounty_amount=float(row["bounty_amount"] or 0.0),
            disclosed_at=row["disclosed_at"],
            program_handle=row["program_handle"],
            program_name=row["program_name"],
            summary=row["summary"] or "",
            vulnerability_details=row["vulnerability_details"] or "",
            reproduction_steps=row["reproduction_steps"] or "",
            impact=row["impact"] or "",
            remediation=row["remediation"] or "",
            technologies=json.loads(row["technologies_json"] or "[]"),
            tags=json.loads(row["tags_json"] or "[]"),
            license=row["license"] or "custom",
            training_eligible=bool(row["training_eligible"]),
        )
