"""Security Intelligence SQLite Storage and Provenance Store.

Manages persistent intelligence records, full-text lexical search, structured metadata,
version constraint evaluation, and hypothesis outcome tracking.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from bb.config import DATA, now_iso
from bb.intelligence.models import HypothesisOutcomeRecord, IntelligenceRecord, VersionConstraint
from bb.intelligence.versions import record_matches_component

INTELLIGENCE_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS intelligence_records (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_url TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    published_at TEXT,
    updated_at TEXT,
    affected_product TEXT,
    affected_component TEXT,
    version_constraints TEXT,
    cwe_ids TEXT,
    capec_ids TEXT,
    references_json TEXT,
    cvss_score REAL,
    severity TEXT,
    data_freshness TEXT,
    parse_status TEXT NOT NULL,
    meta TEXT
);

CREATE INDEX IF NOT EXISTS idx_intel_source ON intelligence_records(source);
CREATE INDEX IF NOT EXISTS idx_intel_vuln_class ON intelligence_records(vuln_class);
CREATE INDEX IF NOT EXISTS idx_intel_product ON intelligence_records(affected_product);

CREATE TABLE IF NOT EXISTS hypothesis_outcomes (
    hypothesis_id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    supporting_intelligence_ids TEXT,
    supporting_observations TEXT,
    proposed_test TEXT NOT NULL,
    executed INTEGER NOT NULL DEFAULT 0,
    result TEXT NOT NULL,
    verification_result TEXT,
    researcher_review TEXT,
    final_report_outcome TEXT,
    model_version TEXT,
    prompt_version TEXT,
    requests_cost INTEGER NOT NULL DEFAULT 0,
    duration_ms REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_hypo_program ON hypothesis_outcomes(program);
CREATE INDEX IF NOT EXISTS idx_hypo_vuln_class ON hypothesis_outcomes(vuln_class);
CREATE INDEX IF NOT EXISTS idx_hypo_result ON hypothesis_outcomes(result);

CREATE VIRTUAL TABLE IF NOT EXISTS intelligence_fts USING fts5(
    id,
    title,
    description,
    vuln_class,
    affected_product,
    affected_component
);
"""


def _compute_freshness(published_at: str | None, retrieved_at: str) -> str:
    """Calculates freshness bucket: fresh (<180 days), stale (>365 days), normal."""
    date_str = published_at or retrieved_at
    if not date_str:
        return "unknown"
    try:
        clean_date = date_str.split("T")[0]
        dt = datetime.strptime(clean_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        now_dt = datetime.now(timezone.utc)
        age_days = (now_dt - dt).days
        if age_days <= 180:
            return "fresh"
        elif age_days > 730:
            return "stale"
        return "normal"
    except Exception:
        return "normal"


class IntelligenceStore:
    """Persistent storage, indexing, and querying for the Security Intelligence Engine."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = DATA / "intelligence.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.executescript(INTELLIGENCE_SCHEMA)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    def upsert_record(self, record: IntelligenceRecord) -> bool:
        """Upsert a normalized intelligence record and maintain FTS index."""
        freshness = record.data_freshness or _compute_freshness(record.published_at, record.retrieved_at)
        vcs_json = json.dumps([vc.to_dict() for vc in record.version_constraints])
        cwes_json = json.dumps(record.cwe_ids)
        capecs_json = json.dumps(record.capec_ids)
        refs_json = json.dumps(record.references)
        meta_json = json.dumps(record.meta)

        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute("SELECT rowid FROM intelligence_records WHERE id = ?", (record.id,))
            existing = cursor.fetchone()

            if existing:
                rowid = existing["rowid"]
                # Update table
                cursor.execute(
                    """
                    UPDATE intelligence_records SET
                        source=?, source_id=?, source_url=?, title=?, description=?,
                        vuln_class=?, retrieved_at=?, published_at=?, updated_at=?,
                        affected_product=?, affected_component=?, version_constraints=?,
                        cwe_ids=?, capec_ids=?, references_json=?, cvss_score=?,
                        severity=?, data_freshness=?, parse_status=?, meta=?
                    WHERE id=?
                    """,
                    (
                        record.source, record.source_id, record.source_url, record.title,
                        record.description, record.vuln_class, record.retrieved_at,
                        record.published_at, record.updated_at, record.affected_product,
                        record.affected_component, vcs_json, cwes_json, capecs_json,
                        refs_json, record.cvss_score, record.severity, freshness,
                        record.parse_status, meta_json, record.id,
                    ),
                )
                # Re-index FTS cleanly
                cursor.execute("DELETE FROM intelligence_fts WHERE rowid = ?", (rowid,))
                cursor.execute(
                    """
                    INSERT INTO intelligence_fts(rowid, id, title, description, vuln_class, affected_product, affected_component)
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (rowid, record.id, record.title, record.description, record.vuln_class, record.affected_product, record.affected_component),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO intelligence_records (
                        id, source, source_id, source_url, title, description, vuln_class,
                        retrieved_at, published_at, updated_at, affected_product, affected_component,
                        version_constraints, cwe_ids, capec_ids, references_json, cvss_score,
                        severity, data_freshness, parse_status, meta
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.id, record.source, record.source_id, record.source_url, record.title,
                        record.description, record.vuln_class, record.retrieved_at,
                        record.published_at, record.updated_at, record.affected_product,
                        record.affected_component, vcs_json, cwes_json, capecs_json,
                        refs_json, record.cvss_score, record.severity, freshness,
                        record.parse_status, meta_json,
                    ),
                )
                rowid = cursor.lastrowid
                cursor.execute(
                    """
                    INSERT INTO intelligence_fts(rowid, id, title, description, vuln_class, affected_product, affected_component)
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (rowid, record.id, record.title, record.description, record.vuln_class, record.affected_product, record.affected_component),
                )
        return True

    def get_record(self, record_id: str) -> IntelligenceRecord | None:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM intelligence_records WHERE id = ?", (record_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_record(row)

    def _row_to_record(self, row: sqlite3.Row) -> IntelligenceRecord:
        vcs_raw = json.loads(row["version_constraints"] or "[]")
        vcs = [VersionConstraint.from_dict(v) for v in vcs_raw]
        cwes = json.loads(row["cwe_ids"] or "[]")
        capecs = json.loads(row["capec_ids"] or "[]")
        refs = json.loads(row["references_json"] or "[]")
        meta = json.loads(row["meta"] or "{}")

        return IntelligenceRecord(
            id=row["id"],
            source=row["source"],
            source_id=row["source_id"],
            source_url=row["source_url"],
            title=row["title"],
            description=row["description"],
            vuln_class=row["vuln_class"],
            retrieved_at=row["retrieved_at"],
            published_at=row["published_at"],
            updated_at=row["updated_at"],
            affected_product=row["affected_product"],
            affected_component=row["affected_component"],
            version_constraints=vcs,
            cwe_ids=cwes,
            capec_ids=capecs,
            references=refs,
            cvss_score=row["cvss_score"],
            severity=row["severity"],
            data_freshness=row["data_freshness"],
            parse_status=row["parse_status"],
            meta=meta,
        )

    def search(
        self,
        query: str | None = None,
        source: str | None = None,
        vuln_class: str | None = None,
        product: str | None = None,
        version: str | None = None,
        limit: int = 50,
    ) -> list[IntelligenceRecord]:
        """Search intelligence records using exact filters and FTS5 ranking."""
        cursor = self.conn.cursor()

        if query:
            clean_q = "".join(c if c.isalnum() or c in " _-" else " " for c in query).strip()
            tokens = [t for t in clean_q.split() if len(t) > 1]
            if tokens:
                fts_expr = " NEAR ".join(f'"{t}"*' for t in tokens)
                sql = """
                    SELECT r.* FROM intelligence_records r
                    JOIN intelligence_fts f ON r.rowid = f.rowid
                    WHERE intelligence_fts MATCH ?
                """
                params: list[Any] = [fts_expr]
            else:
                sql = "SELECT * FROM intelligence_records WHERE 1=1"
                params = []
        else:
            sql = "SELECT * FROM intelligence_records WHERE 1=1"
            params = []

        if source:
            sql += " AND source = ?"
            params.append(source)
        if vuln_class:
            sql += " AND vuln_class LIKE ?"
            params.append(f"%{vuln_class}%")
        if product:
            sql += " AND (affected_product LIKE ? OR description LIKE ?)"
            params.append(f"%{product}%")
            params.append(f"%{product}%")

        sql += " LIMIT ?"
        params.append(limit * 2)

        cursor.execute(sql, params)
        rows = cursor.fetchall()

        records = [self._row_to_record(r) for r in rows]

        if version and product:
            filtered = []
            for rec in records:
                matched, _ = record_matches_component(rec, product, version)
                if matched:
                    filtered.append(rec)
            return filtered[:limit]

        return records[:limit]

    # --- Hypothesis Outcome Persistence ---

    def record_hypothesis_outcome(self, outcome: HypothesisOutcomeRecord) -> None:
        """Persist a hypothesis outcome record for feedback loop analysis."""
        supp_intel = json.dumps(outcome.supporting_intelligence_ids)
        supp_obs = json.dumps(outcome.supporting_observations)

        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO hypothesis_outcomes (
                    hypothesis_id, program, endpoint, method, vuln_class,
                    supporting_intelligence_ids, supporting_observations, proposed_test,
                    executed, result, verification_result, researcher_review,
                    final_report_outcome, model_version, prompt_version, requests_cost,
                    duration_ms, created_at, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    outcome.hypothesis_id, outcome.program, outcome.endpoint, outcome.method,
                    outcome.vuln_class, supp_intel, supp_obs, outcome.proposed_test,
                    1 if outcome.executed else 0, outcome.result, outcome.verification_result,
                    outcome.researcher_review, outcome.final_report_outcome,
                    outcome.model_version, outcome.prompt_version, outcome.requests_cost,
                    outcome.duration_ms, outcome.created_at, outcome.notes,
                ),
            )

    def get_hypothesis_outcomes(
        self,
        program: str | None = None,
        vuln_class: str | None = None,
        result: str | None = None,
        limit: int = 100,
    ) -> list[HypothesisOutcomeRecord]:
        sql = "SELECT * FROM hypothesis_outcomes WHERE 1=1"
        params: list[Any] = []
        if program:
            sql += " AND program = ?"
            params.append(program)
        if vuln_class:
            sql += " AND vuln_class = ?"
            params.append(vuln_class)
        if result:
            sql += " AND result = ?"
            params.append(result)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        out = []
        for r in rows:
            out.append(
                HypothesisOutcomeRecord(
                    hypothesis_id=r["hypothesis_id"],
                    program=r["program"],
                    endpoint=r["endpoint"],
                    method=r["method"],
                    vuln_class=r["vuln_class"],
                    supporting_intelligence_ids=json.loads(r["supporting_intelligence_ids"] or "[]"),
                    supporting_observations=json.loads(r["supporting_observations"] or "[]"),
                    proposed_test=r["proposed_test"],
                    executed=bool(r["executed"]),
                    result=r["result"],
                    verification_result=r["verification_result"],
                    researcher_review=r["researcher_review"],
                    final_report_outcome=r["final_report_outcome"],
                    model_version=r["model_version"],
                    prompt_version=r["prompt_version"],
                    requests_cost=r["requests_cost"],
                    duration_ms=r["duration_ms"],
                    created_at=r["created_at"],
                    notes=r["notes"] or "",
                )
            )
        return out
