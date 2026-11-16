"""Persistent SQLite storage for discovered programs, policy snapshots, and human selections."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional

from bb.config import DATA
from bb.programs.program_models import (
    AIClassification,
    DiscoveredProgram,
    PriorityTier,
    ProgramAsset,
    ProgramEligibilityState,
    ResearchOpportunity,
    ScoreCriterion,
)


class ProgramStore:
    """Thread-safe SQLite database for HackerOne program discovery intelligence."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path is not None else (DATA / "h1_programs.db")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS programs (
                    handle TEXT PRIMARY KEY,
                    program_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    state TEXT NOT NULL,
                    submission_state TEXT NOT NULL,
                    offers_bounties INTEGER NOT NULL,
                    currency TEXT,
                    min_bounty REAL,
                    max_bounty REAL,
                    policy_text TEXT,
                    policy_hash TEXT,
                    retrieved_at TEXT,
                    eligibility_state TEXT,
                    eligibility_reasons_json TEXT,
                    in_scope_assets_json TEXT,
                    out_of_scope_assets_json TEXT,
                    ai_classification TEXT,
                    opportunity_score REAL,
                    evidence_confidence REAL,
                    priority_tier TEXT,
                    score_breakdown_json TEXT,
                    opportunities_json TEXT,
                    is_selected INTEGER DEFAULT 0,
                    is_rejected INTEGER DEFAULT 0,
                    selection_notes TEXT DEFAULT '',
                    raw_attributes_json TEXT,
                    updated_at REAL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prog_eligibility ON programs (eligibility_state)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prog_score ON programs (opportunity_score)")
            conn.commit()

    def save_program(self, prog: DiscoveredProgram) -> None:
        now = time.time()
        in_scope_dict = [a.__dict__ for a in prog.in_scope_assets]
        out_scope_dict = [a.__dict__ for a in prog.out_of_scope_assets]
        breakdown_dict = [c.__dict__ for c in prog.score_breakdown]
        opps_dict = [o.__dict__ for o in prog.research_opportunities]

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO programs (
                    handle, program_id, name, url, state, submission_state,
                    offers_bounties, currency, min_bounty, max_bounty,
                    policy_text, policy_hash, retrieved_at, eligibility_state,
                    eligibility_reasons_json, in_scope_assets_json, out_of_scope_assets_json,
                    ai_classification, opportunity_score, evidence_confidence,
                    priority_tier, score_breakdown_json, opportunities_json,
                    is_selected, is_rejected, selection_notes, raw_attributes_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    prog.handle,
                    prog.program_id,
                    prog.name,
                    prog.url,
                    prog.state,
                    prog.submission_state,
                    1 if prog.offers_bounties else 0,
                    prog.currency,
                    prog.min_bounty,
                    prog.max_bounty,
                    prog.policy_text,
                    prog.policy_hash,
                    prog.retrieved_at,
                    prog.eligibility_state.value,
                    json.dumps(prog.eligibility_reasons),
                    json.dumps(in_scope_dict),
                    json.dumps(out_scope_dict),
                    prog.ai_classification.value,
                    prog.opportunity_score,
                    prog.evidence_confidence,
                    prog.priority_tier.value,
                    json.dumps(breakdown_dict),
                    json.dumps(opps_dict),
                    1 if prog.is_selected else 0,
                    1 if prog.is_rejected else 0,
                    prog.selection_notes,
                    json.dumps(prog.raw_attributes),
                    now,
                ),
            )
            conn.commit()

    def get_program(self, handle: str) -> Optional[DiscoveredProgram]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM programs WHERE handle = ?", (handle,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_program(row)

    def list_ranked_programs(
        self,
        bounty_only: bool = True,
        eligible_only: bool = True,
        limit: int = 50,
    ) -> List[DiscoveredProgram]:
        sql = "SELECT * FROM programs WHERE 1=1"
        params: List[Any] = []
        if bounty_only:
            sql += " AND offers_bounties = 1"
        if eligible_only:
            sql += " AND eligibility_state = 'ELIGIBLE'"
        sql += " ORDER BY opportunity_score DESC, evidence_confidence DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            return [self._row_to_program(r) for r in cur.fetchall()]

    def count_programs(self) -> Dict[str, int]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM programs")
            total = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM programs WHERE offers_bounties = 1")
            bounties = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM programs WHERE eligibility_state = 'ELIGIBLE'")
            eligible = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM programs WHERE ai_classification = 'CONFIRMED_AI_BUILT'")
            ai_confirmed = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM programs WHERE ai_classification = 'PROBABLE_AI_BUILT'")
            ai_probable = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM programs WHERE is_selected = 1")
            selected = cur.fetchone()[0]

            return {
                "total": total,
                "offers_bounties": bounties,
                "eligible": eligible,
                "ai_confirmed": ai_confirmed,
                "ai_probable": ai_probable,
                "selected": selected,
            }

    @staticmethod
    def _row_to_program(row: sqlite3.Row) -> DiscoveredProgram:
        in_assets = [ProgramAsset(**a) for a in json.loads(row["in_scope_assets_json"] or "[]")]
        out_assets = [ProgramAsset(**a) for a in json.loads(row["out_of_scope_assets_json"] or "[]")]

        breakdown_list = [ScoreCriterion(**c) for c in json.loads(row["score_breakdown_json"] or "[]")]
        opps_list = [ResearchOpportunity(**o) for o in json.loads(row["opportunities_json"] or "[]")]

        prog = DiscoveredProgram(
            program_id=row["program_id"],
            handle=row["handle"],
            name=row["name"],
            url=row["url"],
            state=row["state"],
            submission_state=row["submission_state"],
            offers_bounties=bool(row["offers_bounties"]),
            currency=row["currency"] or "USD",
            min_bounty=row["min_bounty"],
            max_bounty=row["max_bounty"],
            policy_text=row["policy_text"] or "",
            policy_hash=row["policy_hash"] or "",
            retrieved_at=row["retrieved_at"] or "",
            eligibility_state=ProgramEligibilityState(row["eligibility_state"]),
            eligibility_reasons=json.loads(row["eligibility_reasons_json"] or "[]"),
            in_scope_assets=in_assets,
            out_of_scope_assets=out_assets,
            ai_classification=AIClassification(row["ai_classification"]),
            opportunity_score=float(row["opportunity_score"] or 0.0),
            evidence_confidence=float(row["evidence_confidence"] or 0.0),
            priority_tier=PriorityTier(row["priority_tier"]),
            score_breakdown=breakdown_list,
            research_opportunities=opps_list,
            is_selected=bool(row["is_selected"]),
            is_rejected=bool(row["is_rejected"]),
            selection_notes=row["selection_notes"] or "",
            raw_attributes=json.loads(row["raw_attributes_json"] or "{}"),
        )
        return prog
