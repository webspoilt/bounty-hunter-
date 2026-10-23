"""
Observation DB — every fact gets provenance, everything dedupable.
Rule: nothing enters the pipeline without a tool name + command/outcome row here.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    tool TEXT NOT NULL,
    command TEXT NOT NULL,
    target TEXT NOT NULL,
    verdict TEXT NOT NULL,             -- informational | candidate | finding
    payload TEXT NOT NULL,             -- full detail JSON (request, response, notes)
    payload_hash TEXT NOT NULL UNIQUE, -- dedup: hash of normalized content
    scope_check TEXT NOT NULL          -- 'ALLOW' — refuses rows that failed the gate
);
CREATE INDEX IF NOT EXISTS idx_obs_verdict ON observations(verdict);
CREATE INDEX IF NOT EXISTS idx_obs_target ON observations(target);
"""


def _normalize_hash(tool: str, target: str, payload: dict) -> str:
    """Hash of semantic content so identical observations dedupe across runs."""
    blob = json.dumps(
        {"tool": tool, "target": target, "payload": payload},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8", errors="replace")
    return hashlib.sha256(blob).hexdigest()


class ObservationDB:
    def __init__(self, path: str | Path = "data/observations.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(SCHEMA)

    def insert(
        self,
        *,
        tool: str,
        command: str,
        target: str,
        verdict: str = "informational",
        payload: dict | None = None,
        scope_allowed: bool = True,
    ) -> tuple[int, bool]:
        """Returns (row_id, was_new). Duplicate insert → was_new=False, id of existing row.
        Discards the row (raises) if it wasn't scope-checked."""
        if not scope_allowed:
            raise ValueError(
                f"REFUSED: observation for {target!r} did not pass the scope engine. "
                "No out-of-scope data enters the DB."
            )
        if verdict not in ("informational", "candidate", "finding"):
            raise ValueError(f"bad verdict: {verdict!r}")
        payload = payload or {}
        h = _normalize_hash(tool, target, payload)
        cur = self.conn.execute(
            "SELECT id FROM observations WHERE payload_hash = ?", (h,)
        )
        existing = cur.fetchone()
        if existing:
            return existing[0], False
        cur = self.conn.execute(
            "INSERT INTO observations (created_at, tool, command, target, verdict, payload, payload_hash, scope_check) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (time.time(), tool, command, target, verdict, json.dumps(payload), h, "ALLOW"),
        )
        self.conn.commit()
        return cur.lastrowid, True

    def candidates(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, created_at, tool, command, target, payload "
            "FROM observations WHERE verdict='candidate' ORDER BY created_at DESC"
        ).fetchall()
        return [
            {"id": r[0], "created_at": r[1], "tool": r[2], "command": r[3],
             "target": r[4], "payload": json.loads(r[5])}
            for r in rows
        ]

    def evidence_for(self, target: str) -> list[dict]:
        """Full provenance trail for one target — what tool found what, in order."""
        rows = self.conn.execute(
            "SELECT created_at, tool, command, verdict, payload FROM observations "
            "WHERE target=? ORDER BY created_at", (target,)
        ).fetchall()
        return [
            {"created_at": r[0], "tool": r[1], "command": r[2],
             "verdict": r[3], "payload": json.loads(r[4])}
            for r in rows
        ]

    def promote(self, row_id: int, new_verdict: str) -> None:
        """candidate -> finding (after 2x reproduce) or back to informational (false positive)."""
        if new_verdict not in ("informational", "finding"):
            raise ValueError(f"can only promote to informational|finding, got {new_verdict!r}")
        self.conn.execute("UPDATE observations SET verdict=? WHERE id=?", (new_verdict, row_id))
        self.conn.commit()

    def stats(self) -> dict:
        cur = self.conn.execute(
            "SELECT verdict, COUNT(*) FROM observations GROUP BY verdict"
        )
        return dict(cur.fetchall())

    def close(self) -> None:
        self.conn.close()
