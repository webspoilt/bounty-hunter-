"""SQLite store: runs, assets, endpoints, exchanges, scope audit, findings, queue.

The scope audit table is the point: every request attempt, allowed *or refused*, is a
row. The old DB could only ever record "ALLOW".
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

from bb.config import DB_PATH, now_iso
from bb.models import Evidence, Exchange, Finding, sev_rank

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, program TEXT NOT NULL, target TEXT, started_at TEXT NOT NULL,
    ended_at TEXT, scope_fingerprint TEXT, meta TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, host TEXT NOT NULL,
    url TEXT, status INTEGER, server TEXT, title TEXT, tech TEXT, source TEXT,
    created_at TEXT NOT NULL, UNIQUE(run_id, host, url)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, url TEXT NOT NULL,
    method TEXT NOT NULL, host TEXT NOT NULL, path TEXT, source TEXT,
    params TEXT, auth_hint TEXT, created_at TEXT NOT NULL,
    UNIQUE(run_id, method, url)
);
CREATE TABLE IF NOT EXISTS exchanges (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, tool TEXT, method TEXT, url TEXT,
    status INTEGER, req_headers TEXT, req_body TEXT, resp_headers TEXT, resp_body TEXT,
    duration_ms INTEGER, created_at TEXT NOT NULL, payload_hash TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS scope_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, target TEXT, verdict TEXT NOT NULL,
    reason TEXT, host TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, run_id TEXT, title TEXT NOT NULL, bug_class TEXT,
    severity TEXT, confidence TEXT, status TEXT, host TEXT, url TEXT,
    summary TEXT, impact TEXT, remediation TEXT, steps TEXT, evidence TEXT,
    meta TEXT, created_at TEXT NOT NULL, report_path TEXT
);
CREATE TABLE IF NOT EXISTS queue (
    id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
    queued_at TEXT NOT NULL, decided_at TEXT, channel TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_queue_state ON queue(state);
CREATE INDEX IF NOT EXISTS idx_endpoints_run ON endpoints(run_id);
"""


def _hash_payload(run_id: str | None, tool: str, method: str, url: str, status: int,
                  body: str) -> str:
    import hashlib
    blob = json.dumps([run_id, tool, method, url, status, body], sort_keys=False)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


class Store:
    def __init__(self, path: str | Path = DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # ---------- runs ----------

    def start_run(self, program: str, target: str = "", scope_fingerprint: str = "",
                  meta: dict | None = None) -> str:
        run_id = uuid.uuid4().hex[:12]
        self.conn.execute(
            "INSERT INTO runs (id, program, target, started_at, scope_fingerprint, meta) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, program, target, now_iso(), scope_fingerprint, json.dumps(meta or {})))
        self.conn.commit()
        return run_id

    def finish_run(self, run_id: str, meta: dict | None = None) -> None:
        row = self.conn.execute("SELECT meta FROM runs WHERE id=?", (run_id,)).fetchone()
        merged = json.loads(row["meta"] or "{}") if row else {}
        merged.update(meta or {})
        self.conn.execute("UPDATE runs SET ended_at=?, meta=? WHERE id=?",
                          (now_iso(), json.dumps(merged), run_id))
        self.conn.commit()

    def run(self, run_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    def latest_run(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def finding_run(self, finding_id: str) -> str | None:
        row = self.conn.execute("SELECT run_id FROM findings WHERE id=?",
                                (finding_id,)).fetchone()
        return row["run_id"] if row else None

    # ---------- audit ----------

    def audit_scope(self, run_id: str | None, target: str, verdict: str, reason: str,
                    host: str = "") -> None:
        self.conn.execute(
            "INSERT INTO scope_audit (run_id, target, verdict, reason, host, created_at) "
            "VALUES (?,?,?,?,?,?)", (run_id, target, verdict, reason, host, now_iso()))
        self.conn.commit()

    def audit_counts(self, run_id: str) -> dict:
        rows = self.conn.execute(
            "SELECT verdict, COUNT(*) n FROM scope_audit WHERE run_id=? GROUP BY verdict",
            (run_id,)).fetchall()
        return {r["verdict"]: r["n"] for r in rows}

    # ---------- assets / endpoints ----------

    def add_asset(self, run_id: str, host: str, url: str | None = None, status: int | None = None,
                  server: str = "", title: str = "", tech: list | None = None,
                  source: str = "") -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO assets (run_id, host, url, status, server, title, tech, "
            "source, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, host, url, status, server, title, json.dumps(tech or []), source, now_iso()))
        self.conn.commit()

    def add_endpoint(self, run_id: str, url: str, method: str = "GET", host: str = "",
                     path: str = "", source: str = "", params: list | None = None,
                     auth_hint: str = "") -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO endpoints (run_id, url, method, host, path, source, params, "
            "auth_hint, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, url, method.upper(), host, path, source, json.dumps(params or []),
             auth_hint, now_iso()))
        self.conn.commit()

    def endpoints(self, run_id: str | None = None) -> list[dict]:
        q = ("SELECT * FROM endpoints" if run_id is None else
             "SELECT * FROM endpoints WHERE run_id=?") + " ORDER BY id"
        rows = self.conn.execute(q, (() if run_id is None else (run_id,))).fetchall()
        return [dict(r) | {"params": json.loads(r["params"] or "[]")} for r in rows]

    def assets(self, run_id: str | None = None) -> list[dict]:
        q = ("SELECT * FROM assets" if run_id is None else
             "SELECT * FROM assets WHERE run_id=?") + " ORDER BY id"
        rows = self.conn.execute(q, (() if run_id is None else (run_id,))).fetchall()
        return [dict(r) for r in rows]

    # ---------- exchanges ----------

    def add_exchange(self, run_id: str | None, tool: str, ex: Exchange) -> bool:
        h = _hash_payload(run_id, tool, ex.method, ex.url, ex.status, ex.response_body[:2000])
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO exchanges (run_id, tool, method, url, status, req_headers, "
            "req_body, resp_headers, resp_body, duration_ms, created_at, payload_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, tool, ex.method, ex.url, ex.status,
             json.dumps(ex.request_headers), ex.request_body,
             json.dumps(ex.response_headers), ex.response_body,
             ex.duration_ms, ex.at, h))
        self.conn.commit()
        return cur.rowcount > 0

    # ---------- findings ----------

    def add_finding(self, finding: Finding, run_id: str | None = None) -> str:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, run_id, title, bug_class, severity, confidence, "
            "status, host, url, summary, impact, remediation, steps, evidence, meta, created_at, "
            "report_path) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (finding.id, run_id, finding.title, finding.bug_class, finding.severity,
             finding.confidence, finding.status, finding.host, finding.url, finding.summary,
             finding.impact, finding.remediation, json.dumps(finding.steps),
             json.dumps([e.to_dict() for e in finding.evidence]), json.dumps(finding.meta),
             finding.created_at, finding.meta.get("report_path")))
        self.conn.commit()
        return finding.id

    def set_report_path(self, finding_id: str, path: str) -> None:
        self.conn.execute("UPDATE findings SET report_path=? WHERE id=?", (path, finding_id))
        self.conn.commit()

    def update_meta(self, finding_id: str, **kv) -> None:
        row = self.conn.execute("SELECT meta FROM findings WHERE id=?", (finding_id,)).fetchone()
        meta = json.loads(row["meta"] or "{}") if row else {}
        meta.update(kv)
        self.conn.execute("UPDATE findings SET meta=? WHERE id=?", (json.dumps(meta), finding_id))
        self.conn.commit()

    def exchanges(self, run_id: str, limit: int = 500) -> list[Exchange]:
        rows = self.conn.execute(
            "SELECT * FROM exchanges WHERE run_id=? ORDER BY id LIMIT ?", (run_id, limit)).fetchall()
        return [Exchange(method=r["method"], url=r["url"], status=r["status"],
                         request_headers=json.loads(r["req_headers"] or "{}"),
                         request_body=r["req_body"] or "",
                         response_headers=json.loads(r["resp_headers"] or "{}"),
                         response_body=r["resp_body"] or "",
                         duration_ms=r["duration_ms"] or 0, at=r["created_at"])
                for r in rows]

    def set_status(self, finding_id: str, status: str) -> None:
        self.conn.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
        self.conn.commit()

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id LIKE ?",
                                (finding_id + "%",)).fetchone()
        if not row:
            return None
        return self._row_to_finding(row)

    def find_duplicate(self, bug_class: str, url: str) -> Finding | None:
        """Same bug on the same URL from an earlier run: refresh instead of duplicating."""
        row = self.conn.execute(
            "SELECT * FROM findings WHERE bug_class=? AND url=? AND status IN ('candidate','confirmed') "
            "ORDER BY created_at DESC LIMIT 1", (bug_class, url)).fetchone()
        return self._row_to_finding(row) if row else None

    def findings(self, status: str | None = None, run_id: str | None = None,
                 min_severity: str = "info") -> list[Finding]:
        clauses, args = [], []
        if status:
            clauses.append("status=?"); args.append(status)
        if run_id:
            clauses.append("run_id=?"); args.append(run_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.conn.execute(
            f"SELECT * FROM findings{where} ORDER BY created_at DESC", args).fetchall()
        out = [self._row_to_finding(r) for r in rows]
        out = [f for f in out if sev_rank(f.severity) >= sev_rank(min_severity)]
        out.sort(key=lambda f: (-sev_rank(f.severity), f.created_at))
        return out

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding.from_dict({
            "id": row["id"], "title": row["title"], "bug_class": row["bug_class"],
            "severity": row["severity"], "confidence": row["confidence"],
            "status": row["status"], "host": row["host"], "url": row["url"],
            "summary": row["summary"], "impact": row["impact"],
            "remediation": row["remediation"], "steps": json.loads(row["steps"] or "[]"),
            "evidence": json.loads(row["evidence"] or "[]"),
            "meta": json.loads(row["meta"] or "{}"), "created_at": row["created_at"],
        })

    # ---------- approval queue ----------

    def queue_add(self, finding_id: str, channel: str = "cli") -> tuple[str, bool]:
        existing = self.conn.execute(
            "SELECT id FROM queue WHERE finding_id=?", (finding_id,)).fetchone()
        if existing:
            return existing["id"], False
        qid = uuid.uuid4().hex[:10]
        self.conn.execute(
            "INSERT INTO queue (id, finding_id, state, queued_at, channel) VALUES (?,?,?,?,?)",
            (qid, finding_id, "pending", now_iso(), channel))
        self.conn.commit()
        return qid, True

    def queue(self, state: str | None = "pending") -> list[dict]:
        q = ("SELECT q.*, f.title, f.severity, f.bug_class, f.url, f.report_path "
             "FROM queue q JOIN findings f ON f.id = q.finding_id")
        args: tuple = ()
        if state:
            q += " WHERE q.state=?"
            args = (state,)
        q += " ORDER BY q.queued_at"
        return [dict(r) for r in self.conn.execute(q, args).fetchall()]

    def decide(self, queue_id: str, approved: bool) -> dict:
        row = self.conn.execute("SELECT * FROM queue WHERE id LIKE ?",
                                (queue_id + "%",)).fetchone()
        if not row:
            raise KeyError(f"no queue item matching {queue_id!r}")
        if row["state"] != "pending":
            raise ValueError(f"queue item {row['id']} already {row['state']}")
        state = "approved" if approved else "rejected"
        self.conn.execute("UPDATE queue SET state=?, decided_at=? WHERE id=?",
                          (state, now_iso(), row["id"]))
        self.conn.execute("UPDATE findings SET status=? WHERE id=?",
                          ("confirmed" if approved else "rejected", row["finding_id"]))
        self.conn.commit()
        out = dict(row); out["state"] = state
        return out

    def stats(self) -> dict:
        def one(sql: str, *a):
            r = self.conn.execute(sql, a).fetchone()
            return r[0] if r else 0
        by_status = {r["status"]: r["n"] for r in self.conn.execute(
            "SELECT status, COUNT(*) n FROM findings GROUP BY status")}
        return {
            "findings": one("SELECT COUNT(*) FROM findings"),
            "by_status": by_status,
            "pending_approvals": one("SELECT COUNT(*) FROM queue WHERE state='pending'"),
            "endpoints": one("SELECT COUNT(*) FROM endpoints"),
            "assets": one("SELECT COUNT(*) FROM assets"),
            "exchanges": one("SELECT COUNT(*) FROM exchanges"),
        }

    # deterministic finding expansion for tests/inspection
    @staticmethod
    def evidence_of(row: dict) -> list[Evidence]:
        return [Evidence.from_dict(e) for e in (row.get("evidence") or [])]
