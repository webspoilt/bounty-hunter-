"""Local HackerOne disclosed-report index and duplicate checklist.

The official dataset is pulled from Hugging Face and indexed in SQLite FTS5. It is a
*snapshot of disclosed reports*, not the program's private report history: it can show
public precedent and likely duplicates, never prove uniqueness. Checks are recorded as
evidence; the verdict is deliberately hedged.

Data handling: the dataset is stored locally under `data/h1_disclosed/` (gitignored),
indexed locally, and never redistributed. The dataset card says it is provided under
HackerOne's Terms of Service; treat it as local research material.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from bb.config import DUPLICATES, H1_DATA, H1_INDEX, now_iso

DATASET = "Hacker0x01/hackerone_disclosed_reports"
DATASET_FILES = (
    "data/train-00000-of-00001.parquet",
    "data/validation-00000-of-00001.parquet",
    "data/test-00000-of-00001.parquet",
)
MAX_BODY_CHARS = 20_000
TOKEN_RE = re.compile(r"[A-Za-z0-9_]{2,}")
STOPWORDS = {"the", "and", "for", "with", "from", "this", "that", "was", "were", "are",
             "its", "not", "but", "can", "has", "have", "been", "into", "then", "than",
             "when", "where", "which", "their", "there", "using", "used", "http", "https"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS h1_reports (
    id INTEGER PRIMARY KEY,
    report_id INTEGER NOT NULL UNIQUE,
    title TEXT NOT NULL,
    team TEXT,
    weakness TEXT,
    asset TEXT,
    asset_type TEXT,
    disclosed_at TEXT,
    substate TEXT,
    has_bounty INTEGER,
    votes INTEGER,
    visibility TEXT,
    body TEXT
);
CREATE TABLE IF NOT EXISTS h1_meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS duplicate_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    dataset_sha TEXT,
    queries TEXT,
    matches TEXT,
    verdict TEXT,
    evidence_path TEXT
);
"""


class DuplicateError(RuntimeError):
    pass


def _fts_sql() -> str:
    return ("CREATE VIRTUAL TABLE h1_fts USING fts5("
            "title, body, content='h1_reports', content_rowid='id', "
            "tokenize='porter unicode61')")


def _asset_matches(asset: str, host: str) -> bool:
    """Exact host or wildcard domain match; never a bare substring like localhost-now."""
    if not asset or not host:
        return False
    candidate = asset.strip().lower()
    target = host.strip().lower().strip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    candidate = candidate.split("/")[0].rstrip(".")
    return bool(candidate) and (target == candidate or target.endswith("." + candidate))


def _fts_query(text: str) -> str:
    tokens = []
    for token in TOKEN_RE.findall((text or "").lower()):
        if token in STOPWORDS or token in tokens:
            continue
        tokens.append(token)
        if len(tokens) >= 20:
            break
    return " OR ".join(f'"{token}"' for token in tokens)


class DupIndex:
    def __init__(self, path: str | Path = H1_INDEX):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        try:
            self.conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS h1_fts USING fts5("
                              "title, body, content='h1_reports', content_rowid='id', "
                              "tokenize='porter unicode61')")
        except sqlite3.OperationalError as exc:
            raise DuplicateError("SQLite FTS5 is not available in this Python build") from exc

    def close(self) -> None:
        self.conn.close()

    # ---------- ingest ----------

    def replace_records(self, records: list[dict], meta: dict | None = None) -> dict:
        self.conn.execute("DROP TABLE IF EXISTS h1_fts")
        self.conn.execute("DELETE FROM h1_reports")
        self.conn.execute(_fts_sql())
        for record in records:
            self.conn.execute(
                "INSERT OR REPLACE INTO h1_reports (report_id, title, team, weakness, asset, "
                "asset_type, disclosed_at, substate, has_bounty, votes, visibility, body) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (record["report_id"], record["title"], record.get("team", ""),
                 record.get("weakness", ""), record.get("asset", ""),
                 record.get("asset_type", ""), record.get("disclosed_at", ""),
                 record.get("substate", ""), int(bool(record.get("has_bounty"))),
                 record.get("votes") or 0, record.get("visibility", ""),
                 record.get("body", "")[:MAX_BODY_CHARS]))
        self.conn.execute("INSERT INTO h1_fts(h1_fts) VALUES('rebuild')")
        report_meta = {
            "dataset": DATASET,
            "ingested_at": now_iso(),
            "rows": str(len(records)),
            "body_cap": str(MAX_BODY_CHARS),
            **(meta or {}),
        }
        for key, value in report_meta.items():
            self.conn.execute("INSERT OR REPLACE INTO h1_meta (key, value) VALUES (?,?)",
                              (key, str(value)))
        self.conn.commit()
        return report_meta

    # ---------- reads ----------

    def meta(self) -> dict:
        return {row["key"]: row["value"] for row in self.conn.execute("SELECT * FROM h1_meta")}

    def stats(self) -> dict:
        rows = self.conn.execute("SELECT COUNT(*) c FROM h1_reports").fetchone()["c"]
        return {"rows": rows, **self.meta()}

    def search(self, query: str, *, team: str | None = None, asset: str | None = None,
               weakness: str | None = None, k: int = 10) -> list[dict]:
        fts = _fts_query(query)
        if not fts:
            return []
        where = ["h1_fts MATCH ?"]
        args: list = [fts]
        if team:
            where.append("lower(r.team) = ?")
            args.append(team.lower())
        if weakness:
            where.append("r.weakness LIKE ?")
            args.append(f"%{weakness}%")
        # Asset matching happens in Python: a SQL LIKE '%localhost%' matches
        # 'localhost-now', which is not the same asset.
        fetch_limit = max(int(k) * 20, 100) if asset else max(1, min(int(k), 50))
        args.append(fetch_limit)
        sql = ("SELECT r.report_id, r.title, r.team, r.weakness, r.asset, r.asset_type, "
               "r.disclosed_at, r.has_bounty, r.votes, r.visibility, "
               "bm25(h1_fts) AS rank, snippet(h1_fts, 1, '[', ']', '…', 18) AS snippet "
               "FROM h1_fts JOIN h1_reports r ON r.id = h1_fts.rowid "
               f"WHERE {' AND '.join(where)} ORDER BY rank LIMIT ?")
        rows = [dict(row) for row in self.conn.execute(sql, args)]
        if asset:
            rows = [row for row in rows if _asset_matches(row.get("asset") or "", asset)]
        rows = rows[:max(1, min(int(k), 50))]
        for row in rows:
            row["score"] = round(-float(row.pop("rank")), 3)
            row["url"] = f"https://hackerone.com/reports/{row['report_id']}"
        return rows


# ---------- dataset acquisition ----------

def pull(dest: str | Path = H1_DATA, log=print) -> list[Path]:
    try:
        from huggingface_hub import hf_hub_download
    except ImportError as exc:
        raise DuplicateError('dataset download needs huggingface-hub; '
                             'install with `pip install "bountybot[h1]"`') from exc
    target = Path(dest).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    paths = []
    for name in DATASET_FILES:
        path = hf_hub_download(DATASET, name, repo_type="dataset", local_dir=str(target))
        paths.append(Path(path))
        log(f"  [h1] {path}")
    return paths


def _normalize(row: dict) -> dict | None:
    try:
        report_id = int(row.get("id"))
    except (TypeError, ValueError):
        return None
    team = row.get("team") or {}
    weakness = row.get("weakness") or {}
    scope = row.get("structured_scope") or {}
    body = row.get("vulnerability_information") or ""
    return {
        "report_id": report_id,
        "title": row.get("title") or "(untitled)",
        "team": str(team.get("handle") or "").lower(),
        "weakness": str(weakness.get("name") or ""),
        "asset": str(scope.get("asset_identifier") or ""),
        "asset_type": str(scope.get("asset_type") or ""),
        "disclosed_at": str(row.get("disclosed_at") or "")[:10],
        "substate": str(row.get("substate") or ""),
        "has_bounty": bool(row.get("has_bounty?")),
        "votes": row.get("vote_count") or 0,
        "visibility": str(row.get("visibility") or ""),
        "body": str(body)[:MAX_BODY_CHARS],
    }


def ingest_parquet(directory: str | Path = H1_DATA, *, index: DupIndex | None = None,
                   log=print) -> dict:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise DuplicateError('parquet ingestion needs pyarrow; install with '
                             '`pip install "bountybot[h1]"`') from exc
    root = Path(directory).expanduser().resolve()
    files = sorted(root.rglob("*.parquet"))
    if not files:
        raise DuplicateError(f"no .parquet files under {root} — run `bb duplicate pull` first")

    records: dict[int, dict] = {}
    for path in files:
        table = pq.read_table(path)
        for row in table.to_pylist():
            record = _normalize(row)
            if record:
                records[record["report_id"]] = record

    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    meta = {"fingerprint": digest.hexdigest()[:16], "files": str(len(files)),
            "source_dir": str(root)}
    idx = index or DupIndex()
    db_path = str(idx.path)
    try:
        report_meta = idx.replace_records(list(records.values()), meta)
    finally:
        if index is None:
            idx.close()
    log(f"  [h1] indexed {len(records)} reports from {len(files)} parquet files "
        f"(fingerprint {report_meta['fingerprint']})")
    return {"rows": len(records), "files": len(files),
            "fingerprint": report_meta["fingerprint"], "db": db_path}


# ---------- duplicate check evidence ----------

CLASS_HINTS = {
    "idor": "idor authorization access control object ownership",
    "broken access control": "authorization access control permission tenant",
    "cors": "cors cross origin",
    "graphql": "graphql introspection schema",
    "open redirect": "open redirect location",
    "information disclosure": "information disclosure exposed",
}


def _class_text(bug_class: str) -> str:
    low = (bug_class or "").lower()
    for key, value in CLASS_HINTS.items():
        if key in low or low in key:
            return value
    return bug_class or "authorization access control"


def check_finding(finding_id: str, store, *, index: DupIndex | None = None,
                  k: int = 8, log=print) -> dict:
    finding = store.get_finding(finding_id)
    if not finding:
        raise DuplicateError(f"no finding matching {finding_id!r}")
    idx = index or DupIndex()
    meta = idx.meta()
    if not meta.get("rows") or int(meta.get("rows", 0)) <= 0:
        raise DuplicateError("duplicate index is empty — run `bb duplicate pull --ingest`")

    run_id = store.finding_run(finding.id)
    run = store.run(run_id) if run_id else None
    program = (run or {}).get("program") or finding.meta.get("program") or ""
    parts = urlsplit(finding.url)
    host = (parts.hostname or "").lower()
    path_tokens = [token for token in re.split(r"[/_\-]+", parts.path)
                   if len(token) > 1 and not token.isdigit()][-5:]
    query_tokens = list(parse_qs(parts.query).keys())
    class_text = _class_text(finding.bug_class)

    searches = [
        {"label": "team + path/class",
         "query": " ".join(path_tokens + query_tokens + [finding.bug_class, class_text]),
         "team": program or None},
        {"label": "asset + class", "query": class_text, "asset": host or None},
        {"label": "title", "query": finding.title, "team": program or None},
    ]

    merged: dict[int, dict] = {}
    executed = []
    for search in searches:
        query = search["query"].strip()
        if not query:
            continue
        executed.append({k2: v for k2, v in search.items() if v})
        for row in idx.search(query, team=search.get("team"), asset=search.get("asset"), k=k):
            entry = merged.get(row["report_id"])
            if entry is None or row["score"] > entry["score"]:
                row = dict(row)
                row["query_label"] = search["label"]
                merged[row["report_id"]] = row

    results = sorted(merged.values(), key=lambda row: (
        0 if _asset_matches(row.get("asset") or "", host) else 1,
        -row["score"]))
    for row in results:
        same_asset = _asset_matches(row.get("asset") or "", host)
        weak = (row.get("weakness") or "").lower()
        same_class = any(word in weak for word in
                         ("authoriz", "access control", "idor", "permission", "tenant"))
        row["same_asset"] = same_asset
        row["match_kind"] = ("same asset + authorization class" if same_asset and same_class
                             else "same asset" if same_asset
                             else "public precedent")

    if any(r["match_kind"].startswith("same asset +") for r in results):
        verdict = "possible duplicate / close precedent"
    elif any(r["same_asset"] for r in results):
        verdict = "asset has disclosed reports"
    elif results:
        verdict = "public precedent only"
    else:
        verdict = "no disclosed precedent"

    checked_at = now_iso()
    evidence = DUPLICATES / f"{finding.id}.md"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(_render_evidence(finding, program, host, verdict, executed, results,
                                         meta, checked_at), encoding="utf-8")
    idx.conn.execute(
        "INSERT INTO duplicate_checks (finding_id, checked_at, dataset_sha, queries, matches, "
        "verdict, evidence_path) VALUES (?,?,?,?,?,?,?)",
        (finding.id, checked_at, meta.get("fingerprint", ""), json.dumps(executed),
         json.dumps(results), verdict, str(evidence)))
    idx.conn.commit()
    if index is None:
        idx.close()
    log(f"  [duplicate] {verdict}: {len(results)} disclosed match(es) -> {evidence}")
    return {"verdict": verdict, "matches": results, "evidence_path": str(evidence),
            "queries": executed, "meta": meta}


def _render_evidence(finding, program: str, host: str, verdict: str,
                     queries: list[dict], results: list[dict], meta: dict,
                     checked_at: str) -> str:
    lines = [
        f"# Duplicate check - {finding.id}",
        "",
        f"- **Finding:** {finding.title}",
        f"- **Program:** `{program}`" if program else "- **Program:** unknown",
        f"- **Asset:** `{finding.url}`",
        f"- **Class:** {finding.bug_class}",
        f"- **Checked:** {checked_at}",
        f"- **Dataset:** {meta.get('dataset', DATASET)} "
        f"(local snapshot, fingerprint `{meta.get('fingerprint', '?')}`, "
        f"{meta.get('rows', '?')} reports, ingested {meta.get('ingested_at', '?')})",
        "",
        "## Queries run",
        "",
        "| # | label | query | filters |",
        "|---|---|---|---|",
    ]
    for i, query in enumerate(queries, 1):
        filters = ", ".join(f"{k}={v!r}" for k, v in query.items() if k not in ("label", "query"))
        labels = query.get("label", "")
        text = query.get("query", "").replace("|", "\\|")[:160]
        lines.append(f"| {i} | {labels} | `{text}` | {filters or '—'} |")

    lines += ["", "## Closest disclosed reports", ""]
    if results:
        lines += ["| report | title | team | asset | weakness | disclosed | match |",
                  "|---|---|---|---|---|---|---|"]
        for row in results:
            title = (row.get("title") or "").replace("|", "\\|")[:100]
            lines.append(f"| [#{row['report_id']}]({row['url']}) | {title} | "
                         f"`{row.get('team', '')}` | `{row.get('asset', '')}` | "
                         f"{row.get('weakness', '')} | {row.get('disclosed_at', '')} | "
                         f"{row.get('match_kind', '')} |")
    else:
        lines.append("_No disclosed reports matched the generated queries._")

    lines += [
        "",
        "## Verdict",
        "",
        f"**{verdict}**",
        "",
        "This index contains **disclosed** reports only. A program's private report history is",
        "invisible here, so this is a prioritisation aid, not proof of uniqueness. A negative",
        "result does not mean the finding is novel.",
        "",
        "## Manual checks still required",
        "",
        "1. Search HackerOne Hacktivity for the exact path, parameter, and program handle.",
        "2. Check the program's own disclosed reports and changelog.",
        "3. Search the web for the endpoint/parameter with the program name.",
        "4. Record the check and its result with `bb outcome --notes` when the program responds.",
        "",
        "Disclosed dataset snapshot: " + meta.get("ingested_at", "unknown") +
        ". Dataset source: " + DATASET + ".",
        "",
    ]
    return "\n".join(lines)
