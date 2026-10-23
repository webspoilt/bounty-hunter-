"""
ingest_h1.py — pull Hacker0x01/hackerone_disclosed_reports (official H1 dataset)
and load the authz/IDOR subset into the local KnowledgeBase.

Filter: resolved + has_bounty + weakness-name contains an authz keyword.
Body: title + team + weakness + vulnerability_information (trimmed).
Run:  python ingest_h1.py [--cap 2500]
Local embeds via Ollama (nomic-embed-text) — CPU-friendly, resumable.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from knowledge_base import KnowledgeBase  # noqa: E402

DATASET = "Hacker0x01/hackerone_disclosed_reports"
AUTHZ_KEYWORDS = [
    "authorization",
    "access control",
    "idor",
    "privilege",
    "permission",
]
MIN_BODY = 120          # skip stubs
MAX_BODY_CHARS = 2500   # trim monster reports


def body_for(row: dict) -> str | None:
    info = (row.get("vulnerability_information") or "").strip()
    if len(info) < MIN_BODY:
        return None
    weakness = (row.get("weakness") or {}).get("name", "")
    team = (row.get("team") or {}).get("handle", "")
    when = (row.get("disclosed_at") or "")[:10]
    head = f"Title: {row.get('title','')}\nProgram: {team}\nWeakness: {weakness}\nDisclosed: {when}\n"
    return head + info[:MAX_BODY_CHARS]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap", type=int, default=2500)
    args = ap.parse_args()

    from datasets import load_dataset
    ds = load_dataset(DATASET, split="train", streaming=True)

    kb = KnowledgeBase()
    picked: list[tuple[str, str, dict]] = []
    seen_ids = {e["meta"].get("report_id") for e in kb.entries if e["meta"].get("source") == "h1_disclosed"}

    scanned = 0
    for row in ds:
        scanned += 1
        if str(row.get("substate", "")).lower() != "resolved":
            continue
        if not row.get("has_bounty?"):
            continue
        weakness = (row.get("weakness") or {}).get("name", "").lower()
        if not any(k in weakness for k in AUTHZ_KEYWORDS):
            continue
        rid = row.get("id")
        if rid in seen_ids:
            continue
        body = body_for(row)
        if not body:
            continue
        meta = {
            "source": "h1_disclosed",
            "report_id": rid,
            "team": (row.get("team") or {}).get("handle", ""),
            "weakness": (row.get("weakness") or {}).get("name", ""),
            "disclosed_at": (row.get("disclosed_at") or "")[:10],
            "votes": row.get("vote_count"),
        }
        picked.append((f"{row.get('title','')} [{meta['team']}]", body, meta))
        if len(picked) >= args.cap:
            break

    print(f"scanned={scanned} selected={len(picked)}")
    n = kb.add_documents(picked)
    print(f"ingested {n} chunks; kb total = {kb.stats()['total_chunks']}")
    demo = kb.query("how to detect IDOR by replaying an admin endpoint as a user", k=3)
    for h in demo:
        print(f"  {h['score']:.3f}  {h['title'][:80]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
