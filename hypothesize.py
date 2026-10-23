"""
hypothesize.py — the bridge between memory and the laptop's own model.
Given a target + program scope, retrieves the top-K similar disclosed bugs +
playbook entries from the KnowledgeBase, then asks the LOCAL LLM for a short,
prioritized hypothesis list. Text-only output: it never constructs requests.
Those drafts get turned into differ candidates BY YOU (or by runner config).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx

OLLAMA = "http://127.0.0.1:11434"
DRAFT_MODEL = "qwen2.5:3b-instruct-q4_K_M"   # fast on this laptop; 7B for depth up to you
SYSTEM = (
    "You are a bug-bounty hypothesis generator. Use ONLY the provided context "
    "about what similar programs paid for. Output exactly 5 bullet lines: "
    "'ENDPOINT|REPLAY|WHY'. Keep REPLAY a concrete 2-role test idea. No preamble."
)


def retrieve(kb_path: str, program: str, classes: list[str]) -> list[dict]:
    from knowledge_base import KnowledgeBase
    kb = KnowledgeBase(kb_path)
    out: list[dict] = []
    q = (
        f"top paid authz IDOR patterns for {program}: "
        + "; ".join(classes or ["object id authorization"])
    )
    for h in kb.query(q, k=6):
        out.append(h)
    return out


def draft(context_block: str) -> str:
    r = httpx.post(
        f"{OLLAMA}/api/chat",
        json={
            "model": DRAFT_MODEL,
            "stream": False,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"CONTEXT:\n{context_block}\nTARGET CLASS: IDOR / broken authz"},
            ],
        },
        timeout=600.0,
    )
    r.raise_for_status()
    return r.json()["message"]["content"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kb", default="data/kb.json")
    ap.add_argument("--program", required=True, help="team handle the KB filtered on, e.g. 'zomato'")
    ap.add_argument("--classes", default="authorization,idor,privilege")
    ap.add_argument("--fuzzy", action="store_true", help="ignore program filter, use global corpus")
    args = ap.parse_args()

    hits = retrieve(args.kb, "" if args.fuzzy else args.program, args.classes.split(","))
    block = "\n---\n".join(
        f"[{h['title']}] {h['text'][:400]}" for h in hits
    ) or "(KB query returned nothing)"
    print(draft(block))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
