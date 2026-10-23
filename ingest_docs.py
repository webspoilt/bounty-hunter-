"""
ingest_docs.py — load curated reference docs into the KnowledgeBase.

Sources:
  kb_docs/            our own playbooks
  ../Claude-BugHunter/skills/<name>/SKILL.md   (vendored methodology, MIT)

Usage:  python ingest_docs.py            # recommended default set
        python ingest_docs.py <file> [...]
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from knowledge_base import KnowledgeBase  # noqa: E402

BUGHUNTER = ROOT.parent / "Claude-BugHunter" / "skills"

DEFAULT_SKILLS = [
    "hunt-idor", "hunt-auth-bypass", "triage-validation", "report-writing",
    "bb-methodology", "security-arsenal", "hunt-graphql", "hunt-ato",
    "hunt-session", "hunt-shadow-api", "evidence-hygiene", "recon-scope-triage",
]


def main() -> int:
    kb = KnowledgeBase()
    sources: list[tuple[str, Path, dict]] = [
        (p.stem, p, {"source": "playbook", "path": str(p)})
        for p in sorted((ROOT / "kb_docs").glob("*.md"))
    ]
    if BUGHUNTER.exists():
        sources += [
            (s, BUGHUNTER / s / "SKILL.md", {"source": "bughunter-skill", "skill": s})
            for s in DEFAULT_SKILLS
        ]
    docs = [(t, p, m) for t, p, m in sources if p.exists()]
    print(f"ingesting {len(docs)} documents "
          f"({sum(1 for _,_,m in docs if m['source']=='playbook')} playbook, "
          f"{sum(1 for _,_,m in docs if m['source']=='bughunter-skill')} skills)")
    n = kb.add_documents([
        (title, path.read_text(encoding="utf-8", errors="ignore"), meta)
        for title, path, meta in docs
    ])
    st = kb.stats()
    print(f"added {n} chunks; KB now {st['total_chunks']} chunks")
    demo = kb.query("which endpoints should I fuzz first for broken object level authorization", k=3)
    for h in demo:
        print(f"  {h['score']:.3f}  {h['title'][:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
