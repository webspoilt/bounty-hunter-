"""Knowledge base tests — live against local Ollama (skips server-down)."""
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from knowledge_base import KnowledgeBase, chunk_text


def ollama_up() -> bool:
    try:
        return httpx.get("http://127.0.0.1:11434/api/tags", timeout=3).status_code == 200
    except Exception:
        return False


def run() -> int:
    failures = 0

    def check(cond, label):
        nonlocal failures
        if not cond:
            failures += 1
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    # ---- chunking (no network) ----
    long = " ".join(f"para{i} text about vulnerability class {i}." for i in range(50))
    cs = chunk_text(long, size=200, overlap=50)
    check(len(cs) > 1 and all(len(c) <= 200 for c in cs), f"long text chunked ({len(cs)} chunks)")
    check(chunk_text("") == [], "empty text -> no chunks")

    if not ollama_up():
        print("\n(SKIP live embed tests: Ollama server not running)")
        print(f"\n{'ALL PASS (with skips)' if failures == 0 else f'{failures} FAILURES'}")
        return failures

    # ---- live: embed + query ----
    with tempfile.TemporaryDirectory() as tmp:
        kb = KnowledgeBase(Path(tmp) / f"kb_{uuid.uuid4().hex}.json")
        n = kb.add_document(
            "authz-writeup-demo",
            "The researcher found that user B could access user A's invoice by "
            "incrementing the object id in /api/v1/invoices/<id>. The server did "
            "not check ownership. Bountied as IDOR, critical. " + long,
            meta={"program": "demo", "bug_class": "IDOR"},
        )
        check(n > 1, f"document embedded and stored ({n} chunks)")
        check(kb.stats()["total_chunks"] == n, "stats track")

        hits = kb.query("how to find IDOR object id authorization bugs", k=2)
        check(len(hits) == 2, "query returns k results")
        check(hits[0]["title"] == "authz-writeup-demo", "top hit is the right doc")
        check("IDOR" in hits[0]["text"] or "authorization" in hits[0]["text"].lower(),
              "top hit text is relevant")

        kb.save()
        kb2 = KnowledgeBase(kb.path)
        check(len(kb2.entries) == n, "KB persists to disk and reloads")

    print(f"\n{'ALL PASS' if failures == 0 else f'{failures} FAILURES'}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
