"""Health checks for the local stack, so `bb integrations` tells the truth."""
from __future__ import annotations

import shutil

import httpx

from bb.config import ARTEX_TOKEN, ARTEX_URL, CBH, KB_PATH, OLLAMA, PENTAGI_URL
from bb.llm import Ollama


def probe_all() -> list[dict]:
    out = []

    ollama = Ollama()
    models = ollama.models() if ollama.available() else []
    out.append({"name": "ollama", "ok": bool(models), "url": OLLAMA,
                "detail": ", ".join(models) if models else "not reachable (bb report still works)"})

    try:
        from bb.kb import KnowledgeBase
        kb = KnowledgeBase()
        st = kb.stats()
        out.append({"name": "knowledge-base", "ok": st["chunks"] > 0, "url": str(KB_PATH),
                    "detail": f"{st['chunks']} chunks / {st['documents']} docs / dim {st['dim']}"})
    except Exception as exc:
        out.append({"name": "knowledge-base", "ok": False, "url": str(KB_PATH), "detail": str(exc)})

    out.append({"name": "cbh", "ok": CBH.exists(), "url": str(CBH),
                "detail": "recon/report backend" if CBH.exists() else "not found (set CBH_HOME)"})

    ok = False
    detail = ARTEX_TOKEN or "no ARTEX_TOKEN"
    try:
        r = httpx.get(f"{ARTEX_URL}/api/health", timeout=3.0)
        ok = r.status_code < 500
        detail = f"HTTP {r.status_code}; " + ("token set" if ARTEX_TOKEN else "token missing")
    except httpx.HTTPError as exc:
        detail = f"unreachable: {exc}"
    out.append({"name": "artex", "ok": ok, "url": ARTEX_URL, "detail": detail})

    ok = False
    detail = "unreachable"
    try:
        r = httpx.get(PENTAGI_URL, timeout=3.0, verify=False)
        ok = r.status_code < 500
        detail = f"HTTP {r.status_code} (agent runs are manual)"
    except httpx.HTTPError as exc:
        detail = f"unreachable: {exc}"
    out.append({"name": "pentagi", "ok": ok, "url": PENTAGI_URL, "detail": detail})

    for name, url in (("juice-shop", "http://localhost:3000"),
                      ("burp", "http://127.0.0.1:8080")):
        try:
            r = httpx.get(url, timeout=2.0)
            out.append({"name": name, "ok": True, "url": url, "detail": f"HTTP {r.status_code}"})
        except httpx.HTTPError:
            out.append({"name": name, "ok": False, "url": url, "detail": "not running"})
    return out


def format_status(rows: list[dict]) -> str:
    lines = []
    for r in rows:
        mark = "OK  " if r["ok"] else "MISS"
        lines.append(f"[{mark}] {r['name']:16} {r['url']}")
        lines.append(f"        {r['detail']}")
    return "\n".join(lines)
