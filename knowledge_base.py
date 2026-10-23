"""
Knowledge Base — the "what does this program actually pay for" layer.

Pipeline: ingest curated text (disclosures, writeups, cheatsheets)
  -> chunk -> embed via Ollama(nomic-embed-text) -> local cosine search.

Deliberately dependency-light: requests/httpx + stdlib only. Vectors stored in
JSON; pure-python cosine is fine for a few hundred chunks (your whole corpus).
"""
from __future__ import annotations

import math
import json
from pathlib import Path
from typing import Any

import httpx

OLLAMA = "http://127.0.0.1:11434"
EMBED_MODEL = "nomic-embed-text"


def chunk_text(text: str, size: int = 900, overlap: int = 120) -> list[str]:
    text = " ".join(text.split())  # normalize whitespace
    if len(text) <= size:
        return [text] if text else []
    chunks = []
    start = 0
    while start < len(text):
        piece = text[start:start + size]
        chunks.append(piece)
        if start + size >= len(text):
            break
        start += size - overlap
    return chunks


class KnowledgeBase:
    def __init__(self, path: str | Path = "data/kb.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict[str, Any]] = []
        if self.path.exists():
            self.entries = json.loads(self.path.read_text(encoding="utf-8"))

    # ---------- internals ----------

    def _embed(self, texts: list[str]) -> list[list[float]]:
        with httpx.Client(timeout=180.0) as c:
            r = c.post(f"{OLLAMA}/api/embed",
                       json={"model": EMBED_MODEL, "input": texts})
            r.raise_for_status()
            data = r.json()
            return data["embeddings"]

    @staticmethod
    def _cosine(a: list[float], b: list[float]) -> float:
        num = sum(x * y for x, y in zip(a, b))
        da = math.sqrt(sum(x * x for x in a))
        db = math.sqrt(sum(x * x for x in b))
        return num / (da * db) if da and db else 0.0

    # ---------- API ----------

    def add_document(self, title: str, text: str, meta: dict | None = None) -> int:
        """Ingest one document: chunked, embedded, stored. Returns # chunks added."""
        chunks = chunk_text(text)
        if not chunks:
            return 0
        vectors = self._embed(chunks)
        for chunk, vec in zip(chunks, vectors):
            self.entries.append({
                "title": title,
                "meta": meta or {},
                "text": chunk,
                "vector": vec,
            })
        self.save()
        return len(chunks)

    def add_documents(
        self,
        docs: list[tuple[str, str, dict | None]],
        batch_size: int = 32,
        save_every: int = 500,
    ) -> int:
        """Bulk ingest (title, text, meta) tuples with batched embedding.
        Returns total chunks added. Saves periodically so a long run is resumable."""
        added = 0
        for i in range(0, len(docs), batch_size):
            batch = docs[i:i + batch_size]
            titles, chunks, metas = [], [], []
            for title, text, meta in batch:
                for c in chunk_text(text):
                    titles.append(title)
                    chunks.append(c)
                    metas.append(meta or {})
            if not chunks:
                continue
            vectors = self._embed(chunks)
            for title, chunk, meta, vec in zip(titles, chunks, metas, vectors):
                self.entries.append({
                    "title": title,
                    "meta": meta,
                    "text": chunk,
                    "vector": vec,
                })
            added += len(chunks)
            if added % save_every < batch_size:
                self.save()
        self.save()
        return added

    def query(self, question: str, k: int = 3) -> list[dict]:
        if not self.entries:
            return []
        [qvec] = self._embed([question])
        scored = [
            (self._cosine(qvec, e["vector"]), e)
            for e in self.entries
        ]
        scored.sort(key=lambda t: t[0], reverse=True)
        return [
            {"score": round(s, 4), "title": e["title"], "meta": e["meta"], "text": e["text"]}
            for s, e in scored[:k]
        ]

    def stats(self) -> dict:
        titles = {}
        for e in self.entries:
            titles[e["title"]] = titles.get(e["title"], 0) + 1
        return {"total_chunks": len(self.entries), "by_document": titles}

    def save(self) -> None:
        self.path.write_text(json.dumps(self.entries), encoding="utf-8")
