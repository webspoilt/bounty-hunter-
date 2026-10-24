"""Knowledge base: local RAG over disclosed reports and playbooks.

Fixes over v1:
  * content-hash dedupe, so re-running an ingest does not duplicate every chunk
  * metadata filter (`where={"team": ...}`), so precedent is actually from the program
  * embedding-dimension check, so switching models fails loudly instead of scoring garbage
  * atomic save (tmp + replace) instead of truncating a 16 MB JSON file
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any

from bb.config import KB_PATH
from bb.llm import Ollama, OllamaError


def chunk_text(text: str, size: int = 900, overlap: int = 120) -> list[str]:
    text = " ".join((text or "").split())
    if not text:
        return []
    if len(text) <= size:
        return [text]
    chunks, start = [], 0
    while start < len(text):
        chunks.append(text[start:start + size])
        if start + size >= len(text):
            break
        start += size - overlap
    return chunks


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:24]


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        raise ValueError(f"embedding dimension mismatch: {len(a)} vs {len(b)}")
    num = sum(x * y for x, y in zip(a, b))
    da = math.sqrt(sum(x * x for x in a))
    db = math.sqrt(sum(x * x for x in b))
    return num / (da * db) if da and db else 0.0


class KnowledgeBase:
    def __init__(self, path: str | Path = KB_PATH, llm: Ollama | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.llm = llm or Ollama()
        self.entries: list[dict[str, Any]] = []
        self._hashes: set[str] = set()
        if self.path.exists():
            try:
                self.entries = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"knowledge base {self.path} is corrupt: {exc}") from exc
            self._hashes = {_hash(e.get("text", "")) for e in self.entries}

    # ---------- reads ----------

    @property
    def dim(self) -> int | None:
        for e in self.entries:
            v = e.get("vector")
            if v:
                return len(v)
        return None

    def stats(self) -> dict:
        by_doc: dict[str, int] = {}
        for e in self.entries:
            by_doc[e.get("title", "?")] = by_doc.get(e.get("title", "?"), 0) + 1
        return {"chunks": len(self.entries), "documents": len(by_doc),
                "dim": self.dim, "path": str(self.path), "by_document": by_doc}

    def query(self, question: str, k: int = 5, where: dict | None = None) -> list[dict]:
        candidates = [e for e in self.entries if self._matches(e, where)]
        if not candidates or not question.strip():
            return []
        if not self.llm.available():
            return []
        [qvec] = self.llm.embed([question])
        scored = [(_cosine(qvec, e["vector"]), e) for e in candidates if e.get("vector")]
        scored.sort(key=lambda t: t[0], reverse=True)
        return [{"score": round(s, 4), "title": e.get("title", ""),
                 "meta": e.get("meta") or {}, "text": e.get("text", "")}
                for s, e in scored[:k]]

    @staticmethod
    def _matches(entry: dict, where: dict | None) -> bool:
        if not where:
            return True
        meta = entry.get("meta") or {}
        return all(str(meta.get(k, "")).lower() == str(v).lower() for k, v in where.items())

    def lexical_contains(self, needle: str) -> int:
        """Cheap duplicate check: how many stored chunks mention this path verbatim."""
        needle = (needle or "").strip().lower()
        if len(needle) < 4:
            return 0
        return sum(1 for e in self.entries if needle in (e.get("text") or "").lower())

    # ---------- writes ----------

    def add_documents(self, docs: list[tuple[str, str, dict | None]],
                      batch_size: int = 32) -> int:
        """(title, text, meta) tuples. Skips chunks already present."""
        pending: list[tuple[str, str, dict]] = []
        for title, text, meta in docs:
            for chunk in chunk_text(text):
                h = _hash(chunk)
                if h in self._hashes:
                    continue
                self._hashes.add(h)
                pending.append((title, chunk, meta or {}))
        if not pending:
            return 0
        added = 0
        for i in range(0, len(pending), batch_size):
            batch = pending[i:i + batch_size]
            vectors = self.llm.embed([c for _, c, _ in batch])
            if len(vectors) != len(batch):
                raise OllamaError(f"embedding count mismatch: {len(vectors)} != {len(batch)}")
            for (title, chunk, meta), vec in zip(batch, vectors):
                self.entries.append({"title": title, "meta": meta, "text": chunk,
                                     "vector": vec})
                added += 1
        self.save()
        return added

    def add_document(self, title: str, text: str, meta: dict | None = None) -> int:
        return self.add_documents([(title, text, meta)])

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.entries, separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, self.path)

    def ingest_paths(self, paths: list[Path], source: str = "doc") -> int:
        docs = []
        for p in paths:
            if not p.exists():
                continue
            docs.append((p.stem, p.read_text(encoding="utf-8", errors="ignore"),
                         {"source": source, "path": str(p)}))
        return self.add_documents(docs)
