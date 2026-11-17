"""Lightweight vector store interface with cosine similarity for vulnerability chunks."""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Compute cosine similarity between two float vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))
    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0
    return dot / (norm1 * norm2)


class LocalVectorStore:
    """In-memory or SQLite-backed lightweight vector index for semantic retrieval."""

    def __init__(self):
        # chunk_id -> (vector, metadata)
        self.vectors: Dict[str, Tuple[List[float], Dict[str, Any]]] = {}

    def add(self, chunk_id: str, vector: List[float], metadata: Dict[str, Any]) -> None:
        self.vectors[chunk_id] = (vector, metadata)

    def search(self, query_vector: List[float], top_k: int = 5) -> List[Tuple[str, float, Dict[str, Any]]]:
        results: List[Tuple[str, float, Dict[str, Any]]] = []
        for chunk_id, (vec, meta) in self.vectors.items():
            sim = cosine_similarity(query_vector, vec)
            results.append((chunk_id, sim, meta))
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]
