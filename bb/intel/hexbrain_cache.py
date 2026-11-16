"""Local response caching for HexBrain API calls with hash validation and TTL."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from bb.config import DATA


class HexBrainCache:
    """Thread-safe SQLite-backed response cache for HexBrain API queries."""

    def __init__(self, db_path: Optional[Path] = None, default_ttl_sec: int = 86400 * 7):
        if db_path is None:
            self.db_path = DATA / "hexbrain_cache.db"
        else:
            self.db_path = Path(db_path)
        self.default_ttl = default_ttl_sec
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS api_cache (
                    cache_key TEXT PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    params_hash TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    content_sha256 TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires ON api_cache (expires_at)")
            conn.commit()

    @staticmethod
    def compute_key(endpoint: str, params: Dict[str, Any]) -> Tuple[str, str]:
        canonical_params = json.dumps(params, sort_keys=True)
        params_hash = hashlib.sha256(canonical_params.encode("utf-8")).hexdigest()
        cache_key = f"{endpoint}:{params_hash}"
        return cache_key, params_hash

    def get(self, endpoint: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cache_key, _ = self.compute_key(endpoint, params)
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT response_json, expires_at, content_sha256 FROM api_cache WHERE cache_key = ?",
                (cache_key,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            if row["expires_at"] < now:
                # Expired
                cursor.execute("DELETE FROM api_cache WHERE cache_key = ?", (cache_key,))
                conn.commit()
                return None
            
            raw_text = row["response_json"]
            # Validate hash
            calc_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
            if calc_hash != row["content_sha256"]:
                return None  # Cache corruption

            try:
                return json.loads(raw_text)
            except Exception:
                return None

    def set(self, endpoint: str, params: Dict[str, Any], data: Dict[str, Any], ttl_sec: Optional[int] = None) -> None:
        cache_key, params_hash = self.compute_key(endpoint, params)
        now = time.time()
        ttl = ttl_sec if ttl_sec is not None else self.default_ttl
        expires_at = now + ttl
        raw_text = json.dumps(data)
        content_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO api_cache (
                    cache_key, endpoint, params_hash, response_json, created_at, expires_at, content_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (cache_key, endpoint, params_hash, raw_text, now, expires_at, content_sha256),
            )
            conn.commit()

    def purge_expired(self) -> int:
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM api_cache WHERE expires_at < ?", (now,))
            conn.commit()
            return cursor.rowcount

    def clear(self) -> None:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM api_cache")
            conn.commit()
