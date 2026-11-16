"""Deduplication and conflict resolution across multiple vulnerability dataset sources."""
from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional, Set, Tuple
from bb.intel.hexbrain_models import HexBrainReport


class Deduplicator:
    """Detects and resolves duplicate reports across heterogeneous sources."""

    def __init__(self):
        self.seen_ids: Set[str] = set()
        self.seen_content_hashes: Set[str] = set()
        self.seen_url_keys: Set[str] = set()

    @staticmethod
    def normalize_title(title: str) -> str:
        """Strip punctuation and whitespace for fuzzy duplicate detection."""
        t = re.sub(r"[^a-zA-Z0-9\s]", " ", title.lower())
        return " ".join(t.split())

    @staticmethod
    def compute_content_fingerprint(report: HexBrainReport) -> str:
        """Calculate content hash from title + core summary / details."""
        raw = f"{report.cwe_id or ''}|{Deduplicator.normalize_title(report.title)}|{report.vulnerability_details[:500]}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def is_duplicate(self, report: HexBrainReport) -> Tuple[bool, Optional[str]]:
        """Check if report has already been ingested by ID, URL, or content hash."""
        # Check explicit ID
        if report.report_id in self.seen_ids:
            return True, f"DUPLICATE_ID: {report.report_id}"

        # Check source URL
        if report.source_url:
            norm_url = report.source_url.rstrip("/").lower()
            if norm_url in self.seen_url_keys:
                return True, f"DUPLICATE_URL: {report.source_url}"

        # Check content fingerprint
        fp = self.compute_content_fingerprint(report)
        if fp in self.seen_content_hashes:
            return True, f"DUPLICATE_CONTENT_HASH: {fp}"

        return False, None

    def register(self, report: HexBrainReport) -> None:
        """Register report attributes to prevent subsequent duplicates."""
        self.seen_ids.add(report.report_id)
        if report.source_url:
            self.seen_url_keys.add(report.source_url.rstrip("/").lower())
        self.seen_content_hashes.add(self.compute_content_fingerprint(report))
