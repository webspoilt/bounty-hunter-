"""Bounty Hunter 2.0 - Finding Deduplication and Correlation Engine.

Normalizes URLs, routes, HTTP methods, and vulnerability classes to identify
when multiple scanners (or repeated runs) detect the same underlying issue.
Merges evidence, updates confidence, and maintains duplicate lineage.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

from bb.models import Evidence, Finding


class FindingDeduplicator:
    """Computes deterministic correlation hashes and deduplicates security findings."""

    @classmethod
    def compute_correlation_key(cls, host: str, url: str, method: str, bug_class: str) -> str:
        """Generates a stable fingerprint based on host, normalized route, method, and bug class.
        
        Example:
        - GET /api/vulnerable/profiles/1 -> GET /api/vulnerable/profiles/{id}
        - GET /api/vulnerable/profiles/2 -> GET /api/vulnerable/profiles/{id}
        Both resolve to the same underlying IDOR endpoint fingerprint.
        """
        norm_host = (host or "").lower().strip()
        parsed = urlparse(url) if url else None
        path = parsed.path if parsed else url

        # Normalize path parameters: replace integer IDs and UUIDs with placeholders
        norm_path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        norm_path = re.sub(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)", "/{uuid}", norm_path)
        norm_path = re.sub(r"/[0-9a-fA-F]{16,64}(?=/|$)", "/{hash}", norm_path)

        norm_method = (method or "GET").upper().strip()
        norm_bug = cls._normalize_bug_class(bug_class)

        raw = f"{norm_host}|{norm_method}|{norm_path}|{norm_bug}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _normalize_bug_class(bug_class: str) -> str:
        b = (bug_class or "").lower().strip()
        if "idor" in b or "broken object" in b or "bfla" in b:
            return "idor"
        if "sql" in b or "sqli" in b:
            return "sqli"
        if "xss" in b or "cross-site scripting" in b:
            return "xss"
        if "ssrf" in b:
            return "ssrf"
        if "cors" in b:
            return "cors"
        if "open_redirect" in b or "redirect" in b:
            return "open_redirect"
        if "rce" in b or "command injection" in b:
            return "rce"
        if "traversal" in b or "lfi" in b:
            return "lfi"
        return b

    @classmethod
    def deduplicate_findings(cls, findings: list[Finding]) -> tuple[list[Finding], list[tuple[str, str]]]:
        """Takes a batch of findings, consolidates duplicates, and returns:
        (unique_findings, list_of_(duplicate_id, original_id))
        """
        seen: dict[str, Finding] = {}
        duplicates: list[tuple[str, str]] = []

        for f in findings:
            key = cls.compute_correlation_key(f.host, f.url, f.meta.get("method", "GET"), f.bug_class)
            f.meta["correlation_key"] = key

            if key not in seen:
                seen[key] = f
            else:
                original = seen[key]
                duplicates.append((f.id, original.id))
                # Merge evidence into the primary finding
                cls._merge_evidence(original, f)

        return list(seen.values()), duplicates

    @classmethod
    def _merge_evidence(cls, primary: Finding, secondary: Finding) -> None:
        """Combines evidence, notes other reporting engines, and escalates confidence if appropriate."""
        existing_summaries = {e.summary for e in primary.evidence}
        for ev in secondary.evidence:
            if ev.summary not in existing_summaries:
                primary.evidence.append(ev)
                existing_summaries.add(ev.summary)

        # Track engines that reported this
        engines = set(primary.meta.get("reporting_engines", [primary.meta.get("discovery_engine", "unknown")]))
        engines.add(secondary.meta.get("discovery_engine", "unknown"))
        primary.meta["reporting_engines"] = sorted(engines)

        # Multi-engine confirmation increases confidence
        if len(engines) > 1 and primary.confidence != "high":
            primary.confidence = "high"
            primary.meta["multi_engine_confirmed"] = True
