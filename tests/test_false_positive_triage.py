"""Tests for False-Positive Triage and Finding Context Enrichment."""
from __future__ import annotations

from pathlib import Path
import pytest

from bb.intel.false_positive_triage import FalsePositiveTriager, TriageVerdict
from bb.intel.finding_context import FindingContextEnricher
from bb.intel.knowledge_base import KnowledgeBase
from bb.intel.hexbrain_models import HexBrainReport


def test_triage_policy_prohibition(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test_kb.db")
    triager = FalsePositiveTriager(kb=kb)

    res = triager.triage_finding(
        finding_id="F-001",
        target_endpoint="/api/login",
        vulnerability_type="Rate Limiting Bypass",
        evidence="Sent 100 requests without HTTP 429",
        program_policy_prohibitions=["Rate Limiting", "DDoS"],
    )
    assert res.verdict == TriageVerdict.LIKELY_OUT_OF_SCOPE
    assert res.confidence >= 0.90


def test_triage_scanner_artifact_json_xss(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test_kb.db")
    triager = FalsePositiveTriager(kb=kb)

    res = triager.triage_finding(
        finding_id="F-002",
        target_endpoint="/api/v1/search",
        vulnerability_type="Cross-Site Scripting",
        evidence="HTTP 200 OK\nContent-Type: application/json\n\n{\"query\": \"<script>alert(1)</script>\"}",
        cwe_id="CWE-79",
    )
    assert res.verdict == TriageVerdict.LIKELY_SCANNER_ARTIFACT


def test_triage_likely_valid(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test_kb.db")
    triager = FalsePositiveTriager(kb=kb)

    evidence = (
        "GET /api/profiles/1 HTTP/1.1\n"
        "Cookie: session=bob_session_token\n"
        "HTTP/1.1 200 OK\n"
        '{"id": 1, "username": "alice", "email": "alice@example.com", "role": "admin"}'
    )
    res = triager.triage_finding(
        finding_id="F-003",
        target_endpoint="/api/profiles/1",
        vulnerability_type="IDOR",
        evidence=evidence,
        cwe_id="CWE-639",
    )
    assert res.verdict == TriageVerdict.LIKELY_VALID
    assert res.confidence >= 0.80


def test_finding_context_enricher(tmp_path: Path):
    kb = KnowledgeBase(db_path=tmp_path / "test_kb.db")
    enricher = FindingContextEnricher(kb=kb)

    finding = {
        "id": "F-010",
        "title": "BOLA user invoice",
        "type": "IDOR",
        "cwe_id": "CWE-639",
    }
    enriched = enricher.enrich(finding)
    assert enriched["cwe_canonical_name"] == "Authorization Bypass Through User-Controlled Key (IDOR / BOLA)"
    assert "A01:2025" in enriched["owasp_2025"]
