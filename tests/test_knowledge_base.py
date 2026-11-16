"""Tests for KnowledgeBase, Chunking, and Hybrid Retrieval."""
from __future__ import annotations

from pathlib import Path
import pytest

from bb.intel.hexbrain_models import HexBrainReport, HexBrainTechnique
from bb.intel.chunking import chunk_vulnerability_report
from bb.intel.knowledge_base import KnowledgeBase
from bb.intel.retrieval import HybridRetriever


def test_chunking_vulnerability_report():
    rep = HexBrainReport(
        report_id="H1-TEST-01",
        title="IDOR on User Invoice Download",
        source="hackerone",
        source_url="https://hackerone.com/reports/123",
        cwe_id="CWE-639",
        severity="high",
        summary="User can download invoices of other users by altering invoice_id parameter.",
        vulnerability_details="When fetching /api/invoices/99, the server fails to check ownership.",
        reproduction_steps="1. Log in as Bob\n2. Call GET /api/invoices/1",
        impact="Unauthorized disclosure of customer PII and purchasing receipts.",
        remediation="Check that invoice.user_id matches current_user.id.",
        technologies=["python", "django"],
        training_eligible=False,
    )
    chunks = chunk_vulnerability_report(rep)
    assert len(chunks) == 5
    sections = [c.section for c in chunks]
    assert "overview" in sections
    assert "root_cause" in sections
    assert "reproduction" in sections
    assert "impact" in sections
    assert "remediation" in sections


def test_knowledge_base_crud_and_fts(tmp_path: Path):
    db_file = tmp_path / "kb_test.db"
    kb = KnowledgeBase(db_path=db_file)

    rep = HexBrainReport(
        report_id="H1-SQLI-01",
        title="SQL Injection on search box",
        source="hexbrain",
        source_url="https://hackerone.com/reports/555",
        cwe_id="CWE-89",
        severity="critical",
        bounty_amount=3000.0,
        summary="Attacker can extract user table using UNION SELECT payload.",
        vulnerability_details="Vulnerable parameter 'q' directly concatenated into raw query.",
        technologies=["php", "mysql"],
        training_eligible=True,
    )
    kb.store_report(rep)

    assert kb.count_reports() == 1
    assert kb.count_chunks() >= 1

    fetched = kb.get_report("H1-SQLI-01")
    assert fetched is not None
    assert fetched.cwe_id == "CWE-89"
    assert fetched.bounty_amount == 3000.0

    # Test Hybrid Retriever FTS matching
    retriever = HybridRetriever(kb=kb)
    results = retriever.search(query="UNION SELECT raw query", cwe_id="CWE-89")
    assert len(results) >= 1
    assert results[0]["report"].report_id == "H1-SQLI-01"

    # Test search with non-matching CWE
    no_results = retriever.search(query="UNION SELECT", cwe_id="CWE-79")
    assert len(no_results) == 0
