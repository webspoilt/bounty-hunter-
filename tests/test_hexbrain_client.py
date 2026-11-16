"""Tests for HexBrain API Client, Models, and Caching."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from bb.intel.hexbrain_models import HexBrainReport, HexBrainTechnique
from bb.intel.hexbrain_cache import HexBrainCache
from bb.intel.hexbrain_client import HexBrainClient, HexBrainAuthError, HexBrainRateLimitError
from bb.intel.hexbrain_search import normalize_cwe_id, build_search_query
from bb.intel.hexbrain import HexBrainEngine


def test_hexbrain_report_serialization():
    rep = HexBrainReport(
        report_id="H1-1001",
        title="SQL Injection on login endpoint",
        source="hexbrain",
        source_url="https://hackerone.com/reports/1001",
        cwe_id="CWE-89",
        cwe_title="Improper Neutralization of Special Elements used in an SQL Command",
        vulnerability_type="sql_injection",
        severity="critical",
        bounty_amount=2500.0,
        program_handle="acme",
        technologies=["php", "mysql"],
        tags=["auth", "sqli"],
        license="custom",
        training_eligible=False,
    )
    d = rep.to_dict()
    assert d["report_id"] == "H1-1001"
    assert d["bounty_amount"] == 2500.0

    restored = HexBrainReport.from_dict(d)
    assert restored.report_id == rep.report_id
    assert restored.technologies == ["php", "mysql"]
    assert restored.training_eligible is False


def test_hexbrain_cache_roundtrip(tmp_path: Path):
    cache_db = tmp_path / "test_cache.db"
    cache = HexBrainCache(db_path=cache_db, default_ttl_sec=60)

    endpoint = "/test"
    params = {"q": "idor", "page": 1}
    data = {"status": "ok", "items": [1, 2, 3]}

    # Initially missing
    assert cache.get(endpoint, params) is None

    # Set and retrieve
    cache.set(endpoint, params, data)
    hit = cache.get(endpoint, params)
    assert hit is not None
    assert hit["items"] == [1, 2, 3]


def test_hexbrain_search_normalization():
    assert normalize_cwe_id("89") == "CWE-89"
    assert normalize_cwe_id("cwe-79") == "CWE-79"
    assert normalize_cwe_id("CWE-200") == "CWE-200"

    q = build_search_query("Testing CWE-89 injection", cwe=None, limit=200)
    assert q.cwe_id == "CWE-89"
    assert q.limit == 100  # Capped at 100


@patch("urllib.request.urlopen")
def test_hexbrain_client_test_connection_operational(mock_urlopen, tmp_path: Path):
    mock_classes = MagicMock()
    mock_classes.status = 200
    mock_classes.__enter__.return_value = mock_classes
    mock_classes.read.return_value = json.dumps({
        "total_reports": 15244,
        "programs": 428,
        "classes": [{"id": "XSS", "name": "Cross-site Scripting", "reports": 2587}],
    }).encode("utf-8")

    mock_urlopen.return_value = mock_classes

    cache = HexBrainCache(db_path=tmp_path / "cache.db")
    client = HexBrainClient(api_key="test_key_123", cache=cache)
    diag = client.test_connection()

    assert diag["connected"] is True
    assert diag["status"] == "OPERATIONAL"
    assert diag["dataset_stats"]["reports_count"] == 15244
    assert diag["dataset_stats"]["programs_count"] == 428


def test_hexbrain_client_unconfigured():
    client = HexBrainClient(api_key="")
    diag = client.test_connection()
    assert diag["connected"] is False
    assert diag["status"] == "UNCONFIGURED"


@patch("urllib.request.urlopen")
def test_hexbrain_client_search_reports(mock_urlopen, tmp_path: Path):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = json.dumps({
        "total": 1,
        "reports": [
            {
                "id": 9999,
                "title": "BOLA on user invoices",
                "weakness": "CWE-639",
                "vuln_class": "Broken Access Control",
                "severity": "high",
                "bounty_usd": 1500.0,
                "url": "https://hackerone.com/reports/9999",
            }
        ]
    }).encode("utf-8")
    mock_urlopen.return_value = mock_resp

    cache = HexBrainCache(db_path=tmp_path / "cache.db")
    client = HexBrainClient(api_key="test_key", cache=cache)
    reports = client.search_reports(query="invoice BOLA", cwe_id="CWE-639")

    assert len(reports) == 1
    assert reports[0].report_id == "H1-9999"
    assert reports[0].cwe_id == "CWE-639"
    assert reports[0].bounty_amount == 1500.0


def test_hexbrain_engine_facade():
    mock_client = MagicMock()
    mock_client.api_key = "test_key"
    mock_client.base_url = "https://api.hexbrain.io/v1"
    mock_client.test_connection.return_value = {
        "connected": True,
        "status": "OPERATIONAL",
        "message": "Connected",
        "dataset_stats": {"reports_count": 15244},
    }
    engine = HexBrainEngine(client=mock_client)
    st = engine.status()
    assert st["status"] == "OPERATIONAL"
    assert st["dataset_stats"]["reports_count"] == 15244
