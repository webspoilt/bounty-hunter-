"""Tests for normalization, CVE lookup, learning, WAF canary probe, AI response analysis, UI dashboard, and autonomous loop."""
import json
import pytest
from pathlib import Path
from bb import normalize, cve, learn, waf, analyze, ui
from bb.models import Finding, Evidence, Exchange
from bb.scope import Scope
from bb.store import Store
from bb.auto import AutoHunter, AutoHunterConfig


def test_normalize_path_templates():
    assert normalize.normalize_path("/api/v1/users/1234") == "/api/v1/users/{id}"
    assert normalize.normalize_path("/posts/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11") == "/posts/{uuid}"
    assert normalize.normalize_path("/static/app.js") == "/static/app.js"
    assert normalize.normalize_url("https://example.com/api/v1/users/42?cb=123&page=1") == "//example.com/api/v1/users/{id}?cb=?&page=?"


def test_cve_index(tmp_path):
    cve_file = tmp_path / "test_cve.json"
    data = [
        {
            "id": "CVE-2024-9999",
            "title": "Example Nginx buffer overflow",
            "description": "Nginx 1.18 buffer overflow allows RCE",
            "products": ["nginx 1.18", "nginx"],
            "cvss": 9.8,
            "cwe": ["CWE-120"],
            "kev": True
        }
    ]
    cve_file.write_text(json.dumps(data), encoding="utf-8")
    idx_file = tmp_path / "index.json"
    idx = cve.CveIndex(path=idx_file)
    res = cve.import_file(cve_file, index=idx)
    assert res["records"] == 1
    assert res["added"] == 1
    hits = idx.query("nginx 1.18")
    assert len(hits) == 1
    assert hits[0]["id"] == "CVE-2024-9999"
    assert hits[0]["kev"] is True


def test_waf_canary_variants():
    canary = waf.canary()
    assert canary.startswith("bbwaf")
    vars = waf.variants(canary)
    assert len(vars) >= 5
    names = [v["name"] for v in vars]
    assert "plain" in names
    assert "url-encoded" in names
    assert "double-encoded" in names


def test_ai_response_analysis_offline():
    ex = Exchange(
        method="GET",
        url="https://app.example.com/api/users/2",
        status=200,
        response_body='{"id": 2, "name": "Bob", "secret": "12345"}',
        response_headers={"content-type": "application/json"}
    )
    finding = Finding(
        id="f-test-1",
        title="IDOR on /api/users/2",
        bug_class="IDOR",
        severity="high",
        confidence="high",
        status="candidate",
        url="https://app.example.com/api/users/2",
        host="app.example.com",
        summary="User A viewed User B's profile",
        evidence=[Evidence(summary="exchange", exchange=ex)]
    )
    analysis = analyze.analyze_offline(finding)
    assert "verdict" in analysis
    assert "next_tests" in analysis
    assert len(analysis["next_tests"]) > 0
    full_analysis = analyze.analyze(finding, use_llm=False)
    assert full_analysis["source"] in ("offline-rules", "deterministic")


def test_learning_report_and_export(tmp_path):
    db_file = tmp_path / "test.db"
    store = Store(path=db_file)
    f = Finding(
        id="f-learn-1",
        title="BOLA on /invoices/99",
        bug_class="bola",
        severity="high",
        confidence="high",
        status="candidate",
        url="https://app.example.com/invoices/99",
        host="app.example.com",
        evidence=[Evidence(summary="test ev")]
    )
    store.add_finding(f)
    store.set_outcome("f-learn-1", status="accepted", bounty=500.0)
    rep = learn.learning_report(store)
    assert rep["decided"] >= 1
    export_file = tmp_path / "sft.jsonl"
    exp = learn.export_dataset(store, path=export_file)
    assert exp["rows"] == 1
    assert export_file.exists()


def test_auto_hunter_dry_run(tmp_path):
    db_file = tmp_path / "auto.db"
    store = Store(path=db_file)
    scope = Scope(["app.example.com"])
    cfg = AutoHunterConfig(
        program="example",
        scope=scope,
        entry_urls=["https://app.example.com/"],
        dry_run=True,
        llm=False,
        run_waf_probe=False,
        cve_match=False,
        ai_analysis=False
    )
    hunter = AutoHunter(cfg, store=store, log=lambda msg: None)
    res = hunter.run()
    assert res["status"] == "completed"
    assert "run_id" in res


def test_ui_dashboard_handler(tmp_path):
    from unittest.mock import MagicMock
    from io import BytesIO
    handler = ui.DashboardHandler
    # Verify handler HTML is valid
    assert "BountyBot Dashboard" in ui.DASHBOARD_HTML
