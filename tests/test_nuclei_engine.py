"""Unit and integration tests for Nuclei Engine Integration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bb.engines.base import EngineCategory, EngineState, ExecutionContext, FindingLifecycle
from bb.engines.nuclei import NucleiEngine


@pytest.fixture
def nuclei_engine():
    return NucleiEngine()


@pytest.fixture
def sample_nuclei_jsonl(tmp_path: Path) -> Path:
    sample_data = [
        {
            "template-id": "fastapi-docs-exposure",
            "info": {
                "name": "FastAPI OpenAPI Documentation Exposed",
                "author": ["bountybot"],
                "tags": ["exposure", "api"],
                "description": "Publicly accessible Swagger UI docs.",
                "severity": "low",
                "classification": {"cve-id": []},
            },
            "type": "http",
            "matched-at": "http://127.0.0.1:8000/docs",
            "request": "GET /docs HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\n<html>Swagger UI</html>",
            "timestamp": "2026-11-12T18:00:00Z",
        },
        # Duplicate match to test deduplication
        {
            "template-id": "fastapi-docs-exposure",
            "info": {
                "name": "FastAPI OpenAPI Documentation Exposed",
                "severity": "low",
            },
            "type": "http",
            "matched-at": "http://127.0.0.1:8000/docs",
            "request": "GET /docs HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\n<html>Swagger UI</html>",
            "timestamp": "2026-11-12T18:00:01Z",
        },
        {
            "template-id": "cors-permissive-credentials",
            "info": {
                "name": "Permissive CORS with Credentials Misconfiguration",
                "author": ["bountybot"],
                "tags": ["cors", "misconfig"],
                "description": "Reflects arbitrary Origin with Allow-Credentials true.",
                "severity": "medium",
            },
            "type": "http",
            "matched-at": "http://127.0.0.1:8000/api/vulnerable/cors/user-info",
            "request": "GET /api/vulnerable/cors/user-info HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.com\r\n\r\n{}",
            "timestamp": "2026-11-12T18:00:02Z",
        },
    ]

    p = tmp_path / "nuclei_sample.jsonl"
    with open(p, "w", encoding="utf-8") as f:
        for item in sample_data:
            f.write(json.dumps(item) + "\n")
    return p


def test_nuclei_properties(nuclei_engine):
    assert nuclei_engine.name == "nuclei"
    assert "Nuclei" in nuclei_engine.display_name
    assert nuclei_engine.category == EngineCategory.DAST
    assert nuclei_engine.official_repository == "https://github.com/projectdiscovery/nuclei"
    assert nuclei_engine.license == "MIT"
    assert "cve" in nuclei_engine.get_capabilities()
    assert "exposure" in nuclei_engine.get_capabilities()


def test_nuclei_availability(nuclei_engine):
    avail = nuclei_engine.check_availability()
    assert avail.name == "nuclei"
    assert avail.state in (EngineState.READY, EngineState.VERIFIED_OPERATIONAL, EngineState.NOT_INSTALLED)
    if avail.available:
        assert "v3." in avail.version
        assert avail.binary_path is not None


def test_nuclei_target_validation(nuclei_engine):
    assert nuclei_engine.validate_target("http://127.0.0.1:8000") is True
    assert nuclei_engine.validate_target("https://example.com/api") is True
    assert nuclei_engine.validate_target("ftp://example.com") is False
    assert nuclei_engine.validate_target("invalid_url") is False


def test_nuclei_jsonl_parsing_and_deduplication(nuclei_engine, sample_nuclei_jsonl):
    ctx = ExecutionContext(program="owasp-lab", target="http://127.0.0.1:8000")
    findings = nuclei_engine.collect_findings(sample_nuclei_jsonl, ctx)

    # Must deduplicate the 2 identical fastapi-docs-exposure matches down to 1
    assert len(findings) == 2

    docs_finding = next(f for f in findings if f.meta["template_id"] == "fastapi-docs-exposure")
    assert docs_finding.severity == "low"
    assert docs_finding.bug_class == "exposed"
    assert docs_finding.status == FindingLifecycle.DISCOVERED.value
    assert docs_finding.meta["active_discovery"] is True
    assert len(docs_finding.evidence) == 1

    cors_finding = next(f for f in findings if f.meta["template_id"] == "cors-permissive-credentials")
    assert cors_finding.severity == "medium"
    assert cors_finding.bug_class == "cors"
    assert cors_finding.status == FindingLifecycle.DISCOVERED.value


def test_nuclei_live_execution_on_local_lab(nuclei_engine):
    avail = nuclei_engine.check_availability()
    if not avail.available:
        pytest.skip("Nuclei binary not installed")

    ctx = ExecutionContext(program="owasp-lab", target="http://127.0.0.1:8000", timeout_sec=20)
    result = nuclei_engine.execute(ctx)

    assert result.success is True
    assert result.exit_code == 0
    assert len(result.findings) >= 2  # Discovers docs and CORS misconfig
    assert any(f.bug_class == "cors" for f in result.findings)
