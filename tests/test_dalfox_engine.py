"""Unit and integration tests for Dalfox Engine Integration."""
from __future__ import annotations

import json
import pytest

from bb.engines.base import EngineCategory, EngineState, ExecutionContext, FindingLifecycle
from bb.engines.dalfox import DalfoxEngine


@pytest.fixture
def dalfox_engine():
    return DalfoxEngine()


def test_dalfox_properties(dalfox_engine):
    assert dalfox_engine.name == "dalfox"
    assert "Dalfox" in dalfox_engine.display_name
    assert dalfox_engine.category == EngineCategory.SPECIALIST
    assert dalfox_engine.official_repository == "https://github.com/hahwul/dalfox"
    assert dalfox_engine.license == "MIT"
    assert "reflected_xss" in dalfox_engine.get_capabilities()


def test_dalfox_availability(dalfox_engine):
    avail = dalfox_engine.check_availability()
    assert avail.name == "dalfox"
    assert avail.state in (EngineState.READY, EngineState.VERIFIED_OPERATIONAL, EngineState.NOT_INSTALLED)
    if avail.available:
        assert avail.binary_path is not None


def test_dalfox_target_validation(dalfox_engine):
    assert dalfox_engine.validate_target("http://127.0.0.1:8000/api/vulnerable/echo?msg=test") is True
    assert dalfox_engine.validate_target("https://example.com/search?q=1") is True
    assert dalfox_engine.validate_target("ftp://example.com") is False
    assert dalfox_engine.validate_target("not_a_url") is False


def test_dalfox_findings_parsing(dalfox_engine):
    sample_json = json.dumps([
        {
            "type": "V",
            "inject_type": "inHTML-URL",
            "poc_type": "plain",
            "method": "GET",
            "data": "http://127.0.0.1:8000/api/vulnerable/echo?msg=test%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
            "param": "msg",
            "payload": "\"><script>alert(1)</script>",
            "evidence": "<script>alert(1)</script>",
            "cwe": "CWE-79",
            "severity": "High",
        }
    ])
    ctx = ExecutionContext(program="owasp-lab", target="http://127.0.0.1:8000/api/vulnerable/echo?msg=test")
    findings = dalfox_engine.collect_findings(sample_json, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.bug_class == "xss"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.status == FindingLifecycle.DISCOVERED.value
    assert f.meta["upstream_status"] == "dalfox_verified"
    assert f.meta["param"] == "msg"


def test_dalfox_live_execution_vuln_and_secure(dalfox_engine):
    avail = dalfox_engine.check_availability()
    if not avail.available:
        pytest.skip("Dalfox binary not installed")

    # 1. Vulnerable endpoint
    ctx_vuln = ExecutionContext(
        program="owasp-lab",
        target="http://127.0.0.1:8000/api/vulnerable/echo?msg=test",
        timeout_sec=25,
    )
    res_vuln = dalfox_engine.execute(ctx_vuln)
    assert res_vuln.success is True
    assert len(res_vuln.findings) >= 1
    assert res_vuln.findings[0].bug_class == "xss"

    # 2. Secure control endpoint
    ctx_sec = ExecutionContext(
        program="owasp-lab",
        target="http://127.0.0.1:8000/api/secure/echo?msg=test",
        timeout_sec=25,
    )
    res_sec = dalfox_engine.execute(ctx_sec)
    assert res_sec.success is True
    assert len(res_sec.findings) == 0
