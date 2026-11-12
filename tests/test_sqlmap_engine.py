"""Unit and integration tests for SQLmap Engine Integration."""
from __future__ import annotations

import pytest

from bb.engines.base import EngineCategory, EngineState, ExecutionContext, FindingLifecycle
from bb.engines.sqlmap import SQLmapEngine


@pytest.fixture
def sqlmap_engine():
    return SQLmapEngine()


def test_sqlmap_properties(sqlmap_engine):
    assert sqlmap_engine.name == "sqlmap"
    assert "SQLmap" in sqlmap_engine.display_name
    assert sqlmap_engine.category == EngineCategory.SPECIALIST
    assert sqlmap_engine.official_repository == "https://github.com/sqlmapproject/sqlmap"
    assert sqlmap_engine.license == "GPL-2.0"
    assert "union_sqli" in sqlmap_engine.get_capabilities()


def test_sqlmap_availability(sqlmap_engine):
    avail = sqlmap_engine.check_availability()
    assert avail.name == "sqlmap"
    assert avail.state in (EngineState.READY, EngineState.VERIFIED_OPERATIONAL, EngineState.NOT_INSTALLED)
    if avail.available:
        assert avail.binary_path is not None


def test_sqlmap_target_validation(sqlmap_engine):
    assert sqlmap_engine.validate_target("http://127.0.0.1:8000/api/vulnerable/products/search?q=test") is True
    assert sqlmap_engine.validate_target("https://example.com/item?id=1") is True
    assert sqlmap_engine.validate_target("ftp://example.com") is False
    assert sqlmap_engine.validate_target("not_a_url") is False


def test_sqlmap_output_parsing(sqlmap_engine):
    sample_output = """
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: q (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: q=test' UNION ALL SELECT NULL,NULL,NULL,NULL,CHAR(113)-- uzvr
---
[INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
"""
    ctx = ExecutionContext(program="owasp-lab", target="http://127.0.0.1:8000/api/vulnerable/products/search?q=test")
    findings = sqlmap_engine.collect_findings(sample_output, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.bug_class == "sqli"
    assert f.severity == "critical"
    assert f.status == FindingLifecycle.DISCOVERED.value
    assert f.meta["upstream_status"] == "sqlmap_confirmed_injection"


def test_sqlmap_live_execution_vuln_and_secure(sqlmap_engine):
    avail = sqlmap_engine.check_availability()
    if not avail.available:
        pytest.skip("SQLmap binary not installed")

    # 1. Vulnerable endpoint
    ctx_vuln = ExecutionContext(
        program="owasp-lab",
        target="http://127.0.0.1:8000/api/vulnerable/products/search?q=test",
        timeout_sec=25,
    )
    res_vuln = sqlmap_engine.execute(ctx_vuln)
    assert res_vuln.success is True
    assert len(res_vuln.findings) == 1
    assert res_vuln.findings[0].bug_class == "sqli"

    # 2. Secure control endpoint
    ctx_sec = ExecutionContext(
        program="owasp-lab",
        target="http://127.0.0.1:8000/api/secure/products/search?q=test",
        timeout_sec=25,
    )
    res_sec = sqlmap_engine.execute(ctx_sec)
    assert res_sec.success is True
    assert len(res_sec.findings) == 0
