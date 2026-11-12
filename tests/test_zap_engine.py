"""Unit and regression tests for OWASP ZAP Engine Integration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bb.engines.base import EngineCategory, EngineState, ExecutionContext, FindingLifecycle
from bb.engines.zap import ZAPEngine


@pytest.fixture
def zap_engine():
    return ZAPEngine()


@pytest.fixture
def sample_zap_json(tmp_path: Path) -> Path:
    data = {
        "@version": "2.17.0",
        "site": [
            {
                "@name": "http://127.0.0.1:8000",
                "@host": "127.0.0.1",
                "@port": "8000",
                "@ssl": "false",
                "alerts": [
                    {
                        "pluginId": "40018",
                        "alert": "SQL Injection",
                        "name": "SQL Injection",
                        "riskcode": "3",
                        "confidence": "2",
                        "riskdesc": "High (Medium)",
                        "desc": "SQL injection may be possible on query parameter q.",
                        "uri": "http://127.0.0.1:8000/api/vulnerable/products/search?q=test",
                        "param": "q",
                        "attack": "test' OR '1'='1",
                        "evidence": "sqlite3.OperationalError",
                        "solution": "Use parameterized queries.",
                        "cweid": "89",
                        "wascid": "19",
                        "sourceid": "2",
                    },
                    {
                        "pluginId": "10021",
                        "alert": "X-Content-Type-Options Header Missing",
                        "name": "X-Content-Type-Options Header Missing",
                        "riskcode": "1",
                        "confidence": "2",
                        "riskdesc": "Low (Medium)",
                        "desc": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
                        "uri": "http://127.0.0.1:8000/api/lab/catalog",
                        "param": "",
                        "attack": "",
                        "evidence": "",
                        "solution": "Ensure that the application/web-server sets the Content-Type header appropriately.",
                        "cweid": "693",
                        "wascid": "16",
                        "sourceid": "1",
                    },
                ],
            }
        ],
    }
    p = tmp_path / "zap_sample.json"
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def sample_zap_xml(tmp_path: Path) -> Path:
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<OWASPZAPReport version="2.17.0" generated="Thu, 12 Nov 2026 18:00:00">
  <site name="http://127.0.0.1:8000" host="127.0.0.1" port="8000" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>40012</pluginid>
        <alert>Cross Site Scripting (Reflected)</alert>
        <riskcode>3</riskcode>
        <riskdesc>High (Medium)</riskdesc>
        <desc>A reflected XSS was detected on parameter msg.</desc>
        <uri>http://127.0.0.1:8000/api/vulnerable/echo?msg=test</uri>
        <param>msg</param>
        <attack>&lt;script&gt;alert(1)&lt;/script&gt;</attack>
        <evidence>&lt;script&gt;alert(1)&lt;/script&gt;</evidence>
        <solution>Encode all unescaped output.</solution>
        <cweid>79</cweid>
        <sourceid>2</sourceid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""
    p = tmp_path / "zap_sample.xml"
    p.write_text(xml_content, encoding="utf-8")
    return p


def test_zap_engine_properties(zap_engine):
    assert zap_engine.name == "zap"
    assert "OWASP ZAP" in zap_engine.display_name
    assert zap_engine.category == EngineCategory.DAST
    assert zap_engine.official_repository == "https://github.com/zaproxy/zaproxy"
    assert zap_engine.license == "Apache-2.0"
    assert "spider" in zap_engine.get_capabilities()
    assert "active_scan" in zap_engine.get_capabilities()
    assert "xml_report_import" in zap_engine.get_capabilities()


def test_zap_availability_detection(zap_engine):
    avail = zap_engine.check_availability()
    assert avail.name == "zap"
    assert avail.state in (EngineState.NOT_INSTALLED, EngineState.READY, EngineState.VERIFIED_OPERATIONAL)


def test_zap_target_validation(zap_engine):
    assert zap_engine.validate_target("http://127.0.0.1:8000/api") is True
    assert zap_engine.validate_target("https://example.com") is True
    assert zap_engine.validate_target("not_a_url") is False
    assert zap_engine.validate_target("") is False


def test_zap_json_report_import(zap_engine, sample_zap_json):
    ctx = ExecutionContext(program="owasp-lab", target="http://127.0.0.1:8000")
    findings = zap_engine.import_report(sample_zap_json, ctx)

    assert len(findings) == 2

    # Active SQLi finding
    sqli = next(f for f in findings if f.bug_class == "sqli")
    assert sqli.severity == "high"
    assert sqli.confidence == "medium"
    assert sqli.status == FindingLifecycle.DISCOVERED.value
    assert sqli.meta["zap_scan_type"] == "active"
    assert "[ZAP Active]" in sqli.title
    assert sqli.meta["cwe"] == "CWE-89"
    assert len(sqli.evidence) == 1
    assert sqli.evidence[0].extra["attack_payload"] == "test' OR '1'='1"

    # Passive observation finding
    headers_alert = next(f for f in findings if f.bug_class == "missing_security_headers")
    assert headers_alert.severity == "low"
    assert headers_alert.meta["zap_scan_type"] == "passive"
    assert "[ZAP Passive]" in headers_alert.title
    assert headers_alert.meta["cwe"] == "CWE-693"


def test_zap_xml_report_import(zap_engine, sample_zap_xml):
    ctx = ExecutionContext(program="owasp-lab", target="http://127.0.0.1:8000")
    findings = zap_engine.import_report(sample_zap_xml, ctx)

    assert len(findings) == 1
    xss = findings[0]
    assert xss.bug_class == "xss"
    assert xss.severity == "high"
    assert xss.meta["zap_scan_type"] == "active"
    assert xss.status == FindingLifecycle.DISCOVERED.value
    assert xss.meta["cwe"] == "CWE-79"
