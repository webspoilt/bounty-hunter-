"""Unit and regression tests for Burp Suite Engine Integration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bb.engines.base import EngineCategory, EngineState, ExecutionContext, FindingLifecycle
from bb.engines.burpsuite import BurpSuiteEngine
from bb.store import Store


@pytest.fixture
def burp_engine():
    return BurpSuiteEngine()


@pytest.fixture
def sample_xml(tmp_path: Path) -> Path:
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<issues burpVersion="2026.9.3">
  <issue>
    <serialNumber>101</serialNumber>
    <type>1048832</type>
    <name>SQL injection</name>
    <host ip="127.0.0.1">http://127.0.0.1:8000</host>
    <path>/api/vulnerable/products/search</path>
    <location>/api/vulnerable/products/search [q]</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueDetail>Parameter q is vulnerable to UNION injection.</issueDetail>
    <issueBackground>SQL injection background details.</issueBackground>
    <remediationBackground>Parameterized queries.</remediationBackground>
    <requestresponse>
      <request base64="true">R0VUIC9hcGkvdnVsbmVyYWJsZS9wcm9kdWN0cy9zZWFyY2g/cT10ZXN0IEhUVFAvMS4xDQpIb3N0OiAxMjcuMC4wLjE6ODAwMA0KDQo=</request>
      <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0KeyJzdGF0dXMiOiAib2sifQ==</response>
    </requestresponse>
  </issue>
  <issue>
    <serialNumber>102</serialNumber>
    <type>2097408</type>
    <name>Cross-site scripting (reflected)</name>
    <host ip="127.0.0.1">http://127.0.0.1:8000</host>
    <path>/api/vulnerable/echo</path>
    <location>/api/vulnerable/echo</location>
    <severity>Medium</severity>
    <confidence>Firm</confidence>
    <issueDetail>Echoes unescaped input.</issueDetail>
    <issueBackground>XSS details.</issueBackground>
    <remediationBackground>HTML encoding.</remediationBackground>
  </issue>
</issues>
"""
    p = tmp_path / "burp_export.xml"
    p.write_text(xml_content, encoding="utf-8")
    return p


@pytest.fixture
def sample_items_xml(tmp_path: Path) -> Path:
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<items burpVersion="2026.9.3">
  <item>
    <time>Thu Nov 12 17:00:00 IST 2026</time>
    <url>http://127.0.0.1:8000/api/vulnerable/profiles/1</url>
    <host ip="127.0.0.1">127.0.0.1</host>
    <port>8000</port>
    <protocol>http</protocol>
    <method>GET</method>
    <path>/api/vulnerable/profiles/1</path>
    <status>200</status>
    <responselength>120</responselength>
    <mimetype>JSON</mimetype>
    <comment>Candidate Profile IDOR</comment>
    <request base64="true">R0VUIC9hcGkvdnVsbmVyYWJsZS9wcm9maWxlcy8xIEhUVFAvMS4xDQpIb3N0OiAxMjcuMC4wLjE6ODAwMA0KQXV0aG9yaXphdGlvbjogQmVhcmVyIHNlc3Npb25fYm9iXzQ1Ng0KDQo=</request>
    <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0KeyJ1c2VybmFtZSI6ICJhbGljZSJ9</response>
  </item>
</items>
"""
    p = tmp_path / "burp_items.xml"
    p.write_text(xml_content, encoding="utf-8")
    return p


def test_burp_engine_properties(burp_engine):
    assert burp_engine.name == "burpsuite"
    assert "Burp Suite" in burp_engine.display_name
    assert burp_engine.category == EngineCategory.SPECIALIST
    assert burp_engine.official_repository == "https://portswigger.net/burp"
    assert "xml_items_import" in burp_engine.get_capabilities()
    assert "http_proxy_interception" in burp_engine.get_capabilities()


def test_burp_availability_detection(burp_engine):
    avail = burp_engine.check_availability()
    assert avail.name == "burpsuite"
    assert avail.state in (EngineState.READY, EngineState.VERIFIED_OPERATIONAL, EngineState.NOT_INSTALLED)
    if avail.available:
        assert "Community" in avail.version or "Professional" in avail.version
        assert avail.binary_path is not None


def test_burp_target_validation(burp_engine):
    assert burp_engine.validate_target("http://127.0.0.1:8000/api/vulnerable") is True
    assert burp_engine.validate_target("https://example.com/login") is True
    assert burp_engine.validate_target("not_a_url") is False
    assert burp_engine.validate_target("ftp://example.com") is False
    assert burp_engine.validate_target("") is False


def test_burp_xml_issues_parsing(burp_engine, sample_xml):
    ctx = ExecutionContext(program="test-prog", target="http://127.0.0.1:8000")
    findings = burp_engine.import_file(sample_xml, ctx)

    assert len(findings) == 2

    sqli = next(f for f in findings if f.bug_class == "sqli")
    assert sqli.severity == "high"
    assert sqli.confidence == "high"
    assert sqli.status == FindingLifecycle.DISCOVERED.value # Crucial: NEVER auto-verified
    assert "UNION injection" in sqli.summary
    assert len(sqli.evidence) == 1
    assert "raw_request" in sqli.evidence[0].extra

    xss = next(f for f in findings if f.bug_class == "xss")
    assert xss.severity == "medium"
    assert xss.confidence == "medium"
    assert xss.status == FindingLifecycle.DISCOVERED.value


def test_burp_traffic_items_parsing(burp_engine, sample_items_xml):
    transactions = burp_engine.import_traffic_items(sample_items_xml)
    assert len(transactions) == 1

    tx = transactions[0]
    assert tx.url == "http://127.0.0.1:8000/api/vulnerable/profiles/1"
    assert tx.method == "GET"
    assert tx.status == 200
    assert tx.comment == "Candidate Profile IDOR"
    assert "authorization" in tx.request_headers
    assert tx.request_headers["authorization"] == "Bearer session_bob_456"
    assert '{"username": "alice"}' in tx.response_body


def test_burp_configure_and_state(burp_engine):
    burp_engine.configure({"proxy_host": "127.0.0.2", "proxy_port": 8888})
    assert burp_engine._proxy_host == "127.0.0.2"
    assert burp_engine._proxy_port == 8888


def test_burp_cli_execution_roundtrip(sample_xml, tmp_path: Path):
    from bb.cli import main
    # Test burp status command
    ret_status = main(["engines", "burp", "status"])
    assert ret_status == 0

    # Test burp configure command
    ret_conf = main(["engines", "burp", "configure", "--port", "8080"])
    assert ret_conf == 0

    # Test burp import command
    ret_import = main(["engines", "burp", "import", str(sample_xml), "--program", "test_burp_cli"])
    assert ret_import == 0

    # Test burp findings command
    ret_findings = main(["engines", "burp", "findings", "--program", "test_burp_cli"])
    assert ret_findings == 0
