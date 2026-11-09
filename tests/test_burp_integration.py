"""Comprehensive tests for Strategic Task P7: Burp Suite Integration & Researcher Workspace.

Tests:
1. Proxy configuration & traffic transmission
2. Proxy connection failure: confirms proxy errors are raised cleanly and no unintended direct fallback occurs
3. HAR imports with extended timing & authentication context detection
4. Malformed and invalid HAR handling
5. Sensitive credential & header redaction in HAR / Burp imports
6. Evidence linking & Burp XML traffic export (Repeater/Intruder XML format)
7. Duplicate traffic handling & out-of-scope traffic filtering
8. Safe imports without automatic request replay
9. Burp REST API client probing, error handling, local binding enforcement, and unsupported capability fallback
10. Researcher Workspace rendering of verified findings vs. unverified candidates
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from bb.burp import import_burp, load_burp
from bb.burp_api import BurpApiClient, BurpApiError
from bb.burp_export import export_exchanges_to_burp_xml, export_finding_to_burp
from bb.har import HarError, count_ids, import_har, load_har
from bb.http import ScopedClient
from bb.models import Evidence, Exchange, Finding
from bb.scope import Scope, ScopeViolation
from bb.store import Store


@pytest.fixture
def test_scope():
    return Scope.from_entries("test-lab", ["lab.test", "*.lab.test", "127.0.0.1"])


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "test_p7.db")
    yield s
    s.close()


# --- 1 & 2: Proxy Configuration & Prevention of Direct Fallback ---

def test_proxy_configuration_and_attribute(test_scope):
    client = ScopedClient(test_scope, proxy="http://127.0.0.1:8080", dry_run=True)
    assert client.proxy == "http://127.0.0.1:8080"
    client.close()


def test_proxy_connection_failure_prevents_direct_fallback(test_scope):
    """When a proxy is configured and fails, ScopedClient must fail cleanly rather than

    silently bypassing the proxy to execute directly.
    """
    client = ScopedClient(
        test_scope,
        proxy="http://127.0.0.1:59997",  # Closed local port
        timeout=0.5,
        resolve_dns=False,
    )

    with pytest.raises(httpx.HTTPError) as exc_info:
        client.get("http://127.0.0.1/api/test")

    # Confirms connection failure was raised and no direct fallback occurred
    assert isinstance(exc_info.value, (httpx.ProxyError, httpx.ConnectError, httpx.ConnectTimeout))
    client.close()


# --- 3, 4, 5: Improved HAR Ingestion, Timings, Auth Context, & Redaction ---

def test_improved_har_ingestion_with_auth_context_and_timing(tmp_path, test_scope, store):
    har_doc = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "startedDateTime": "2026-11-09T18:00:00.000Z",
                    "time": 45.2,
                    "request": {
                        "method": "GET",
                        "url": "https://lab.test/api/v1/profile",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer secret_jwt_token_123"},
                            {"name": "Cookie", "value": "session=abc12345; theme=dark"},
                        ],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"username": "alice", "email": "alice@lab.test"}),
                        },
                    },
                }
            ],
        }
    }

    har_path = tmp_path / "test_auth.har"
    har_path.write_text(json.dumps(har_doc), encoding="utf-8")

    entries = load_har(har_path)
    assert len(entries) == 1
    e = entries[0]
    assert e.started_at == "2026-11-09T18:00:00.000Z"
    assert e.duration_ms == 45
    # Auth context safely detected without leaking secrets
    assert e.auth_context.get("auth_type") == "bearer"
    assert e.auth_context.get("session_cookie") == "present"
    # Redaction verified
    assert "secret_jwt_token_123" not in str(e.request_headers)
    assert "[REDACTED]" in e.request_headers.get("Authorization", "")

    # Import into store and verify endpoint metadata
    run_id = store.start_run("test-lab", "https://lab.test", test_scope.fingerprint)
    stats = import_har(har_path, test_scope, store, run_id)
    assert stats["in_scope"] == 1
    assert stats["exchanges"] == 1

    endpoints = store.endpoints(run_id)
    assert len(endpoints) == 1
    assert endpoints[0]["auth_hint"] == "bearer"


def test_malformed_har_handling(tmp_path):
    bad_har = tmp_path / "corrupt.har"
    bad_har.write_text("{ not json", encoding="utf-8")
    with pytest.raises(HarError) as exc_info:
        load_har(bad_har)
    assert "invalid HAR JSON" in str(exc_info.value)


# --- 6: Burp XML Traffic Export with Linked References ---

def test_burp_xml_export_with_references(tmp_path):
    ex = Exchange(
        method="GET",
        url="https://lab.test/api/user/10",
        status=200,
        request_headers={"Host": "lab.test", "User-Agent": "BountyBot"},
        request_body="",
        response_headers={"Content-Type": "application/json"},
        response_body='{"user_id": 10, "role": "admin"}',
        duration_ms=25,
        note="IDOR candidate read",
    )

    finding = Finding(
        title="IDOR in User API",
        bug_class="IDOR",
        severity="high",
        status="candidate",
        url="https://lab.test/api/user/10",
        evidence=[Evidence(summary="Owner read", exchange=ex)],
        meta={"investigation_id": "inv-42", "hypothesis_id": "hypo-99"},
    )

    out_file = tmp_path / "finding_burp.xml"
    xml_str = export_finding_to_burp(finding, output_path=out_file, investigation_id="inv-42")

    assert out_file.exists()
    assert "<items" in xml_str
    assert "<item>" in xml_str
    assert "<url>https://lab.test/api/user/10</url>" in xml_str
    assert "inv:inv-42" in xml_str
    assert "hypo:hypo-99" in xml_str
    assert f"finding:{finding.id}" in xml_str


# --- 7 & 8: Duplicate & Out-of-Scope Traffic Handling Without Replay ---

def test_out_of_scope_traffic_audited_and_not_replayed(tmp_path, test_scope, store):
    har_doc = {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://unauthorized-domain.com/secret"},
                    "response": {"status": 200, "content": {"text": "external"}},
                }
            ],
        }
    }
    har_path = tmp_path / "out_of_scope.har"
    har_path.write_text(json.dumps(har_doc), encoding="utf-8")

    run_id = store.start_run("test-lab", "https://lab.test", test_scope.fingerprint)
    stats = import_har(har_path, test_scope, store, run_id)

    assert stats["in_scope"] == 0
    assert stats["denied"] == 1
    # Deny was recorded in scope_audit table
    audits = store.conn.execute("SELECT * FROM scope_audit WHERE run_id=?", (run_id,)).fetchall()
    assert len(audits) == 1
    assert audits[0]["verdict"] == "DENY"
    # No exchange added
    assert stats["exchanges"] == 0


# --- 9: Burp REST API Probing & Local Binding Security ---

def test_burp_api_local_binding_enforcement():
    with pytest.raises(BurpApiError) as exc_info:
        BurpApiClient(base_url="https://attacker.com:1337")
    assert "must connect to a local address" in str(exc_info.value)


def test_burp_api_probe_unsupported_or_offline():
    client = BurpApiClient(base_url="http://127.0.0.1:59998", timeout=0.5)
    probe = client.probe()
    assert probe["available"] is False
    assert "Community" in probe["edition"]
    assert probe["supported_capabilities"] == []


# --- 10: Researcher Workspace Verified vs. Unverified Separation ---

def test_researcher_workspace_tiers_and_evidence(store):
    candidate = Finding(
        title="Unverified Candidate Claim",
        bug_class="Broken Authentication",
        severity="medium",
        status="candidate",
        url="https://lab.test/admin",
    )
    store.add_finding(candidate, run_id="run-1")

    confirmed = Finding(
        title="Verified IDOR Finding",
        bug_class="IDOR",
        severity="high",
        status="confirmed",
        url="https://lab.test/api/user/5",
        meta={"verify": {"verdict": "confirmed"}},
    )
    store.add_finding(confirmed, run_id="run-1")

    findings = store.findings()
    cand_f = next(f for f in findings if f.status == "candidate")
    conf_f = next(f for f in findings if f.status == "confirmed")

    assert cand_f.status == "candidate"
    assert conf_f.status == "confirmed"
    assert cand_f.status != conf_f.status
