import json

import pytest

from bb.h1 import H1Client, H1Error, submit_curl, submit_payload
from bb.models import Finding


def test_client_requires_credentials(monkeypatch):
    monkeypatch.setattr("bb.h1.H1_USERNAME", "")
    monkeypatch.setattr("bb.h1.H1_TOKEN", "")
    with pytest.raises(H1Error):
        H1Client(username="", token="")


def test_submit_payload_shape():
    f = Finding(title="IDOR on /api/x", bug_class="IDOR", severity="high",
                host="lab.test", url="http://lab.test/api/x/1")
    payload = submit_payload(f, "# report\nbody", "acme", weakness_id=55, structured_scope_id=9)
    attrs = payload["data"]["attributes"]
    assert attrs["team_handle"] == "acme"
    assert attrs["severity_rating"] == "high"
    assert attrs["weakness_id"] == 55
    assert attrs["structured_scope_id"] == 9
    assert attrs["vulnerability_information"].startswith("# report")


def test_submit_curl_is_printed_not_sent():
    f = Finding(title="t", bug_class="IDOR")
    text = submit_curl(submit_payload(f, "body", "acme"))
    assert "curl" in text
    assert "never executed" in text
    assert "api.hackerone.com/v1/reports" in text


def test_scope_import_maps_structured_scopes(monkeypatch):
    client = object.__new__(H1Client)          # skip __init__ (no credentials needed)
    payload = {"data": {"attributes": {"updated_at": "2026-10-01T00:00:00Z"},
                        "relationships": {"structured_scopes": {"data": [
                            {"attributes": {"asset_type": "WILDCARD",
                                            "asset_identifier": "*.acme.io",
                                            "eligible_for_submission": True}},
                            {"attributes": {"asset_type": "URL",
                                            "asset_identifier": "https://api.acme.io/v1",
                                            "eligible_for_submission": True}},
                        ]}}}}
    monkeypatch.setattr(H1Client, "program", lambda self, handle: payload)
    scope = client.scope("acme")
    assert scope.is_in_scope("https://app.acme.io/")
    assert scope.is_in_scope("https://api.acme.io/v1/x")


def test_url_only_scope_restricts_path(monkeypatch):
    client = object.__new__(H1Client)
    payload = {"data": {"relationships": {"structured_scopes": {"data": [
        {"attributes": {"asset_type": "URL", "asset_identifier": "https://api.acme.io/v1",
                        "eligible_for_submission": True}},
    ]}}}}
    monkeypatch.setattr(H1Client, "program", lambda self, handle: payload)
    scope = client.scope("acme")
    assert scope.is_in_scope("https://api.acme.io/v1/x")
    assert not scope.is_in_scope("https://api.acme.io/v2/x")
    assert not scope.is_in_scope("https://other.acme.io/v1/x")


def test_scope_import_without_scopes_is_actionable(monkeypatch):
    client = object.__new__(H1Client)
    monkeypatch.setattr(H1Client, "program", lambda self, handle: {"data": {}})
    with pytest.raises(H1Error) as exc:
        client.scope("acme")
    assert "--from file" in str(exc.value)
