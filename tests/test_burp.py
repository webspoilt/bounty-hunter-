"""Burp 'Save selected items' XML import."""
import httpx
import pytest

from bb import burp
from bb.scope import Scope, ScopeViolation
from bb.store import Store

ITEM_HTTP = """<?xml version="1.0"?>
<items>
  <item>
    <url></url>
    <host ip="203.0.113.7">app.example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/api/invoice/12?client=me</path>
    <status>200</status>
    <request base64="true">R0VUIC9hcGkvaW52b2ljZS8xMj9jbGllbnQ9bWUgSFRUUC8xLjENCkF1dGhvcml6YXRpb246IEJlYXJlciBUYUNNR0hTU1NDT1ZXWU5dTkNPT1MgSVNGUVJINU0NCkhvc3Q6IGFwcC5leGFtcGxlLmNvbQ0KDQo=</request>
    <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0Keysic3RyaXBfc2VjcmV0IjogInNfdGVzdCJ9</response>
  </item>
  <item>
    <url>https://evil.example.org/steal</url>
    <host ip="203.0.113.99">evil.example.org</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/steal</path>
    <status>200</status>
  </item>
</items>
"""

RAW_REQUEST = ("GET /api/invoice/12 HTTP/1.1\r\n"
               "Authorization: Bearer REVIEW\n"
               "Host: app.example.com\r\n\r\n{")


def test_scope_trailing_whitespace_patience(store, tmp_path):
    """The out-of-scope host must be audited, never imported."""
    scope = Scope.from_entries("p", ["app.example.com"])
    run_id = store.start_run("p", "")
    path = tmp_path / "items.xml"
    path.write_text(ITEM_HTTP, encoding="utf-8")
    stats = burp.import_burp(path, scope, store, run_id, log=lambda *a, **k: None)
    assert stats["denied"] == 1
    assert stats["in_scope"] == 1
    rows = store.conn.execute("SELECT verdict FROM scope_audit").fetchall()
    assert any(r["verdict"] == "DENY" for r in rows)


def test_import_records_endpoints_and_redacts(store, tmp_path):
    scope = Scope.from_entries("p", ["app.example.com"])
    run_id = store.start_run("p", "")
    path = tmp_path / "items.xml"
    path.write_text(ITEM_HTTP, encoding="utf-8")
    stats = burp.import_burp(path, scope, store, run_id, log=lambda *a, **k: None)
    assert stats["endpoints"] == 1
    assert stats["id_endpoints"] == 1          # /api/invoice/12 is object-shaped
    ex = store.exchanges(run_id)
    assert len(ex) == 1
    assert "REVIEW" not in ex[0].request_headers.get("Authorization", "")
    strip_secret = ex[0].response_body
    assert strip_secret                      # identity survives; secrets were masked
    assert '"strip_secret"' in strip_secret


def test_non_base64_plain_items(store, tmp_path):
    scope = Scope.from_entries("p", ["app.example.com"])
    run_id = store.start_run("p", "")
    path = tmp_path / "items.xml"
    body = """<items>
      <item>
        <url>https://app.example.com/plain?a=1</url>
        <method>POST</method>
        <status>201</status>
        <request base64="false">POST /plain?a=1 HTTP/1.1\nX-Api-Key: SECRETKEY123\nHost: h\n\nbody</request>
        <response base64="false">HTTP/1.1 201 Created\n\nok</response>
      </item>
    </items>"""
    path.write_text(body, encoding="utf-8")
    stats = burp.import_burp(path, scope, store, run_id, log=lambda *a, **k: None)
    assert stats["exchanges"] == 1
    ex = store.exchanges(run_id)[0]
    assert "SECRETKEY123" not in ex.request_headers.get("X-Api-Key", "")


def test_import_never_replays_a_request(store, tmp_path):
    """The file import path must never touch the network."""
    scope = Scope.from_entries("p", ["app.example.com"])
    run_id = store.start_run("p", "")
    path = tmp_path / "items.xml"
    path.write_text(ITEM_HTTP, encoding="utf-8")
    burp.import_burp(path, scope, store, run_id, log=lambda *a, **k: None)
    assert store.conn.execute("SELECT COUNT(*) c FROM exchanges").fetchone()["c"] >= 1


def test_malformed_xml_raises(tmp_path):
    path = tmp_path / "bad.xml"
    path.write_text("<items><item></", encoding="utf-8")
    with pytest.raises(burp.BurpError):
        burp.load_burp(path)


def test_missing_file_raises():
    with pytest.raises(burp.BurpError):
        burp.load_burp("nope-does-not-exist.xml")


def test_via_cli(store, tmp_path, capsys, monkeypatch):
    import json
    from bb.cli import build_parser
    scope_path = tmp_path / "p.scope.json"
    Scope.from_entries("p", ["app.example.com"]).save(scope_path)
    import bb.config as config
    import bb.cli as cli
    monkeypatch.setattr(cli, "scope_path", lambda program: scope_path)
    path = tmp_path / "items.xml"
    path.write_text(ITEM_HTTP, encoding="utf-8")
    store_db = tmp_path / "db.sqlite"
    monkeypatch.setattr("bb.cli.Store", lambda: Store(store_db))
    parser = build_parser()
    argv = parser.parse_args(["import", "burp", str(path), "--program", "p"])
    assert argv.func(argv) == 0
    store = Store(store_db)
    assert store.conn.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"] == 1
