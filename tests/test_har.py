import json

import pytest

from bb.har import HarError, count_ids, import_har, load_har
from bb.scope import Scope
from bb.store import Store


def entry(method, url, *, status=200, req_headers=None, resp_headers=None,
          req_body=None, resp_body=None, encoding=None, mime="application/json"):
    content = {"mimeType": mime, "text": resp_body or ""}
    if encoding:
        content["encoding"] = encoding
    return {
        "time": 12.5,
        "request": {"method": method, "url": url,
                    "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()],
                    "postData": {"mimeType": "application/json", "text": req_body}
                    if req_body is not None else {}},
        "response": {"status": status,
                     "headers": [{"name": k, "value": v}
                                 for k, v in (resp_headers or {}).items()],
                     "content": content},
    }


def write_har(tmp_path, entries):
    p = tmp_path / "capture.har"
    p.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), encoding="utf-8")
    return p


def test_count_ids():
    assert count_ids("https://lab.test/api/users/42")
    assert count_ids("https://lab.test/api/items?id=9")
    assert not count_ids("https://lab.test/api/products")


def test_import_har_scope_redaction_and_inventory(tmp_path):
    entries = [
        entry("GET", "https://lab.test/api/users/7",
              req_headers={"Authorization": "Bearer SECRET-TOKEN"},
              resp_headers={"Set-Cookie": "session=abc", "Server": "lab"},
              resp_body=json.dumps({"id": 7, "email": "alice@lab.test",
                                    "token": "supersecret"})),
        entry("POST", "https://lab.test/api/items",
              req_body="email=a%40lab.test&password=hunter2",
              resp_body='{"id": 99}'),
        entry("GET", "https://evil.test/collect", resp_body="tracking"),
    ]
    scope = Scope.from_entries("p", ["lab.test"])
    store = Store(tmp_path / "db.sqlite")
    run_id = store.start_run("p")
    stats = import_har(write_har(tmp_path, entries), scope, store, run_id, log=lambda *_: None)

    assert stats["entries"] == 3
    assert stats["in_scope"] == 2
    assert stats["denied"] == 1
    assert stats["endpoints"] == 2
    assert stats["id_endpoints"] == 1
    assert stats["exchanges"] == 2

    rows = store.conn.execute("SELECT * FROM exchanges").fetchall()
    for row in rows:
        assert "SECRET-TOKEN" not in row["req_headers"]
        assert "supersecret" not in row["resp_body"]
        assert "hunter2" not in row["req_body"]
    deny = store.conn.execute(
        "SELECT COUNT(*) c FROM scope_audit WHERE verdict='DENY'").fetchone()["c"]
    assert deny == 1
    endpoints = {e["url"] for e in store.endpoints(run_id)}
    assert "https://lab.test/api/users/7" in endpoints
    assert not any("evil.test" in u for u in endpoints)


def test_import_har_base64_and_binary(tmp_path):
    b64 = __import__("base64").b64encode(b'{"ok": true}').decode()
    entries = [
        entry("GET", "https://lab.test/api/a", resp_body=b64, encoding="base64"),
        entry("GET", "https://lab.test/logo.png", resp_body="AAAA", mime="image/png"),
    ]
    scope = Scope.from_entries("p", ["lab.test"])
    store = Store(tmp_path / "db.sqlite")
    run_id = store.start_run("p")
    import_har(write_har(tmp_path, entries), scope, store, run_id, log=lambda *_: None)
    bodies = [r["resp_body"] for r in store.conn.execute("SELECT resp_body FROM exchanges")]
    assert any('"ok": true' in b for b in bodies)
    assert all("AAAA" not in b for b in bodies)


def test_invalid_har_rejected(tmp_path):
    p = tmp_path / "bad.har"
    p.write_text('{"log": {}}', encoding="utf-8")
    scope = Scope.from_entries("p", ["lab.test"])
    store = Store(tmp_path / "db.sqlite")
    run_id = store.start_run("p")
    with pytest.raises(HarError):
        import_har(p, scope, store, run_id, log=lambda *_: None)

    # a header-injection shaped URL is dropped by the shared loader, not written anywhere
    weird = write_har(tmp_path, [entry("GET", "https://lab.test/a\nInjected: yes")])
    assert load_har(weird) == []
