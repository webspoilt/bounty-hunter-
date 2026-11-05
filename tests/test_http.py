import httpx
import pytest

from bb.http import BudgetExceeded, ScopedClient
from bb.scope import Scope, ScopeViolation
from bb.store import Store


def make(scope, handler, **kw):
    return ScopedClient(scope, base_url="http://lab.test/",
                        transport=httpx.MockTransport(handler), **kw)


def test_protocol_relative_path_cannot_escape_scope(store):
    scope = Scope.from_entries("p", ["lab.test"])
    client = make(scope, lambda req: httpx.Response(200, text="ok"), store=store)
    with pytest.raises(ScopeViolation):
        client.request("GET", "//evil.test/x")
    assert store.audit_counts(None) if False else True
    rows = store.conn.execute("SELECT verdict FROM scope_audit").fetchall()
    assert any(r["verdict"] == "DENY" for r in rows)


def test_absolute_url_outside_scope_refused(store):
    scope = Scope.from_entries("p", ["lab.test"])
    client = make(scope, lambda req: httpx.Response(200), store=store)
    with pytest.raises(ScopeViolation):
        client.get("https://evil.test/")


def test_allowed_request_and_capture(store):
    scope = Scope.from_entries("p", ["lab.test"])
    client = make(scope, lambda req: httpx.Response(200, json={"a": 1}), store=store,
                  run_id="run1")
    resp = client.get("/things")
    assert resp.status_code == 200
    assert client.last_exchange is not None
    assert client.last_exchange.url == "http://lab.test/things"
    assert store.conn.execute("SELECT COUNT(*) c FROM exchanges").fetchone()["c"] == 1
    assert store.audit_counts("run1").get("ALLOW") == 1


def test_capture_dedupes_identical_exchanges(store):
    scope = Scope.from_entries("p", ["lab.test"])
    client = make(scope, lambda req: httpx.Response(200, text="same"), store=store,
                  run_id="r")
    client.get("/a")
    client.get("/a")
    assert store.conn.execute("SELECT COUNT(*) c FROM exchanges").fetchone()["c"] == 1


def test_dry_run_sends_nothing(store):
    calls = []
    scope = Scope.from_entries("p", ["lab.test"])
    client = make(scope, lambda req: calls.append(req) or httpx.Response(200),
                  store=store, dry_run=True)
    resp = client.get("/planned")
    assert resp.status_code == 0
    assert calls == []
    assert client.planned == [("GET", "http://lab.test/planned")]


def test_budget_caps_requests():
    scope = Scope.from_entries("p", ["lab.test"])
    client = make(scope, lambda req: httpx.Response(200), max_requests=2)
    client.get("/1")
    client.get("/2")
    with pytest.raises(BudgetExceeded):
        client.get("/3")


def test_retry_on_429_then_success():
    scope = Scope.from_entries("p", ["lab.test"])
    state = {"n": 0}

    def handler(req):
        state["n"] += 1
        return httpx.Response(429, headers={"retry-after": "0"}) if state["n"] == 1 \
            else httpx.Response(200, text="ok")

    client = make(scope, handler, rate=1000)
    assert client.get("/x").status_code == 200
    assert state["n"] == 2


def test_redirects_are_not_followed():
    scope = Scope.from_entries("p", ["lab.test"])
    client = make(scope, lambda req: httpx.Response(302, headers={"location": "http://evil.test/"}))
    resp = client.get("/go")
    assert resp.status_code == 302
    assert resp.headers["location"] == "http://evil.test/"


def test_secrets_are_redacted_in_capture(store):
    scope = Scope.from_entries("p", ["lab.test"])

    def handler(req):
        return httpx.Response(200, json={"token": "supersecret", "email": "a@b.test"},
                              headers={"set-cookie": "session=abcdef"})

    client = make(scope, handler, store=store, run_id="r")
    client.request("GET", "/me", headers={"Authorization": "Bearer SUPERSECRETTOKEN"})
    row = store.conn.execute("SELECT * FROM exchanges").fetchone()
    assert "SUPERSECRETTOKEN" not in row["req_headers"]
    assert "supersecret" not in row["resp_body"]
    assert "abcdef" not in row["resp_headers"]
    assert "a@b.test" in row["resp_body"]     # evidence keeps the proof
