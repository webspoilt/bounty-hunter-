"""DNS rebinding guard + global kill switch tests.

Real DNS is never touched: resolution is monkeypatched. HTTP tests force
``resolve_dns=True`` because a MockTransport would otherwise skip the guard.
"""
import httpx
import pytest

import bb.scope as scope_mod
from bb import killswitch
from bb.http import ScopedClient
from bb.scope import Scope, ScopeViolation


@pytest.fixture(autouse=True)
def _isolated_kill_file(tmp_path, monkeypatch):
    monkeypatch.setattr(killswitch, "KILL_FILE", tmp_path / "killswitch")
    yield


def resolve_to(*ips):
    return lambda host: tuple(ips)


def test_wildcard_target_resolving_to_private_ip_is_refused(scope, monkeypatch):
    sc = Scope.from_entries("p", ["*.example.com"])
    monkeypatch.setattr(scope_mod, "resolve_host", resolve_to("127.0.0.1"))
    d = sc.verify_resolution("https://attacker.example.com/x")
    assert not d.allowed
    assert "rebinding" in d.reason


def test_wildcard_target_resolving_globally_is_allowed(scope, monkeypatch):
    sc = Scope.from_entries("p", ["*.example.com"])
    monkeypatch.setattr(scope_mod, "resolve_host", resolve_to("93.184.216.34"))
    d = sc.verify_resolution("https://app.example.com/x")
    assert d.allowed
    assert "93.184.216.34" in d.reason


def test_exact_rule_may_resolve_internally(scope, monkeypatch):
    sc = Scope.from_entries("p", ["lab.example.test"])
    monkeypatch.setattr(scope_mod, "resolve_host", resolve_to("192.168.1.10"))
    assert sc.verify_resolution("https://lab.example.test/api").allowed


def test_wildcard_with_explicit_ip_rule_covers_private_ip(scope, monkeypatch):
    sc = Scope.from_entries("p", ["*.example.com", "10.0.0.0/24"])
    monkeypatch.setattr(scope_mod, "resolve_host", resolve_to("10.0.0.5"))
    assert sc.verify_resolution("https://app.example.com/x").allowed


def test_unresolvable_host_is_refused(scope, monkeypatch):
    sc = Scope.from_entries("p", ["app.example.com"])

    def boom(host):
        raise OSError("no such host")

    monkeypatch.setattr(scope_mod, "resolve_host", boom)
    d = sc.verify_resolution("https://app.example.com/")
    assert not d.allowed
    assert "resolution failed" in d.reason


def test_literal_ip_target_needs_no_resolution(scope, monkeypatch):
    calls = []

    def spy(host):
        calls.append(host)
        return ("127.0.0.1",)

    monkeypatch.setattr(scope_mod, "resolve_host", spy)
    assert scope.verify_resolution("http://203.0.113.7/x").allowed
    assert calls == []


def test_dns_guard_runs_inside_scoped_client(store, monkeypatch):
    monkeypatch.setattr(scope_mod, "resolve_host", resolve_to("127.0.0.1"))
    scope = Scope.from_entries("p", ["*.example.com"])
    client = ScopedClient(scope, base_url="https://attacker.example.com/",
                          transport=httpx.MockTransport(lambda req: httpx.Response(200)),
                          store=store, resolve_dns=True)
    with pytest.raises(ScopeViolation) as exc:
        client.get("/x")
    assert "DNS guard" in str(exc.value)
    rows = store.conn.execute("SELECT verdict, reason FROM scope_audit").fetchall()
    assert any(r["verdict"] == "DENY" and "dns guard" in r["reason"] for r in rows)


def test_dns_guard_reason_recorded_on_allow(store, monkeypatch):
    monkeypatch.setattr(scope_mod, "resolve_host", resolve_to("93.184.216.34"))
    scope = Scope.from_entries("p", ["app.example.com"])
    client = ScopedClient(scope, base_url="https://app.example.com/",
                          transport=httpx.MockTransport(lambda req: httpx.Response(200)),
                          store=store, resolve_dns=True)
    client.get("/things")
    rows = store.conn.execute("SELECT verdict, reason FROM scope_audit").fetchall()
    assert any(r["verdict"] == "ALLOW" and "dns:" in r["reason"] for r in rows)


def test_transport_skips_dns_by_default(store):
    scope = Scope.from_entries("p", ["lab.test"])
    client = ScopedClient(scope, base_url="http://lab.test/",
                          transport=httpx.MockTransport(lambda req: httpx.Response(200)),
                          store=store)
    assert client.get("/a").status_code == 200      # no DNS was required or performed


# ---------- kill switch ----------

def _client(store):
    scope = Scope.from_entries("p", ["lab.test"])
    return ScopedClient(scope, base_url="http://lab.test/",
                        transport=httpx.MockTransport(lambda req: httpx.Response(200)),
                        store=store, run_id="r1")


def test_kill_switch_stops_requests(store):
    client = _client(store)
    assert client.get("/ok").status_code == 200
    killswitch.activate("lunch break")
    with pytest.raises(killswitch.AbortRequested) as exc:
        client.get("/blocked")
    assert "lunch break" in str(exc.value)
    assert killswitch.active()
    rows = store.conn.execute(
        "SELECT verdict, reason FROM scope_audit WHERE run_id='r1'").fetchall()
    assert any(r["verdict"] == "STOP" for r in rows)


def test_kill_switch_blocks_dry_run_planning_too(store):
    client = _client(store)
    client.dry_run = True
    killswitch.activate()
    with pytest.raises(killswitch.AbortRequested):
        client.get("/planned")
    assert client.planned == []


def test_resume_reenables_requests(store):
    client = _client(store)
    killswitch.activate()
    assert not killswitch.clear() is None
    killswitch.clear()
    assert not killswitch.active()
    assert client.get("/after").status_code == 200


def test_activate_is_idempotent_and_keeps_reason(tmp_path):
    killswitch.activate("first")
    killswitch.activate()                       # no new reason -> keeps the old one
    assert killswitch.reason() == "first"
    killswitch.activate("escalated")
    assert "first" in killswitch.reason() and "escalated" in killswitch.reason()


def test_stop_and_resume_cli(store, capsys):
    from bb.cli import build_parser
    p = build_parser()
    assert p.parse_args(["stop", "maintenance"]).func(p.parse_args(["stop", "maintenance"])) == 0
    assert killswitch.active() and "maintenance" in killswitch.reason()
    parsed = p.parse_args(["resume"])
    assert parsed.func(parsed) == 0
    assert not killswitch.active()
