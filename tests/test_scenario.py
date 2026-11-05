import json

import httpx
import pytest

from bb import scenario
from bb.scope import Scope
from bb.store import Store

ACCOUNTS = {
    "base_url": "http://lab.test",
    "login": {"path": "/login", "token_field": "token",
              "body_keys": {"email": "email", "password": "password"}},
    "accounts": [
        {"label": "A", "email": "alice@lab.test", "password": "pw"},
        {"label": "B", "email": "bob@lab.test", "password": "pw"},
    ],
}


def make_handler(state):
    def handler(req):
        path = req.url.path
        auth = req.headers.get("authorization", "")
        if path == "/login":
            body = json.loads(req.content or b"{}")
            email = body.get("email", "")
            return httpx.Response(200, json={"token": "tokA" if email.startswith("alice")
                                             else "tokB"})
        if path == "/items/7" and req.method == "GET":
            if auth == "Bearer tokB" and state.get("deny_b"):
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json={"id": 7, "owner": "alice@lab.test",
                                             "name": state.get("name", "orig")})
        if path == "/items" and req.method == "POST":
            if auth != "Bearer tokA":
                return httpx.Response(403)
            state["created"] = True
            return httpx.Response(201, json={"id": 7})
        if path == "/items/7" and req.method == "PATCH":
            if auth != "Bearer tokB":
                return httpx.Response(403)
            state["name"] = json.loads(req.content or b"{}").get("name", "")
            return httpx.Response(200, json={})
        if path == "/items/7" and req.method == "DELETE":
            state["deleted"] = True
            return httpx.Response(204)
        return httpx.Response(404, json={"error": "not found"})
    return handler


def read_scenario(claim=True):
    data = {
        "name": "lab-read-idor",
        "base_url": "http://lab.test",
        "steps": [
            {"id": "owner_read", "role": "A", "method": "GET", "path": "/items/7"},
            {"id": "attack_read", "role": "B", "method": "GET", "path": "/items/7"},
        ],
    }
    if claim:
        data["claim"] = {"type": "idor_read", "step": "attack_read",
                         "owner_step": "owner_read", "owner": "A", "attacker": "B"}
    return data


def write_scenario(cleanup=True):
    data = {
        "name": "lab-write-idor",
        "base_url": "http://lab.test",
        "steps": [
            {"id": "create", "role": "A", "method": "POST", "path": "/items",
             "json": {"name": "bb-test"}, "expect": {"status": [201]},
             "extract": {"item_id": "$.id"}},
            {"id": "attack_write", "role": "B", "method": "PATCH",
             "path": "/items/${item_id}", "json": {"name": "${marker}"}},
            {"id": "owner_verify", "role": "A", "method": "GET",
             "path": "/items/${item_id}"},
        ],
        "claim": {"type": "idor_write", "mutate": "attack_write",
                  "verify": "owner_verify", "owner": "A", "attacker": "B",
                  "marker": "${marker}"},
    }
    if cleanup:
        data["cleanup"] = [{"role": "A", "method": "DELETE", "path": "/items/${item_id}"}]
    return data


@pytest.fixture()
def patch_reports(tmp_path, monkeypatch):
    monkeypatch.setattr("bb.config.KB_PATH", tmp_path / "missing-kb.json")
    monkeypatch.setattr("bb.report.REPORTS", tmp_path / "reports")
    return tmp_path


def run(data, tmp_path, *, allow_write=False, dry_run=False, transport=None,
        log=lambda *_: None):
    store = Store(tmp_path / "db.sqlite")
    scope = Scope.from_entries("p", ["lab.test"])
    return store, scenario.run_scenario(
        data, scope=scope, accounts=ACCOUNTS, program="p", store=store,
        allow_write=allow_write, dry_run=dry_run, transport=transport, log=log)


def test_read_idor_is_confirmed_and_queued(tmp_path, patch_reports):
    store, result = run(read_scenario(), tmp_path,
                        transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "confirmed"
    finding = result["finding"]
    assert finding is not None
    assert finding.bug_class == "IDOR" and finding.confidence == "high"
    assert len(finding.evidence) == 2
    stored = store.get_finding(finding.id)
    assert stored is not None
    assert stored.meta["report_path"]
    assert len(store.queue("pending")) == 1
    assert (tmp_path / "reports" / finding.id / "report.md").exists()


def test_idor_read_without_owner_step_warns(tmp_path, patch_reports):
    logs = []
    data = read_scenario()
    del data["claim"]["owner_step"]
    store, result = run(data, tmp_path, transport=httpx.MockTransport(make_handler({})),
                        log=logs.append)
    assert result["verdict"] == "confirmed"
    assert any("owner_step" in line for line in logs)
    # the claim still holds, but the report has no owner-side exchange
    assert len(result["finding"].evidence) == 1


def test_enforced_boundary_is_not_a_finding(tmp_path, patch_reports):
    store, result = run(read_scenario(), tmp_path,
                        transport=httpx.MockTransport(make_handler({"deny_b": True})))
    assert result["verdict"] == "enforced"
    assert result["finding"] is None
    assert store.findings(status=None) == []


def test_stateful_write_idor_needs_allow_write(tmp_path, patch_reports):
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(500)

    with pytest.raises(scenario.ScenarioError, match="allow-write"):
        run(write_scenario(), tmp_path,
            transport=httpx.MockTransport(handler))
    assert calls["n"] == 0


def test_stateful_write_idor_confirmed_and_cleaned_up(tmp_path, patch_reports):
    state = {}
    store, result = run(write_scenario(), tmp_path, allow_write=True,
                        transport=httpx.MockTransport(make_handler(state)))
    assert result["verdict"] == "confirmed"
    assert state.get("created") and state.get("deleted")
    finding = result["finding"]
    assert finding is not None and finding.bug_class == "IDOR"
    assert any("owner verification" in e.summary for e in finding.evidence)


def test_marker_write_denied_is_enforced(tmp_path, patch_reports):
    state = {"deny_b": True}

    def handler(req):
        if req.url.path == "/login":
            return httpx.Response(200, json={"token": "tokA"})
        return httpx.Response(403)

    # create succeeds only for A; patch for B is denied
    base = make_handler(state)

    def wrapped(req):
        if req.url.path == "/items/7" and req.method == "PATCH":
            return httpx.Response(403)
        return base(req)

    store, result = run(write_scenario(), tmp_path, allow_write=True,
                        transport=httpx.MockTransport(wrapped))
    assert result["verdict"] == "enforced"
    assert result["finding"] is None


def test_dry_run_plans_without_sending(tmp_path, patch_reports):
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(200)

    store, result = run(write_scenario(), tmp_path, dry_run=True,
                        transport=httpx.MockTransport(handler))
    assert result["verdict"] == "dry-run"
    assert calls["n"] == 0
    assert len(result["planned"]) == 3
    assert result["finding"] is None


def test_unresolved_placeholder_skips_step(tmp_path, patch_reports):
    data = read_scenario()
    data["steps"][1]["path"] = "/items/${missing}"
    store, result = run(data, tmp_path, transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "inconclusive"
    skipped = [r for r in result["steps"].values() if r.skipped]
    assert len(skipped) == 1 and "unresolved" in skipped[0].error
    assert store.findings(status=None) == []


def test_scenario_without_claim_is_observational(tmp_path, patch_reports):
    store, result = run(read_scenario(claim=False), tmp_path,
                        transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "observed"
    assert result["finding"] is None
    assert store.findings(status=None) == []


def test_scenario_validation():
    with pytest.raises(scenario.ScenarioError):
        scenario.validate_scenario({"steps": []})
    with pytest.raises(scenario.ScenarioError):
        scenario.validate_scenario({"steps": [{"role": "C", "path": "/x"}]})
    with pytest.raises(scenario.ScenarioError):
        scenario.validate_scenario({"steps": [{"role": "A", "path": "/x", "method": "TRACE"}]})
    with pytest.raises(scenario.ScenarioError):
        scenario.validate_scenario({
            "steps": [{"id": "a", "role": "A", "path": "/x"}],
            "claim": {"type": "idor_read", "step": "nope"}})
