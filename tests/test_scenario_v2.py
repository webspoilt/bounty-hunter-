import json
from pathlib import Path

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
        {"label": "admin", "email": "admin@lab.test", "password": "pw",
         "headers": {"X-Acct": "acct"}},
        {"label": "victim", "email": "victim@lab.test", "password": "pw"},
        {"label": "attacker", "email": "attacker@lab.test", "password": "pw"},
    ],
}


def make_handler(state):
    def handler(req):
        path = req.url.path
        if path == "/login":
            body = json.loads(req.content or b"{}")
            email = body.get("email", "")
            state.setdefault("logins", []).append(email)
            return httpx.Response(200, json={"token": f"tok:{email}"})
        auth = req.headers.get("authorization", "")
        email = auth.removeprefix("Bearer ").removeprefix("tok:")
        if path == "/whoami":
            return httpx.Response(200, json={"email": email})
        if path == "/denied":
            if email.startswith("attacker"):
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json={"ok": True})
        if path == "/limited":
            return httpx.Response(429, json={"error": "slow down"})
        if path == "/state":
            if req.method == "PATCH":
                if state.get("deny_patch"):
                    return httpx.Response(403, json={"error": "forbidden"})
                state["role"] = "admin"
                return httpx.Response(200, json={"role": "admin"})
            if state.get("deny_verify"):
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json={"role": state.get("role", "member")})
        if path == "/items":
            return httpx.Response(200, json={
                "items": [{"id": 7, "owner": "victim@lab.test"}]})
        if path == "/echo":
            state["last_headers"] = dict(req.headers)
            return httpx.Response(200, json={})
        if path.startswith("/next/"):
            state["next_hits"] = state.get("next_hits", 0) + 1
            return httpx.Response(200, json={})
        if path == "/cleanup_fail":
            return httpx.Response(500, json={"error": "boom"})
        if path == "/cleanup":
            state["cleaned"] = True
            return httpx.Response(200, json={})
        return httpx.Response(404, json={})
    return handler


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


def multi_role(read_only=False):
    return {
        "schema": 2,
        "name": "roles",
        "base_url": "http://lab.test",
        "roles": {"admin": {"account": 0}, "victim": {"account": 1},
                  "attacker": {"account": 2}},
        "steps": [
            {"role": "admin", "method": "GET", "path": "/whoami"},
            {"role": "victim", "method": "GET", "path": "/whoami"},
            {"role": "attacker", "method": "GET", "path": "/whoami"},
        ],
    }


def test_roles_log_in_only_referenced_accounts(tmp_path, patch_reports):
    state = {}
    store, result = run(multi_role(), tmp_path, transport=httpx.MockTransport(make_handler(state)))
    assert result["verdict"] == "observed"
    assert len(state["logins"]) == 3
    assert set(state["logins"]) == {"admin@lab.test", "victim@lab.test", "attacker@lab.test"}
    assert result["roles"] == ["admin", "attacker", "victim"]


def test_unreferenced_roles_are_not_logged_in(tmp_path, patch_reports):
    data = multi_role()
    data["steps"] = [data["steps"][0], data["steps"][2]]      # admin + attacker only
    state = {}
    run(data, tmp_path, transport=httpx.MockTransport(make_handler(state)))
    assert set(state["logins"]) == {"admin@lab.test", "attacker@lab.test"}


def test_dry_run_lists_every_referenced_role(tmp_path, patch_reports):
    logs = []
    state = {}
    store, result = run(multi_role(), tmp_path, dry_run=True,
                        transport=httpx.MockTransport(make_handler(state)), log=logs.append)
    assert result["verdict"] == "dry-run"
    assert len(result["planned"]) == 3
    assert result["roles"] == ["admin", "attacker", "victim"]
    assert "logins" not in state
    joined = "\n".join(logs)
    for label in ("admin", "victim", "attacker"):
        assert label in joined


def test_ab_remain_valid_in_schema_two(tmp_path, patch_reports):
    data = {"schema": 2, "base_url": "http://lab.test",
            "steps": [{"role": "A", "method": "GET", "path": "/whoami"},
                      {"role": "B", "method": "GET", "path": "/whoami"}]}
    state = {}
    store, result = run(data, tmp_path, transport=httpx.MockTransport(make_handler(state)))
    assert result["verdict"] == "observed"
    assert result["roles"] == ["A", "B"]


def test_denied_coverage_mid_chain_skips_downstream(tmp_path, patch_reports):
    data = {
        "schema": 2, "base_url": "http://lab.test",
        "roles": {"victim": {"account": 1}, "attacker": {"account": 2}},
        "steps": [
            {"id": "denied", "role": "attacker", "method": "GET", "path": "/denied",
             "denied_is_coverage": True, "expect": {"status": [200]},
             "extract": {"secret": "$.id"}},
            {"id": "downstream", "role": "attacker", "method": "GET",
             "path": "/next/${secret}"},
        ],
        "claim": {"type": "idor_read", "step": "downstream",
                  "owner": "victim", "attacker": "attacker"},
    }
    state = {}
    store, result = run(data, tmp_path, transport=httpx.MockTransport(make_handler(state)))
    assert result["verdict"] == "inconclusive"
    assert result["steps"]["denied"].coverage is True
    assert result["steps"]["downstream"].skipped is True
    assert state.get("next_hits", 0) == 0
    assert store.findings(status=None) == []


def test_denied_claim_step_is_enforced(tmp_path, patch_reports):
    data = {
        "schema": 2, "base_url": "http://lab.test",
        "roles": {"victim": {"account": 1}, "attacker": {"account": 2}},
        "steps": [{"id": "denied", "role": "attacker", "method": "GET", "path": "/denied",
                   "denied_is_coverage": True, "expect": {"status": [200]}}],
        "claim": {"type": "idor_read", "step": "denied",
                  "owner": "victim", "attacker": "attacker"},
    }
    store, result = run(data, tmp_path,
                        transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "enforced"
    assert result["steps"]["denied"].coverage is True
    assert store.findings(status=None) == []


def test_json_assertions_paths_and_deep_equality(tmp_path, patch_reports):
    data = {
        "schema": 2, "base_url": "http://lab.test",
        "steps": [
            {"role": "A", "method": "GET", "path": "/items",
             "expect": {"json": {
                 "$.items[0].id": 7,
                 "$.items.0.id": 7,
                 "$.items[0]": {"id": 7, "owner": "victim@lab.test"},
                 "$.items[0].owner": {"contains": "victim"},
                 "$.missing": {"exists": False},
             },
                 "body_not_contains": ["${A.email}"]}},
            {"role": "B", "method": "GET", "path": "/whoami"},
        ],
    }
    store, result = run(data, tmp_path,
                        transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "observed"


def test_json_assertion_failure_is_not_observed(tmp_path, patch_reports):
    data = {
        "schema": 2, "base_url": "http://lab.test",
        "steps": [
            {"role": "A", "method": "GET", "path": "/items",
             "expect": {"json": {"$.items[0].id": 8}}},
            {"role": "B", "method": "GET", "path": "/whoami"},
        ],
    }
    store, result = run(data, tmp_path,
                        transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "inconclusive"


def state_change_scenario(owner_verify=False):
    steps = [{"id": "promote", "role": "attacker", "method": "PATCH", "path": "/state",
              "json": {"role": "admin"}}]
    claim = {"type": "state_change", "step": "promote",
             "json": {"$.role": "admin"}, "owner": "victim", "attacker": "attacker"}
    if owner_verify:
        steps.append({"id": "verify", "role": "victim", "method": "GET", "path": "/state"})
        claim["owner_verify"] = "verify"
    return {"schema": 2, "base_url": "http://lab.test",
            "roles": {"victim": {"account": 1}, "attacker": {"account": 2}},
            "steps": steps, "claim": claim}


def test_state_change_single_role_is_labelled(tmp_path, patch_reports):
    store, result = run(state_change_scenario(), tmp_path, allow_write=True,
                        transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "confirmed"
    finding = store.get_finding(result["finding"].id)
    assert finding.meta["evidence"] == "single-role"
    assert finding.bug_class == "Broken Access Control"


def test_state_change_with_owner_verify_is_dual_role(tmp_path, patch_reports):
    store, result = run(state_change_scenario(owner_verify=True), tmp_path, allow_write=True,
                        transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "confirmed"
    finding = store.get_finding(result["finding"].id)
    assert finding.meta["evidence"] == "dual-role"
    assert len(finding.evidence) == 2
    report = Path(finding.meta["report_path"]).read_text(encoding="utf-8")
    assert "**Evidence:** dual-role" in report


def test_state_change_denied_is_enforced(tmp_path, patch_reports):
    state = {"deny_patch": True}
    store, result = run(state_change_scenario(), tmp_path, allow_write=True,
                        transport=httpx.MockTransport(make_handler(state)))
    assert result["verdict"] == "enforced"
    assert store.findings(status=None) == []


def test_state_change_failed_owner_verify_is_inconclusive(tmp_path, patch_reports):
    state = {"deny_verify": True}
    store, result = run(state_change_scenario(owner_verify=True), tmp_path, allow_write=True,
                        transport=httpx.MockTransport(make_handler(state)))
    assert result["verdict"] == "inconclusive"
    assert store.findings(status=None) == []


def test_429_is_not_denied_coverage(tmp_path, patch_reports):
    data = {
        "schema": 2, "base_url": "http://lab.test",
        "roles": {"victim": {"account": 1}, "attacker": {"account": 2}},
        "steps": [{"id": "limited", "role": "attacker", "method": "GET", "path": "/limited",
                   "denied_is_coverage": True, "expect": {"status": [200]}}],
        "claim": {"type": "idor_read", "step": "limited",
                  "owner": "victim", "attacker": "attacker"},
    }
    store, result = run(data, tmp_path,
                        transport=httpx.MockTransport(make_handler({})))
    assert result["verdict"] == "inconclusive"
    assert result["steps"]["limited"].coverage is False


def test_all_declared_role_indices_are_validated(tmp_path, patch_reports):
    data = multi_role()
    data["roles"]["unused"] = {"account": 9}
    state = {}
    with pytest.raises(scenario.ScenarioError, match="out of range"):
        run(data, tmp_path, transport=httpx.MockTransport(make_handler(state)))


def test_state_change_requires_attacker_step():
    data = state_change_scenario()
    data["steps"][0]["role"] = "victim"
    with pytest.raises(scenario.ScenarioError, match="attacker role"):
        scenario.validate_scenario(data)


def test_reserved_extract_names_are_rejected():
    base = {
        "schema": 2, "base_url": "http://lab.test",
        "roles": {"attacker": {"account": 1}, "victim": {"account": 2}},
        "steps": [
            {"id": "attacker", "role": "attacker", "method": "GET", "path": "/x",
             "extract": {"email": "$.id"}},
            {"role": "victim", "method": "GET", "path": "/x"},
        ],
    }
    with pytest.raises(scenario.ScenarioError, match="reserved"):
        scenario.validate_scenario(base)
    base["steps"][0]["extract"] = {"marker": "$.id"}
    with pytest.raises(scenario.ScenarioError, match="reserved"):
        scenario.validate_scenario(base)


def test_header_precedence_account_then_role_then_step(tmp_path, patch_reports):
    data = {
        "schema": 2, "base_url": "http://lab.test",
        "roles": {
            "admin": {"account": 0, "headers": {"X-Acct": "role-over", "X-Role": "role"}},
            "victim": {"account": 1},
        },
        "steps": [
            {"role": "admin", "method": "GET", "path": "/echo",
             "headers": {"X-Role": "step"}},
            {"role": "victim", "method": "GET", "path": "/whoami"},
        ],
    }
    state = {}
    run(data, tmp_path, transport=httpx.MockTransport(make_handler(state)))
    headers = state["last_headers"]
    assert headers["x-acct"] == "role-over"
    assert headers["x-role"] == "step"


def test_cleanup_unresolved_is_skipped_not_guessed(tmp_path, patch_reports):
    logs = []
    data = {
        "schema": 2, "base_url": "http://lab.test",
        "steps": [{"role": "A", "method": "GET", "path": "/whoami"},
                  {"role": "B", "method": "GET", "path": "/whoami"}],
        "cleanup": [{"role": "A", "method": "DELETE", "path": "/items/${missing}"}],
    }
    store, result = run(data, tmp_path, allow_write=True,
                        transport=httpx.MockTransport(make_handler({})), log=logs.append)
    assert result["cleanup_errors"] == []
    assert any("unresolved" in line for line in logs)


def test_cleanup_http_failure_honours_ignore_failure(tmp_path, patch_reports):
    data = {
        "schema": 2, "base_url": "http://lab.test",
        "steps": [{"role": "A", "method": "GET", "path": "/whoami"},
                  {"role": "B", "method": "GET", "path": "/whoami"}],
        "cleanup": [{"role": "A", "method": "DELETE", "path": "/cleanup_fail",
                     "ignore_failure": False}],
    }
    store, result = run(data, tmp_path, allow_write=True,
                        transport=httpx.MockTransport(make_handler({})))
    assert len(result["cleanup_errors"]) == 1


@pytest.mark.parametrize("field", ["roles", "expect_json", "denied", "state_change"])
def test_schema_one_rejects_schema_two_fields(field):
    if field == "roles":
        data = {"steps": [{"role": "A", "path": "/x"}], "roles": {"admin": {"account": 2}}}
    elif field == "expect_json":
        data = {"steps": [{"role": "A", "path": "/x", "expect": {"json": {"$.a": 1}}}]}
    elif field == "denied":
        data = {"steps": [{"role": "A", "path": "/x", "denied_is_coverage": True}]}
    else:
        data = {"steps": [{"id": "a", "role": "A", "path": "/x"},
                          {"role": "B", "path": "/x"}],
                "claim": {"type": "state_change", "step": "a", "json": {"$.a": 1},
                          "owner": "B", "attacker": "A"}}
    with pytest.raises(scenario.ScenarioError, match="schema"):
        scenario.validate_scenario(data)
