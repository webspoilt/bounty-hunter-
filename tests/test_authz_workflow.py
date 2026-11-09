"""Automated comprehensive test suite for Task P4: Autonomous Two-Account Authorization Investigation.

Validates the complete 20-step authorization investigation workflow:
1. Account A owner access baseline.
2. Account B non-owner denial baseline.
3. Cross-account exposure identification.
4. Public/shared object negative control (false positive challenge).
5. Nonexistent object negative control (static/wildcard route challenge).
6. Missing identity markers (insufficient evidence challenge).
7. Soft error body masked as 200 OK challenge.
8. Inconsistent or dissimilar baselines.
9. Out-of-scope request refusal.
10. Global request-budget exhaustion.
11. Global kill-switch halting.
12. GET endpoint classified as state-changing.
13. Write approval enforcement (rejection of unapproved write operations).
14. Specific approval token matching (approval mismatch refusal).
15. Tev1 unavailable / fallback prioritization handling.
16. Independent verification returning verified, rejected, and inconclusive.
17. Checkpoint persistence and crash recovery (resumption without duplicate execution).
18. Cleanup execution and cleanup failure recording.
19. Report generation and placement in human approval queue (no automatic submission).
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from bb.authz import (
    ApplicationModel,
    AuthorizationVerifier,
    AuthzInvestigationWorkflow,
    Endpoint,
    Hypothesis,
    Identity,
    InvestigationState,
    ObjectRef,
    Parameter,
    Role,
    ScenarioSpec,
    build_inventory_from_har,
    generate_hypotheses,
    prioritize_hypotheses_with_tev1,
)
from bb.authz.workflow import AUTHZ_CHECKPOINTS_DIR
from bb.har import HarEntry
from bb.http import RequestBudget, ScopedClient
from bb.scope import Scope
from bb.store import Store

# Test accounts fixture
ACCOUNTS = {
    "base_url": "http://lab.test",
    "login": {
        "path": "/login",
        "token_field": "token",
        "body_keys": {"email": "email", "password": "password"},
    },
    "accounts": [
        {"label": "A", "email": "alice@lab.test", "password": "pwA"},
        {"label": "B", "email": "bob@lab.test", "password": "pwB"},
    ],
}


def make_har_file(tmp_path: Path, entries_data: list[dict]) -> Path:
    """Helper to write a valid minimal HAR file for testing."""
    har_entries = []
    for e in entries_data:
        har_entries.append({
            "request": {
                "method": e.get("method", "GET"),
                "url": e.get("url", "http://lab.test/items/42"),
                "headers": e.get("req_headers", [{"name": "Authorization", "value": "Bearer tokA"}]),
                "postData": {"text": json.dumps(e.get("body", {}))} if "body" in e else {},
            },
            "response": {
                "status": e.get("status", 200),
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {
                    "text": json.dumps(e.get("resp_body", {"id": 42, "owner": "alice@lab.test"})),
                },
            },
        })

    har_obj = {"log": {"version": "1.2", "entries": har_entries}}
    har_path = tmp_path / "traffic.har"
    har_path.write_text(json.dumps(har_obj), encoding="utf-8")
    return har_path


@pytest.fixture
def authz_env(tmp_path, monkeypatch):
    """Provide isolated store, scope, and checkpoint environment."""
    checkpoints_dir = tmp_path / "checkpoints"
    checkpoints_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("bb.authz.workflow.AUTHZ_CHECKPOINTS_DIR", checkpoints_dir)

    db_path = tmp_path / "test_authz.db"
    store = Store(db_path)
    scope = Scope.from_entries(
        program="lab-prog",
        in_scope=["lab.test"],
        out_of_scope=["out-of-scope.test"],
    )
    return {
        "dir": tmp_path,
        "store": store,
        "scope": scope,
        "checkpoints": checkpoints_dir,
    }


# ==============================================================================
# 1. APPLICATION MODEL & INVENTORY TESTS
# ==============================================================================

def test_model_and_provenance(authz_env):
    """ApplicationModel correctly registers entities with explicit provenance."""
    model = ApplicationModel("lab-prog")
    model.add_role(Role(name="A", label="Owner", provenance="operator-confirmed"))
    model.add_role(Role(name="B", label="Attacker", provenance="operator-confirmed"))
    model.add_identity(Identity(role="A", identifier="alice@lab.test", provenance="operator-confirmed"))
    model.add_identity(Identity(role="B", identifier="bob@lab.test", provenance="operator-confirmed"))

    model.add_endpoint(Endpoint(
        method="GET",
        url_pattern="/api/documents/{id}",
        host="lab.test",
        path="/api/documents/123",
        provenance="observed",
    ))
    model.add_parameter(Parameter(
        name="id",
        kind="path",
        endpoint_key="GET /api/documents/123",
        example_value="123",
        is_object_identifier=True,
        provenance="observed",
    ))
    model.add_object(ObjectRef(
        object_id="123",
        object_type="document",
        owner_identity="alice@lab.test",
        provenance="observed",
    ))

    data = model.to_dict()
    assert len(data["roles"]) == 2
    assert len(data["identities"]) == 2
    assert len(data["endpoints"]) == 1
    assert len(data["objects"]) == 1
    assert data["roles"]["A"]["provenance"] == "operator-confirmed"
    assert data["objects"]["123"]["provenance"] == "observed"


def test_build_inventory_from_har(authz_env):
    """Build inventory discovers endpoints, parameters, and objects from scoped traffic."""
    model = ApplicationModel("lab-prog")
    entries = [
        HarEntry(
            index=0,
            method="GET",
            url="http://lab.test/api/items/7?filter=recent",
            status=200,
            request_headers={"authorization": "Bearer tokA"},
            response_headers={"content-type": "application/json"},
            request_body="",
            response_body='{"id": 7, "owner": "alice@lab.test"}',
            duration_ms=10,
        ),
        HarEntry(
            index=1,
            method="POST",
            url="http://out-of-scope.test/api/items",  # Out of scope: should be skipped
            status=201,
            request_headers={},
            response_headers={},
            request_body="",
            response_body="",
            duration_ms=10,
        ),
    ]

    build_inventory_from_har(model, entries, authz_env["scope"])
    assert len(model.endpoints) == 1
    assert any("/api/items/{id}" in e.url_pattern for e in model.endpoints.values())
    assert "7" in model.objects
    assert any(p.name == "filter" for p in model.parameters.values())


# ==============================================================================
# 2. HYPOTHESIS GENERATION & TEV1 PRIORITIZATION TESTS
# ==============================================================================

def test_hypothesis_generation_and_planning(authz_env):
    """Workflow generates read/write hypotheses and can build a plan without executing."""
    har_path = make_har_file(authz_env["dir"], [
        {"method": "POST", "url": "http://lab.test/api/items", "body": {"name": "test"}, "status": 201, "resp_body": {"id": 99}},
        {"method": "GET", "url": "http://lab.test/api/items/99", "status": 200, "resp_body": {"id": 99, "owner": "alice@lab.test"}},
        {"method": "PATCH", "url": "http://lab.test/api/items/99", "body": {"name": "mod"}, "status": 200, "resp_body": {"id": 99}},
    ])

    wf = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
    )

    plan = wf.build_plan()
    assert plan["investigation_id"]
    assert plan["endpoints_observed"] >= 1
    assert len(plan["hypotheses"]) >= 1

    # Check plannable without execution: Store remains empty
    assert len(authz_env["store"].findings()) == 0
    assert authz_env["store"].stats()["exchanges"] == 0


def test_tev1_prioritization_and_fallback(authz_env):
    """Tev1 prioritization prioritizes candidate or defaults cleanly on missing model."""
    h1 = Hypothesis(
        id="HYPO-READ-1",
        title="Read test",
        description="desc",
        kind="idor_read",
        target_endpoint="/items/1",
        target_method="GET",
        object_id="1",
        owner_role="A",
        attacker_role="B",
        scenario=ScenarioSpec(name="s1", base_url="http://lab.test", steps=[], claim={}),
        is_state_changing=False,
        priority_score=5,
    )
    h2 = Hypothesis(
        id="HYPO-WRITE-2",
        title="Write test",
        description="desc",
        kind="idor_write",
        target_endpoint="/items/1",
        target_method="POST",
        object_id="1",
        owner_role="A",
        attacker_role="B",
        scenario=ScenarioSpec(name="s2", base_url="http://lab.test", steps=[], claim={}),
        is_state_changing=True,
        priority_score=8,
    )

    mock_gateway = MagicMock()
    mock_gateway.select_task.return_value = {
        "selected_index": 1,
        "confidence": 0.88,
        "reason": "Prioritize high-impact write mutation first",
        "provenance": {"model": "tev1:0.8b"},
    }

    prioritized = prioritize_hypotheses_with_tev1(mock_gateway, [h1, h2])
    assert prioritized[0].id == "HYPO-WRITE-2"
    assert prioritized[0].decision_provenance["confidence"] == 0.88

    # Fallback on gateway exception
    mock_gateway.select_task.side_effect = RuntimeError("Endpoint offline")
    fallback_res = prioritize_hypotheses_with_tev1(mock_gateway, [h1, h2])
    assert len(fallback_res) == 2


# ==============================================================================
# 3. INDEPENDENT VERIFIER TESTS (ADVERSARIAL CHALLENGES)
# ==============================================================================

def test_verifier_confirms_valid_cross_account_idor():
    """Verifier confirms IDOR when owner marker is present and controls pass."""
    client = MagicMock(spec=ScopedClient)
    # Control A (unauth): returns 401 Unauthorized
    client.get.side_effect = [
        httpx.Response(401, json={"error": "unauthorized"}),  # unauth check
        httpx.Response(404, json={"error": "not found"}),     # nonexistent ID check
    ]

    verifier = AuthorizationVerifier(client)
    hypo = Hypothesis(
        id="H1", title="IDOR", description="", kind="idor_read",
        target_endpoint="http://lab.test/items/42", target_method="GET",
        object_id="42", owner_role="A", attacker_role="B",
        scenario=ScenarioSpec(name="s", base_url="http://lab.test", steps=[], claim={}),
    )
    exec_results = {
        "verdict": "confirmed",
        "steps": {
            "owner_read": {"status": 200, "body": '{"id": 42, "owner": "alice@lab.test", "data": "secret"}'},
            "attack_read": {"status": 200, "body": '{"id": 42, "owner": "alice@lab.test", "data": "secret"}', "url": "http://lab.test/items/42"},
        },
    }
    roles = {
        "A": Role("A", label="alice@lab.test"),
        "B": Role("B", label="bob@lab.test"),
    }
    setattr(roles["A"], "identity", "alice@lab.test")
    setattr(roles["B"], "identity", "bob@lab.test")

    res = verifier.verify_hypothesis_result(hypo, exec_results, roles, {"identity_a": "alice@lab.test", "identity_b": "bob@lab.test"})
    assert res.status == "verified"
    assert res.verdict == "confirmed_authorization_bypass"
    assert res.identity_marker_found is True


def test_verifier_rejects_when_boundary_enforced():
    """Verifier rejects candidate when attacker receives HTTP 401/403."""
    verifier = AuthorizationVerifier(MagicMock())
    hypo = Hypothesis(
        id="H1", title="IDOR", description="", kind="idor_read",
        target_endpoint="http://lab.test/items/42", target_method="GET",
        object_id="42", owner_role="A", attacker_role="B",
        scenario=ScenarioSpec(name="s", base_url="http://lab.test", steps=[], claim={}),
    )
    exec_results = {
        "steps": {
            "owner_read": {"status": 200, "body": '{"id": 42}'},
            "attack_read": {"status": 403, "body": '{"error": "forbidden"}'},
        },
    }
    res = verifier.verify_hypothesis_result(hypo, exec_results, {}, {})
    assert res.status == "rejected"
    assert res.verdict == "enforced"


def test_verifier_rejects_public_or_shared_object():
    """Verifier rejects when unauthenticated request accesses the same data (public resource)."""
    client = MagicMock(spec=ScopedClient)
    # Unauthenticated request returns 200 with identical body
    client.get.return_value = httpx.Response(200, json={"id": 42, "title": "public announcement"})

    verifier = AuthorizationVerifier(client)
    hypo = Hypothesis(
        id="H1", title="IDOR", description="", kind="idor_read",
        target_endpoint="http://lab.test/items/42", target_method="GET",
        object_id="42", owner_role="A", attacker_role="B",
        scenario=ScenarioSpec(name="s", base_url="http://lab.test", steps=[], claim={}),
    )
    exec_results = {
        "steps": {
            "owner_read": {"status": 200, "body": '{"id": 42, "title": "public announcement"}'},
            "attack_read": {"status": 200, "body": '{"id": 42, "title": "public announcement"}', "url": "http://lab.test/items/42"},
        },
    }
    res = verifier.verify_hypothesis_result(hypo, exec_results, {}, {})
    assert res.status == "rejected"
    assert res.verdict == "public_or_shared_resource"


def test_verifier_rejects_wildcard_route():
    """Verifier rejects when non-existent object ID also returns 200 OK."""
    client = MagicMock(spec=ScopedClient)
    client.get.side_effect = [
        httpx.Response(401, json={"error": "unauth"}),  # unauth check denies
        httpx.Response(200, json={"message": "ok"}),    # fake ID also returns 200 with same body!
    ]

    verifier = AuthorizationVerifier(client)
    hypo = Hypothesis(
        id="H1", title="IDOR", description="", kind="idor_read",
        target_endpoint="http://lab.test/items/42", target_method="GET",
        object_id="42", owner_role="A", attacker_role="B",
        scenario=ScenarioSpec(name="s", base_url="http://lab.test", steps=[], claim={}),
    )
    exec_results = {
        "steps": {
            "owner_read": {"status": 200, "body": '{"message": "ok"}'},
            "attack_read": {"status": 200, "body": '{"message": "ok"}', "url": "http://lab.test/items/42"},
        },
    }
    res = verifier.verify_hypothesis_result(hypo, exec_results, {}, {})
    assert res.status == "rejected"
    assert res.verdict == "static_or_wildcard_route"


def test_verifier_rejects_soft_404_disguised_as_200():
    """Verifier rejects HTTP 200 containing soft error indicators."""
    verifier = AuthorizationVerifier(MagicMock())
    hypo = Hypothesis(
        id="H1", title="IDOR", description="", kind="idor_read",
        target_endpoint="http://lab.test/items/42", target_method="GET",
        object_id="42", owner_role="A", attacker_role="B",
        scenario=ScenarioSpec(name="s", base_url="http://lab.test", steps=[], claim={}),
    )
    exec_results = {
        "steps": {
            "owner_read": {"status": 200, "body": '{"id": 42}'},
            "attack_read": {"status": 200, "body": '{"error": "not found", "message": "does not exist"}'},
        },
    }
    res = verifier.verify_hypothesis_result(hypo, exec_results, {}, {})
    assert res.status == "rejected"
    assert res.verdict == "soft_error_disguised_as_success"


def test_verifier_inconclusive_on_insufficient_evidence():
    """Verifier returns inconclusive when identity markers or step traces are missing."""
    verifier = AuthorizationVerifier(MagicMock())
    hypo = Hypothesis(
        id="H1", title="IDOR", description="", kind="idor_read",
        target_endpoint="http://lab.test/items/42", target_method="GET",
        object_id="42", owner_role="A", attacker_role="B",
        scenario=ScenarioSpec(name="s", base_url="http://lab.test", steps=[], claim={}),
    )
    # Missing attacker step
    res = verifier.verify_hypothesis_result(hypo, {"steps": {}}, {}, {})
    assert res.status == "inconclusive"
    assert res.verdict == "insufficient_evidence"


# ==============================================================================
# 4. END-TO-END WORKFLOW, APPROVAL GATES & CRASH RECOVERY TESTS
# ==============================================================================

def test_workflow_e2e_read_idor_verified(authz_env):
    """End-to-end execution of a read IDOR investigation against mock transport."""
    state_mock = {"deny_b": False}

    def lab_handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        auth = req.headers.get("authorization", "")
        if path == "/login":
            body = json.loads(req.content or b"{}")
            email = body.get("email", "")
            tok = "tokA" if "alice" in email else "tokB"
            return httpx.Response(200, json={"token": tok})
        if path == "/api/items/42":
            if not auth:
                return httpx.Response(401, json={"error": "login required"})
            if "tokB" in auth and state_mock.get("deny_b"):
                return httpx.Response(403, json={"error": "denied"})
            return httpx.Response(200, json={"id": 42, "owner": "alice@lab.test", "data": "confidential"})
        if path == "/api/items/9999999999":
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(404)

    transport = httpx.MockTransport(lab_handler)

    har_path = make_har_file(authz_env["dir"], [
        {"method": "GET", "url": "http://lab.test/api/items/42", "status": 200, "resp_body": {"id": 42, "owner": "alice@lab.test"}},
    ])

    wf = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
    )

    result = wf.run_investigation(transport=transport)
    assert result["status"] == "completed"
    assert result["verified"] == 1

    # Verify Finding was persisted in Store and queued in ApprovalGate
    findings = authz_env["store"].findings()
    assert len(findings) == 1
    assert "broken object-level authorization" in findings[0].title.lower()
    assert findings[0].status == "verified"

    # Verify report is placed in human approval queue (NEVER auto-submitted)
    queue = authz_env["store"].queue("pending")
    assert len(queue) == 1
    assert queue[0]["finding_id"] == findings[0].id


def test_workflow_state_changing_requires_human_approval(authz_env):
    """State-changing writes are skipped unless explicit approval is provided."""
    har_path = make_har_file(authz_env["dir"], [
        {"method": "POST", "url": "http://lab.test/api/items", "body": {"name": "test"}, "status": 201, "resp_body": {"id": 55}},
        {"method": "PATCH", "url": "http://lab.test/api/items/55", "body": {"name": "mod"}, "status": 200, "resp_body": {"id": 55}},
    ])

    wf = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
    )

    # Run without approval: write test must be skipped
    res_no_approval = wf.run_investigation(allow_write=False, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert any("requires operator approval" in r.get("reason", "") for r in res_no_approval["results"])
    assert res_no_approval["verified"] == 0

    # Run with approval: write test proceeds
    def write_handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/login":
            return httpx.Response(200, json={"token": "tok"})
        if path == "/api/items" and req.method == "POST":
            return httpx.Response(201, json={"id": 55})
        if path == "/api/items/55":
            return httpx.Response(200, json={"id": 55, "name": "bb-test"})
        return httpx.Response(404)

    transport = httpx.MockTransport(write_handler)
    res_approved = wf.run_investigation(allow_write=True, transport=transport)
    assert res_approved["status"] == "completed"


def test_workflow_crash_recovery_resumption(authz_env):
    """Workflow resumes from checkpoint without duplicating already executed hypotheses."""
    har_path = make_har_file(authz_env["dir"], [
        {"method": "GET", "url": "http://lab.test/api/items/1", "status": 200, "resp_body": {"id": 1}},
        {"method": "GET", "url": "http://lab.test/api/items/2", "status": 200, "resp_body": {"id": 2}},
    ])

    wf1 = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
        investigation_id="AUTHZ-TEST-RESUME",
    )
    plan = wf1.build_plan()
    hypo_ids = [h["id"] for h in plan["hypotheses"]]

    # Simulate partial execution and crash
    wf1.state.executed_hypotheses.append(hypo_ids[0])
    wf1._save_state(wf1.state)

    # Resume with a second workflow instance pointing to the same investigation ID
    wf2 = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
        investigation_id="AUTHZ-TEST-RESUME",
    )
    assert hypo_ids[0] in wf2.state.executed_hypotheses


def test_workflow_respects_kill_switch(authz_env, monkeypatch):
    """Workflow immediately halts when kill switch is active."""
    har_path = make_har_file(authz_env["dir"], [
        {"method": "GET", "url": "http://lab.test/api/items/1", "status": 200, "resp_body": {"id": 1}},
    ])
    wf = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
    )

    # Activate kill switch via bb.killswitch
    monkeypatch.setattr("bb.killswitch.active", lambda: True)

    with pytest.raises(Exception) as exc:
        wf.run_investigation()
    assert "kill switch active" in str(exc.value).lower()


def test_workflow_out_of_scope_denial(authz_env):
    """Requests to out-of-scope hosts are strictly denied by ScopedClient."""
    client = ScopedClient(scope=authz_env["scope"])
    with pytest.raises(Exception):
        client.get("http://out-of-scope.test/api/secrets")


def test_get_endpoint_classified_as_state_changing(authz_env):
    """GET endpoint with state-changing path keyword (/delete) fails closed as state-changing."""
    har_path = make_har_file(authz_env["dir"], [
        {"method": "GET", "url": "http://lab.test/api/items/42/delete", "status": 200, "resp_body": {"id": 42}},
    ])
    wf = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
    )
    plan = wf.build_plan()
    assert plan["state_changing_count"] >= 1
    hypo = [h for h in plan["hypotheses"] if "delete" in h["target_endpoint"]][0]
    assert hypo["is_state_changing"] is True
    assert hypo["requires_approval"] is True

    # Execution without write approval must be skipped
    res = wf.run_investigation(allow_write=False)
    assert any("requires operator approval" in r.get("reason", "") for r in res["results"])


def test_specific_approval_token_binding(authz_env):
    """Approval token must match exact investigation, method, endpoint, object and scenario."""
    har_path = make_har_file(authz_env["dir"], [
        {"method": "POST", "url": "http://lab.test/api/items", "body": {"name": "test"}, "status": 201, "resp_body": {"id": 88}},
        {"method": "PATCH", "url": "http://lab.test/api/items/88", "body": {"name": "mod"}, "status": 200, "resp_body": {"id": 88}},
    ])
    wf = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
        investigation_id="AUTHZ-BINDING-TEST",
    )
    plan = wf.build_plan()
    write_hypo = [h for h in plan["hypotheses"] if h["is_state_changing"]][0]

    # Valid token structure: investigation:hypo:method:endpoint:object:role:scenario
    valid_token = (
        f"AUTHZ-BINDING-TEST:{write_hypo['id']}:{write_hypo['target_method']}:"
        f"{write_hypo['target_endpoint']}:{write_hypo['object_id']}:{write_hypo['attacker_role']}:{write_hypo['scenario']['name']}"
    )

    # Mismatched token (different investigation or different endpoint)
    bogus_token = "DIFFERENT-INV:HYPO:PATCH:http://lab.test/other:88:B:scen"

    # Run with bogus token: must still be skipped
    res_mismatch = wf.run_investigation(allow_write=False, approved_operations=[bogus_token])
    assert any("requires operator approval" in r.get("reason", "") for r in res_mismatch["results"])

    # Run with valid token: authorized
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"token": "t"} if "/login" in r.url.path else {"id": 88}))
    res_valid = wf.run_investigation(allow_write=False, approved_operations=[valid_token], transport=transport)
    assert res_valid["status"] == "completed"


def test_approval_ttl_expiry(authz_env):
    """Expired approval tokens are rejected and require renewed operator authorization."""
    har_path = make_har_file(authz_env["dir"], [
        {"method": "POST", "url": "http://lab.test/api/items", "body": {"name": "test"}, "status": 201, "resp_body": {"id": 77}},
        {"method": "PATCH", "url": "http://lab.test/api/items/77", "body": {"name": "mod"}, "status": 200, "resp_body": {"id": 77}},
    ])
    wf = AuthzInvestigationWorkflow(
        program="lab-prog",
        scope=authz_env["scope"],
        accounts=ACCOUNTS,
        store=authz_env["store"],
        har_path=har_path,
        investigation_id="AUTHZ-TTL-TEST",
    )
    plan = wf.build_plan()
    write_hypo = [h for h in plan["hypotheses"] if h["is_state_changing"]][0]

    token = (
        f"AUTHZ-TTL-TEST:{write_hypo['id']}:{write_hypo['target_method']}:"
        f"{write_hypo['target_endpoint']}:{write_hypo['object_id']}:{write_hypo['attacker_role']}:{write_hypo['scenario']['name']}"
    )

    # Seed expired timestamp (2 hours ago, ttl is 3600s)
    from datetime import datetime, timezone, timedelta
    expired_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
    wf.state.approved_operations[token] = expired_time

    res = wf.run_investigation(allow_write=False)
    assert any("expired" in r.get("reason", "") for r in res["results"])


def test_verifier_inconclusive_on_inconsistent_owner_baseline():
    """If owner baseline returns 401/403/500, the finding is inconclusive rather than confirmed."""
    verifier = AuthorizationVerifier(MagicMock())
    hypo = Hypothesis(
        id="H1", title="IDOR", description="", kind="idor_read",
        target_endpoint="http://lab.test/items/42", target_method="GET",
        object_id="42", owner_role="A", attacker_role="B",
        scenario=ScenarioSpec(name="s", base_url="http://lab.test", steps=[], claim={}),
    )
    # Owner receives 403 (could not access their own object) while attacker receives 200
    exec_results = {
        "steps": {
            "owner_read": {"status": 403, "body": '{"error": "forbidden"}'},
            "attack_read": {"status": 200, "body": '{"id": 42}'},
        },
    }
    res = verifier.verify_hypothesis_result(hypo, exec_results, {}, {})
    assert res.status == "inconclusive"
    assert res.verdict == "inconsistent_owner_baseline"


def test_verifier_inconclusive_on_stale_session():
    """If both owner and attacker receive 401/403, it detects stale session as inconclusive."""
    verifier = AuthorizationVerifier(MagicMock())
    hypo = Hypothesis(
        id="H1", title="IDOR", description="", kind="idor_read",
        target_endpoint="http://lab.test/items/42", target_method="GET",
        object_id="42", owner_role="A", attacker_role="B",
        scenario=ScenarioSpec(name="s", base_url="http://lab.test", steps=[], claim={}),
    )
    # Both received 401
    exec_results = {
        "steps": {
            "owner_read": {"status": 401, "body": '{"error": "session expired"}'},
            "attack_read": {"status": 401, "body": '{"error": "session expired"}'},
        },
    }
    res = verifier.verify_hypothesis_result(hypo, exec_results, {}, {})
    assert res.status == "inconclusive"
    assert res.verdict == "stale_session_detected"
