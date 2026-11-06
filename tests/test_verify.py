"""Independent verification: offline evidence audit + mocked online replay."""
import httpx
import pytest

from bb import verify as verifier
from bb.models import Evidence, Exchange, Finding
from bb.scope import Scope
from bb.session import Role
from bb.store import Store


def _idor_finding(confidence: str = "high", identity_a: str = "alice@lab.test",
                  identity_b: str = "bob@lab.test") -> Finding:
    owner = Exchange(method="GET", url="https://app.example.com/api/invoice/1",
                     status=200, response_body=f'{{"id":1,"email":"{identity_a}"}}')
    attacker = Exchange(method="GET", url="https://app.example.com/api/invoice/1",
                        status=200, response_body=f'{{"id":1,"email":"{identity_a}"}}')
    return Finding(
        title="Broken object-level authorization: invoice read",
        bug_class="IDOR", severity="high", confidence=confidence,
        host="app.example.com", url="https://app.example.com/api/invoice/1",
        summary="s", impact="i", remediation="r", steps=["1"],
        evidence=[Evidence("owner view", owner), Evidence("attacker replay", attacker)],
        meta={"identity_a": identity_a, "identity_b": identity_b})


def test_consistent_idor_evidence_passes_audit():
    result = verifier.audit_offline(_idor_finding())
    assert result["verdict"] == "consistent"


def test_attacker_body_with_own_identity_is_contradicted():
    f = _idor_finding()
    # attacker got 200 but the body is the attacker's OWN object: claim is wrong
    f.evidence[-1].exchange.response_body = f'{{"id":2,"email":"{f.meta["identity_b"]}"}}'
    result = verifier.audit_offline(f)
    assert result["verdict"] == "contradicted"
    assert any("own identity" in i for i in result["issues"])


def test_owner_identity_absent_from_attacker_body_flags_issue():
    f = _idor_finding()
    f.evidence[-1].exchange.response_body = '{"id":1,"email":"someone@else.test"}'
    result = verifier.audit_offline(f)
    assert any("owner identity absent" in i for i in result["issues"])
    assert result["verdict"] == "contradicted"      # confidence=high -> contradicted


def test_medium_confidence_contradiction_stays_uncertain():
    f = _idor_finding(confidence="medium")
    f.evidence[-1].exchange.response_body = '{"totally":"public"}'
    result = verifier.audit_offline(f)
    assert result["verdict"] == "uncertain"
    assert f.status == "candidate"                  # offline never flips low-conf claims


def test_missing_evidence_is_caught():
    f = _idor_finding()
    f.evidence = [Evidence("only one side", f.evidence[0].exchange)]
    result = verifier.audit_offline(f)
    assert any("two-role evidence" in i for i in result["issues"])


def test_scope_fingerprint_change_is_flagged():
    f = _idor_finding()
    f.meta["scope_fingerprint"] = "aaaaaaaaaaaaaaaa"
    f.meta["_current_scope_fingerprint"] = "bbbbbbbbbbbbbbbb"
    result = verifier.audit_offline(f)
    assert any("scope fingerprint changed" in i for i in result["issues"])


# ---------- batch driver (no network: MockTransport + injected roles) ----------

def test_verify_candidates_confirms_reproducing_finding(store, tmp_path):
    f = _idor_finding()
    store.add_finding(f, run_id=None)
    store.update_meta(f.id, program="p")
    scope = Scope.from_entries("p", ["app.example.com"])

    def handler(req):
        # alice = owner, bob = attacker; the lab always leaks
        body = '{"id":1,"email":"alice@lab.test"}'
        return httpx.Response(200, text=body)

    from bb.http import ScopedClient
    client = ScopedClient(scope, base_url="https://app.example.com/",
                          transport=httpx.MockTransport(handler), rate=100)
    roles = [
        Role(label="A", email="alice@lab.test", identity="alice@lab.test",
             headers={"authorization": "Bearer a"}),
        Role(label="B", email="bob@lab.test", identity="bob@lab.test",
             headers={"authorization": "Bearer b"}),
    ]
    from bb import session
    session_login = session.login_roles
    session.login_roles = lambda *a, **k: roles
    try:
        summary = verifier.verify_candidates(
            store, scope, "p", accounts={"base_url": "https://app.example.com"},
            client=client)
    finally:
        session.login_roles = session_login
    assert summary["confirmed"] == 1
    updated = store.get_finding(f.id)
    assert updated.status == "confirmed"
    assert updated.meta["verify"]["online"] == "reproduced"
    # fresh evidence was appended for the report
    assert len(updated.evidence) == 3


def test_verify_candidates_rejects_when_now_enforced(store):
    f = _idor_finding()
    store.add_finding(f, run_id=None)
    store.update_meta(f.id, program="p")
    scope = Scope.from_entries("p", ["app.example.com"])
    store.update_meta(f.id, program="p")

    def handler(req):
        headers = {h.lower(): v for h, v in req.headers.items()}
        if "bearer b" in headers.get("authorization", "").lower():
            return httpx.Response(403, text="forbidden")
        return httpx.Response(200, text='{"id":1,"email":"alice@lab.test"}')

    from bb.http import ScopedClient
    client = ScopedClient(scope, base_url="https://app.example.com/",
                          transport=httpx.MockTransport(handler), rate=100)
    roles = [
        Role(label="A", email="alice@lab.test", identity="alice@lab.test",
             headers={"authorization": "Bearer a"}),
        Role(label="B", email="bob@lab.test", identity="bob@lab.test",
             headers={"authorization": "Bearer b"}),
    ]
    result = verifier.run_verification(f, scope, client=client, roles=roles)
    assert result["online"] == "enforced"
    assert f.status == "rejected"
    assert "now enforced" in f.meta["verify_note"]


def test_verify_candidates_without_accounts_is_offline_only(store, capsys):
    f = _idor_finding()
    store.add_finding(f, run_id=None)
    store.update_meta(f.id, program="p")
    scope = Scope.from_entries("p", ["app.example.com"])
    summary = verifier.verify_candidates(store, scope, "p", accounts=None, client=None)
    assert summary["kept"] == 1 and summary["confirmed"] == 0
    updated = store.get_finding(f.id)
    assert updated.status == "candidate"
    assert updated.meta["verify"]["online"] is None
