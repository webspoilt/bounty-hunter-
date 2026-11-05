import httpx

from bb.checks import CheckOptions, Checker, similarity
from bb.http import ScopedClient
from bb.scope import Scope
from bb.session import Role

A = Role(label="A", email="alice@lab.test", identity="alice@lab.test",
         headers={"Authorization": "Bearer A"})
B = Role(label="B", email="bob@lab.test", identity="bob@lab.test",
         headers={"Authorization": "Bearer B"})


def make(handler, store, entry="http://lab.test/", **kw):
    scope = Scope.from_entries("p", ["lab.test"])
    client = ScopedClient(scope, base_url=entry, transport=httpx.MockTransport(handler),
                          store=store, run_id="run", rate=1000, **kw)
    return Checker(client, store, "run", scope, roles=[A, B],
                   options=CheckOptions(max_endpoints=5, max_assets=2), log=lambda *_: None)


def test_similarity_identical_and_different():
    assert similarity('{"a":1}', '{"a":1}') == 1.0
    assert similarity('{"a":1}', '{"b":2}') < 0.5


def test_idor_confirmed_when_b_sees_a_identity(store):
    def handler(req):
        if req.url.path == "/invoices/42":
            return httpx.Response(200, json={"invoice": {"id": 42, "email": "alice@lab.test",
                                                         "amount": 999}})
        return httpx.Response(404)

    checker = make(handler, store)
    findings = checker.check_authz([{"url": "http://lab.test/invoices/42", "method": "GET"}])
    assert len(findings) == 1
    f = findings[0]
    assert f.bug_class == "IDOR" and f.severity == "high" and f.confidence == "high"
    assert len(f.evidence) == 2
    stored = store.get_finding(f.id)
    assert stored.evidence[1].exchange.status == 200


def test_authz_enforced_produces_no_finding(store):
    def handler(req):
        if req.headers.get("authorization") == "Bearer B":
            return httpx.Response(403, json={"error": "forbidden"})
        return httpx.Response(200, json={"invoice": {"id": 42, "email": "alice@lab.test"}})

    checker = make(handler, store)
    findings = checker.check_authz([{"url": "http://lab.test/invoices/42"}])
    assert findings == []


def test_identical_but_not_owned_is_only_a_candidate(store):
    def handler(req):
        return httpx.Response(200, json={"product": {"id": 1, "name": "shirt", "price": 9}})

    checker = make(handler, store)
    findings = checker.check_authz([{"url": "http://lab.test/products/1"}])
    assert len(findings) == 1
    assert findings[0].confidence == "medium"
    assert findings[0].severity == "medium"


def test_unauth_access(store):
    def handler(req):
        if req.headers.get("authorization") == "Bearer A":
            return httpx.Response(200, json={"id": 7, "email": "alice@lab.test"})
        if "authorization" not in req.headers:
            return httpx.Response(200, json={"id": 7, "email": "alice@lab.test"})
        return httpx.Response(403)

    checker = make(handler, store)
    findings = checker.check_unauth([{"url": "http://lab.test/profile/7"}])
    assert len(findings) == 1
    assert findings[0].bug_class == "Broken Authentication"
    assert findings[0].severity == "high"


def test_cors_reflection(store):
    def handler(req):
        origin = req.headers.get("origin", "")
        if origin:
            return httpx.Response(200, text="ok", headers={
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true"})
        return httpx.Response(200, text="ok")

    checker = make(handler, store)
    findings = checker.check_cors(["http://lab.test/"])
    assert len(findings) == 1
    assert findings[0].bug_class == "CORS" and findings[0].severity == "high"


def test_cors_wildcard_without_credentials_is_not_a_finding(store):
    def handler(req):
        return httpx.Response(200, text="ok", headers={"access-control-allow-origin": "*"})

    checker = make(handler, store)
    assert checker.check_cors(["http://lab.test/"]) == []


def test_exposed_env_file(store):
    def handler(req):
        if req.url.path == "/.env":
            return httpx.Response(200, text="SECRET_KEY=abc123\nDB_PASSWORD=hunter2\n",
                                  headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    checker = make(handler, store)
    findings = checker.check_exposed(["http://lab.test/"])
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].url.endswith("/.env")


def test_graphql_introspection(store):
    def handler(req):
        if req.url.path == "/graphql":
            return httpx.Response(200, json={"data": {"__schema": {"types": [{"name": "User"}]}}})
        return httpx.Response(404)

    checker = make(handler, store)
    findings = checker.check_graphql([{"url": "http://lab.test/graphql"}])
    assert len(findings) == 1
    assert findings[0].bug_class == "GraphQL"


def test_open_redirect(store):
    def handler(req):
        if req.url.path == "/goto":
            nxt = req.url.params.get("next", "")
            if "bb-oob.invalid" in nxt:
                return httpx.Response(302, headers={"location": nxt})
            return httpx.Response(200, text="no redirect")
        return httpx.Response(404)

    checker = make(handler, store)
    findings = checker.check_open_redirect([{"url": "http://lab.test/goto?next=/home"}])
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_security_headers_are_informational_only(store):
    def handler(req):
        return httpx.Response(200, text="<html></html>")

    checker = make(handler, store)
    findings = checker.check_headers(["http://lab.test/"])
    assert len(findings) == 1
    assert findings[0].status == "informational"
    assert findings[0].severity == "info"


def test_run_all_without_roles_skips_authz(store):
    def handler(req):
        return httpx.Response(200, text="ok")

    scope = Scope.from_entries("p", ["lab.test"])
    client = ScopedClient(scope, base_url="http://lab.test/",
                          transport=httpx.MockTransport(handler), store=store, rate=1000)
    checker = Checker(client, store, "run", scope, roles=None,
                      options=CheckOptions(max_endpoints=2, max_assets=1), log=lambda *_: None)
    findings = checker.run_all(["http://lab.test/"], [])
    assert all(f.bug_class != "IDOR" for f in findings)
