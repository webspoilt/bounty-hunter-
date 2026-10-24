import httpx

from bb.http import ScopedClient
from bb.recon import Recon
from bb.scope import Scope


def build(handler, store, run_id="r"):
    scope = Scope.from_entries("p", ["lab.test", "*.lab.test"])
    client = ScopedClient(scope, base_url="http://lab.test/",
                          transport=httpx.MockTransport(handler), store=store,
                          run_id=run_id, rate=1000)
    return Recon(client, store, run_id, scope, log=lambda *_: None)


def test_passive_recon_discovers_links_forms_scripts_and_openapi(store):
    def handler(req):
        path = req.url.path
        if path == "/":
            return httpx.Response(200, text="""
                <html><title>App</title>
                <a href="/account/42">account</a>
                <a href="http://evil.test/leak">out of scope</a>
                <form action="/api/search?q=1"></form>
                <script src="/app.js"></script></html>""",
                headers={"content-type": "text/html"})
        if path == "/app.js":
            return httpx.Response(200, text='fetch("/api/v1/users/7"); var x="/rest/orders/3";')
        if path == "/robots.txt":
            return httpx.Response(200, text="Disallow: /admin\nAllow: /public\n")
        if path == "/sitemap.xml":
            return httpx.Response(200, text="<urlset><loc>http://lab.test/products/9</loc></urlset>")
        if path == "/openapi.json":
            return httpx.Response(200, json={
                "paths": {"/api/v2/accounts/{id}": {
                    "get": {"security": [{"bearer": []}],
                            "parameters": [{"name": "id"}]}}}})
        return httpx.Response(404, text="nope")

    recon = build(handler, store)
    endpoints = recon.passive("http://lab.test/")
    urls = {e["url"] for e in endpoints}
    assert "http://lab.test/account/42" in urls
    assert "http://lab.test/api/search?q=1" in urls
    assert "http://lab.test/api/v1/users/7" in urls
    assert "http://lab.test/rest/orders/3" in urls
    assert "http://lab.test/admin" in urls
    assert "http://lab.test/products/9" in urls
    assert not any("evil.test" in u for u in urls)


def test_openapi_marks_auth_required_and_keeps_templates(store):
    def handler(req):
        if req.url.path == "/openapi.json":
            return httpx.Response(200, json={"paths": {
                "/api/v2/accounts/{id}": {"get": {"security": [{"bearer": []}]}}}})
        return httpx.Response(200, text="<html></html>")

    recon = build(handler, store)
    recon.passive("http://lab.test/")
    rows = store.endpoints("r")
    openapi = [r for r in rows if r["source"] == "openapi"]
    assert openapi and openapi[0]["auth_hint"] == "required"
    assert "{id}" in openapi[0]["url"]


def test_cbh_requires_wildcard_scope(store):
    scope = Scope.from_entries("p", ["lab.test"])          # no wildcard
    client = ScopedClient(scope, base_url="http://lab.test/",
                          transport=httpx.MockTransport(lambda r: httpx.Response(200)),
                          store=store, rate=1000)
    recon = Recon(client, store, "r", scope, log=lambda *_: None)
    ok, reason = recon.cbh_allowed("lab.test")
    assert not ok and "wildcard" in reason

    scope2 = Scope.from_entries("p2", ["*.lab.test"])
    recon2 = Recon(client, store, "r", scope2, log=lambda *_: None)
    ok2, _ = recon2.cbh_allowed("lab.test")
    assert ok2
