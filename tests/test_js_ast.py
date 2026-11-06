"""JS endpoint extraction: AST-first with a regex fallback."""
import httpx
import pytest

from bb.recon import JS_PATH_RE, Recon, _extract_js_paths
from bb.scope import Scope
from bb.store import Store

BUNDLED = """
(function(){
  /* a comment mentioning /api/admin/comments that is NOT a real call */
  var notes = "/api/this_string_is_never_fetched";
  fetch("/api/v1/orders", {method:"GET"});
  axios.get("/api/v2/users");
  const url = "/api/v2/items/42";
  const id = 7;
  client.request("/api/v3/profiles", {id});
  ky.post("/api/v3/invoices");
  somethingElse.get("/not-an-api/just-a-lib");
})();
"""


def test_ast_extracts_http_call_arguments():
    paths, source = _extract_js_paths(BUNDLED)
    assert source == "js-ast"
    assert "/api/v1/orders" in paths
    assert "/api/v2/users" in paths
    assert "/api/v3/profiles" in paths
    assert "/api/v3/invoices" in paths
    # string constants that look like API paths are kept deliberately (old regex did
    # this too); but strings from COMMENTS are not AST nodes and must never leak,
    # and paths that are not API-shaped must stay out.
    assert all("comments" not in p for p in paths)
    assert "/not-an-api/just-a-lib" not in paths


def test_clean_parse_with_no_calls_returns_nothing():
    paths, source = _extract_js_paths("var a = 1;")
    assert paths == []
    assert source == "js-ast"                       # AST worked, found nothing: trust it


def test_syntactically_broken_bundle_falls_back_to_regex():
    broken = "fetch(\"/api/v1/orders\"); function oops( {{{"
    paths, source = _extract_js_paths(broken)
    assert source == "js"
    assert "/api/v1/orders" in paths


def test_regex_fallback_when_ast_not_installed(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_esprima(name, *args, **kwargs):
        if name == "esprima":
            raise ImportError("esprima missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_esprima)
    # force re-resolution: clear any esprima in sys.modules' import cache via the helper
    from bb import recon
    monkeypatch.setattr(recon, "_extract_js_paths_ast",
                        lambda body: (_ for _ in ()).throw(ImportError("gone")))
    paths, source = recon._extract_js_paths(BUNDLED)
    assert source == "js"
    assert "/api/v1/orders" in paths


def test_extract_from_text_used_by_recon(store, monkeypatch):
    scope = Scope.from_entries("p", ["app.example.com"])
    scope.store_probe = True
    client = Recon.__new__(Recon)                   # we only exercise extraction plumbing
    recon = Recon.__new__(Recon)
    recon.seen = {}
    recon.store = store
    recon.run_id = "r"
    recon.scope = scope
    recon.log = lambda *a, **k: None
    captured = []

    def fake_fetch(url):
        captured.append(url)
        return BUNDLED

    monkeypatch.setattr(recon, "_fetch", fake_fetch)
    recon._parse_js("https://app.example.com/main.js", "https://app.example.com")
    rows = store.conn.execute("SELECT url, source FROM endpoints").fetchall()
    by_url = {r["url"]: r["source"] for r in rows}
    assert any("/api/v1/orders" in u and s == "js-ast" for u, s in by_url.items())


def test_minified_vue_style_axios_instance():
    js = ("const service=axios.create({baseURL:window.location.origin});"
          "service.get('/api/v1/basket/3');")
    paths, source = _extract_js_paths(js)
    assert source == "js-ast"
    assert "/api/v1/basket/3" in paths
