"""Recon: passive surface discovery, plus an optional cbh (Claude-BugHunter) run.

Two modes, deliberately:
  * passive — fetch the entry URL, robots.txt, sitemap.xml, HTML links/forms, JS bundles,
    and common OpenAPI documents. Every fetch goes through ScopedClient, so nothing
    outside the program scope is ever requested.
  * cbh — delegate subdomain enumeration + HTTP probing to `cbh recon`. That tool probes
    every *discovered* subdomain, so it is only allowed when the scope contains a wildcard
    covering the target. Otherwise we would be sending traffic to hosts the program never
    authorised.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit, parse_qs

from bb.config import CBH, CBH_HOME, RECON
from bb.http import ScopedClient
from bb.scope import Scope

STATIC_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|mp3|pdf|zip|gz|map)(\?|$)", re.I)
SKIP_PREFIX = ("mailto:", "javascript:", "tel:", "data:", "#")
OPENAPI_PATHS = (
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json",
    "/.well-known/openapi.json", "/api/openapi.json", "/docs/openapi.json",
)
LINK_RE = re.compile(r"""(?:href|action|src)\s*=\s*["']([^"'<>]+)["']""", re.I)
SCRIPT_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
# strings in JS that look like API paths
JS_PATH_RE = re.compile(r"""["'`](/(?:api|rest|v[0-9]+|graphql|internal|admin|users?|accounts?|"""
                        r"""orders?|invoices?|baskets?|items?|files?|documents?|messages?|"""
                        r"""profiles?|transactions?|payments?|reports?|settings?|auth)[^"'`\s]{0,120})["'`]""")
FETCH_RE = re.compile(r"""fetch\(\s*["'`]([^"'`]+)["'`]""")
NUMERIC_ID = re.compile(r"/\d{1,10}(/|$|\?)")


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _clean(raw: str, base: str) -> str | None:
    raw = (raw or "").strip()
    if not raw or raw.lower().startswith(SKIP_PREFIX):
        return None
    if raw.startswith("//"):
        raw = urlsplit(base).scheme + ":" + raw
    absolute = urljoin(base, raw)
    if not absolute.startswith(("http://", "https://")):
        return None
    absolute = absolute.split("#")[0]
    if STATIC_EXT.search(absolute):
        return None
    return absolute


class Recon:
    def __init__(self, client: ScopedClient, store, run_id: str, scope: Scope, log=print):
        self.client = client
        self.store = store
        self.run_id = run_id
        self.scope = scope
        self.log = log
        self.seen: dict[str, dict] = {}

    # ---------- helpers ----------

    def _add(self, url: str, method: str = "GET", source: str = "link",
             auth_hint: str = "", params: list | None = None) -> None:
        if url in self.seen:
            return
        decision = self.scope.check(url)
        if not decision.allowed:
            return
        path = urlsplit(url).path or "/"
        params = params or sorted(parse_qs(urlsplit(url).query).keys())
        self.seen[url] = {"url": url, "method": method, "source": source,
                          "auth_hint": auth_hint, "params": params,
                          "host": decision.host, "path": path}
        self.store.add_endpoint(self.run_id, url, method=method, host=decision.host,
                                path=path, source=source, params=params,
                                auth_hint=auth_hint)

    def _fetch(self, url: str) -> str:
        try:
            resp = self.client.get(url)
        except Exception as exc:
            self.log(f"  [recon] {url}: {exc}")
            return ""
        if resp.status_code >= 400:
            return ""
        return resp.text or ""

    # ---------- passive ----------

    def passive(self, entry_url: str) -> list[dict]:
        origin = _origin(entry_url)
        self.log(f"  [recon] entry {entry_url}")
        try:
            resp = self.client.get(entry_url)
            html = resp.text or ""
        except Exception as exc:
            self.log(f"  [recon] {entry_url}: {exc}")
            resp, html = None, ""
        host = self.scope.check(entry_url).host
        if resp is not None:
            self.store.add_asset(self.run_id, host, entry_url, resp.status_code,
                                 resp.headers.get("server", ""), _title(html), source="entry")
        if 300 <= getattr(resp, "status_code", 0) < 400:
            self.log(f"  [recon] entry redirects to {resp.headers.get('location', '?')} "
                     "(not followed; add it as --entry if it is in scope)")

        for m in LINK_RE.findall(html):
            url = _clean(m, entry_url)
            if url:
                self._add(url, source="html")
        for m in SCRIPT_RE.findall(html):
            url = _clean(m, entry_url)
            if url:
                self._add(url, source="script")
                self._parse_js(url, origin)
        for raw in re.findall(r"""(?:href|action)=["'](/[^"'<>]*)["']""", html, re.I):
            url = _clean(raw, entry_url)
            if url:
                self._add(url, source="form" if "?" not in url else "link")

        self._robots(origin)
        self._sitemaps(origin)
        self._openapi(origin)
        self.log(f"  [recon] {len(self.seen)} endpoints discovered")
        return list(self.seen.values())

    def _parse_js(self, js_url: str, origin: str) -> None:
        body = self._fetch(js_url)
        if not body or len(body) > 2_000_000:
            return
        for raw in set(JS_PATH_RE.findall(body)) | set(FETCH_RE.findall(body)):
            raw = raw.replace("${", "{").replace("}", "}")
            raw = re.sub(r"\{[^}]*\}", "{id}", raw)
            if "{" in raw:            # template: keep as inventory pattern, not a probe target
                continue
            url = _clean(raw, js_url)
            if url:
                self._add(url, source="js")

    def _robots(self, origin: str) -> None:
        text = self._fetch(f"{origin}/robots.txt")
        for line in text.splitlines():
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    self._add(origin + path, source="robots")

    def _sitemaps(self, origin: str, depth: int = 0) -> None:
        if depth > 1:
            return
        text = self._fetch(f"{origin}/sitemap.xml")
        if not text:
            return
        for loc in LOC_RE.findall(text)[:300]:
            if loc.endswith(".xml"):
                self._sitemaps(loc, depth + 1)
                continue
            url = _clean(loc, origin)
            if url:
                self._add(url, source="sitemap")

    def _openapi(self, origin: str) -> None:
        for path in OPENAPI_PATHS:
            url = origin + path
            if not self.scope.is_in_scope(url):
                continue
            try:
                resp = self.client.get(url)
            except Exception:
                continue
            if resp.status_code >= 400:
                continue
            try:
                spec = resp.json()
            except Exception:
                continue
            if not isinstance(spec, dict) or "paths" not in spec:
                continue
            self.log(f"  [recon] OpenAPI document at {url}")
            base = origin
            for server in spec.get("servers") or []:
                if isinstance(server, dict) and server.get("url", "").startswith("http"):
                    base = server["url"].rstrip("/") or origin
            for route, ops in (spec.get("paths") or {}).items():
                if not isinstance(ops, dict):
                    continue
                for method, op in ops.items():
                    if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
                        continue
                    auth = "required" if (op.get("security") or spec.get("security")) else "unknown"
                    concrete = route
                    if "{" in route:
                        self.store.add_endpoint(
                            self.run_id, base + route, method=method.upper(),
                            host=self.scope.check(base).host, path=route,
                            source="openapi", params=_params(op), auth_hint=auth)
                        continue
                    self._add(base + route, method=method.upper(), source="openapi",
                              auth_hint=auth, params=_params(op))
            return

    # ---------- cbh ----------

    def cbh_allowed(self, domain: str) -> tuple[bool, str]:
        if not CBH.exists():
            return False, f"cbh not found at {CBH} (set CBH_HOME)"
        wildcard_ok = any(r.kind == "wildcard" and
                          (domain == r.host or domain.endswith("." + r.host))
                          for r in self.scope.in_rules)
        if not wildcard_ok:
            return False, (f"scope for {self.scope.program} has no wildcard covering {domain}; "
                           "cbh recon probes discovered subdomains, so it is not safe here. "
                           "Add '*.%s' to scope or use passive recon." % domain)
        return True, "wildcard scope covers subdomain probing"

    def cbh_recon(self, domain: str, timeout: int = 900) -> dict:
        ok, why = self.cbh_allowed(domain)
        if not ok:
            self.log(f"  [cbh] refused: {why}")
            return {"error": why}
        RECON.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, str(CBH), "recon", domain, "--out", str(RECON)]
        self.log(f"  [cbh] {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  cwd=str(CBH_HOME))
        except subprocess.TimeoutExpired:
            return {"error": f"cbh timed out after {timeout}s"}
        manifest_path = RECON / domain / "manifest.json"
        if not manifest_path.exists():
            return {"error": f"cbh produced no manifest ({proc.returncode}): "
                             f"{(proc.stderr or proc.stdout)[-400:]}"}
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        imported = 0
        for asset in manifest.get("assets", []):
            host = asset.get("host", "")
            if not host or not self.scope.is_in_scope(host):
                continue
            url = asset.get("url") or f"https://{host}"
            if not self.scope.is_in_scope(url):
                continue
            self.store.add_asset(self.run_id, host, url, asset.get("status"),
                                 asset.get("server", ""), asset.get("title", ""),
                                 asset.get("tech"), source="cbh")
            imported += 1
            self._add(url, source="cbh")
        for row in manifest.get("ranked_surface", []):
            if row.get("url") and self.scope.is_in_scope(row["url"]):
                self._add(row["url"], source="cbh-ranked")
        self.log(f"  [cbh] imported {imported} in-scope assets from manifest")
        return {"manifest": str(manifest_path), "assets": imported,
                "counts": manifest.get("counts", {})}


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return " ".join(m.group(1).split())[:200] if m else ""


def _params(op: dict) -> list[str]:
    names = []
    for p in (op.get("parameters") or []):
        if isinstance(p, dict) and p.get("name"):
            names.append(str(p["name"]))
    body = op.get("requestBody") or {}
    for ctype, spec in (body.get("content") or {}).items():
        schema = (spec or {}).get("schema") or {}
        names += list((schema.get("properties") or {}).keys())
    return names
