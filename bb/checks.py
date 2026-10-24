"""Deterministic checks. Each returns Findings with redacted request/response evidence.

All requests go through ScopedClient. Checks are read-only: GET/HEAD, plus a GraphQL
introspection query and a deliberately unsent redirect probe (we never follow the
Location header, we only read it).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from bb.http import BudgetExceeded, ScopedClient
from bb.models import Evidence, Exchange, Finding, sev_rank
from bb.scope import Scope
from bb.session import Role

PII_RE = re.compile(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", re.I)
TOKEN_KEYS = ("token", "deluxeToken", "apiKey", "secret", "password", "ssn", "iban",
              "creditcard", "auth", "session")
REDIRECT_PARAMS = {"url", "next", "redirect", "redirect_uri", "return", "continue",
                   "destination", "callback", "returnUrl", "return_url", "goto", "target"}
SKIP_PATH_RE = re.compile(r"/(login|signin|signup|register|logout|forgot|reset|cart/checkout)", re.I)


@dataclass
class CheckOptions:
    authz: bool = True
    unauth: bool = True
    cors: bool = True
    exposed: bool = True
    graphql: bool = True
    open_redirect: bool = True
    headers: bool = True
    max_endpoints: int = 60
    max_assets: int = 10
    exposed_paths: tuple[str, ...] = (
        "/.git/config", "/.env", "/.env.local", "/backup.zip", "/db.sql", "/server-status",
        "/.DS_Store", "/phpinfo.php", "/package.json", "/composer.json", "/.svn/entries",
        "/config.json", "/WEB-INF/web.xml",
    )

    @property
    def enabled(self) -> set[str]:
        names = ("authz", "unauth", "cors", "exposed", "graphql", "open_redirect", "headers")
        return {n for n in names if getattr(self, n)}


@dataclass
class CheckStats:
    requests: int = 0
    tested: int = 0
    findings: int = 0
    notes: list[str] = field(default_factory=list)


def similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    ja, jb = _json_leaves(a), _json_leaves(b)
    if ja and jb:
        return _jaccard(ja, jb)
    wa = set(re.findall(r"[A-Za-z0-9_@.\-]{3,}", a))
    wb = set(re.findall(r"[A-Za-z0-9_@.\-]{3,}", b))
    return _jaccard(wa, wb)


def _json_leaves(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except Exception:
        return set()
    out: set[str] = set()

    def walk(v):
        if isinstance(v, dict):
            for k, val in v.items():
                out.add(f"k:{k}")
                walk(val)
        elif isinstance(v, list):
            for item in v:
                walk(item)
        elif isinstance(v, (str, int, float, bool)):
            out.add(str(v))

    walk(data)
    return out


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _has_pii(text: str) -> bool:
    if PII_RE.search(text or ""):
        return True
    low = (text or "").lower()
    return any(f'"{k.lower()}"' in low for k in TOKEN_KEYS)


def _host(url: str) -> str:
    return urlsplit(url).hostname or ""


class Checker:
    def __init__(self, client: ScopedClient, store, run_id: str, scope: Scope,
                 roles: list[Role] | None = None, options: CheckOptions | None = None,
                 log=print):
        self.client = client
        self.store = store
        self.run_id = run_id
        self.scope = scope
        self.roles = roles or []
        self.opts = options or CheckOptions()
        self.log = log
        self.stats = CheckStats()

    # ---------- plumbing ----------

    def _get(self, url: str, headers: dict | None = None, *, method: str = "GET",
             note: str = "", json_body=None):
        try:
            if json_body is not None:
                resp = self.client.request(method, url, headers=headers, json=json_body)
            else:
                resp = self.client.request(method, url, headers=headers)
        except BudgetExceeded:
            raise
        except Exception as exc:
            self.stats.notes.append(f"{method} {url}: {exc}")
            return None, None
        self.stats.requests += 1
        ex = self.client.last_exchange
        if ex is not None:
            ex.note = note
        return resp, ex

    def _text(self, resp) -> str:
        try:
            return resp.text or ""
        except Exception:
            return ""

    def _report(self, finding: Finding, action: str = "") -> Finding:
        existing = self.store.find_duplicate(finding.bug_class, finding.url)
        if existing is not None:
            finding.id = existing.id
            finding.created_at = existing.created_at
            finding.status = existing.status
        self.stats.findings += 1
        self.stats.notes.append(f"finding: {finding.title} [{finding.severity}] {action}".strip())
        self.store.add_finding(finding, self.run_id)
        return finding

    def _endpoints_for_object_testing(self, endpoints: list[dict]) -> list[dict]:
        out = []
        for ep in endpoints:
            url = ep["url"]
            if "{" in url or SKIP_PATH_RE.search(url):
                continue
            if ep.get("method", "GET").upper() not in ("GET", "HEAD"):
                continue
            has_id = bool(re.search(r"/\d{1,10}(/|$|\?)", url)) or bool(
                re.search(r"(^|&)(id|user_?id|uid|order_?id|invoice_?id|account_?id)=", url))
            if has_id:
                out.append(ep)
        return out[: self.opts.max_endpoints]

    # ---------- authz / IDOR ----------

    def check_authz(self, endpoints: list[dict]) -> list[Finding]:
        if not self.opts.authz or len(self.roles) < 2:
            return []
        role_a, role_b = self.roles[0], self.roles[1]
        findings: list[Finding] = []
        targets = self._endpoints_for_object_testing(endpoints)
        self.log(f"  [authz] testing {len(targets)} object-shaped endpoints as "
                 f"{role_a.label} vs {role_b.label}")
        for ep in targets:
            url = ep["url"]
            ra, exa = self._get(url, role_a.headers, note=f"{role_a.label} baseline")
            if ra is None:
                continue
            if not (200 <= ra.status_code < 300):
                continue
            rb, exb = self._get(url, role_b.headers, note=f"{role_b.label} replay")
            if rb is None:
                continue
            self.stats.tested += 1
            a_text, b_text = self._text(ra), self._text(rb)
            if rb.status_code in (401, 402, 403):
                self.stats.notes.append(f"{url}: enforced ({role_b.label} -> {rb.status_code})")
                continue

            a_owns = bool(role_a.identity) and role_a.identity in a_text
            b_owns = bool(role_b.identity) and role_b.identity in b_text
            sim = similarity(a_text, b_text)
            evidence = [
                Evidence(f"{role_a.label} (owner) response", exa),
                Evidence(f"{role_b.label} replay of the same object", exb),
            ]
            meta = {"similarity": round(sim, 3), "a_status": ra.status_code,
                    "b_status": rb.status_code, "a_owns": a_owns, "b_owns": b_owns,
                    "scope_fingerprint": self.scope.fingerprint,
                    "identity_a": role_a.identity, "identity_b": role_b.identity}

            if sim >= 0.90 and a_owns and not b_owns:
                finding = Finding(
                    title=f"Broken object-level authorization: {role_b.label} reads "
                          f"{role_a.label}'s object at {urlsplit(url).path}",
                    bug_class="IDOR", severity="high" if _has_pii(b_text) else "medium",
                    confidence="high", host=_host(url), url=url,
                    summary=(f"Role {role_a.label} legitimately receives its own object. Replaying "
                             f"the same request with role {role_b.label}'s session returns "
                             f"{rb.status_code} with {sim:.0%} identical content, including "
                             f"{role_a.label}'s identifier ({role_a.identity}), while "
                             f"{role_b.label}'s own identifier is absent."),
                    impact=("An authenticated user can read another user's data by requesting an "
                            "object they do not own. " +
                            ("The response contains PII or credential material."
                             if _has_pii(b_text) else "Impact depends on the object contents.")),
                    remediation=("Enforce an object-owner/tenant check on the resolution layer "
                                 "(not the route or the UI): every object read must be scoped to "
                                 "the authenticated subject's tenancy."),
                    steps=[f"Authenticate as {role_a.label} and request {url} (owner view).",
                           f"Authenticate as {role_b.label} and request the same URL.",
                           f"Observe HTTP {rb.status_code} and {sim:.0%} content similarity."],
                    evidence=evidence, meta=meta)
                findings.append(self._report(finding, "queued as candidate"))
                continue

            if sim >= 0.90 and not b_owns and (bool(re.search(r"/\d{1,10}", url)) or _has_pii(b_text)):
                finding = Finding(
                    title=f"Object endpoint returns identical data to two unrelated roles: "
                          f"{urlsplit(url).path}",
                    bug_class="IDOR", severity="medium", confidence="medium",
                    host=_host(url), url=url,
                    summary=(f"Both {role_a.label} and {role_b.label} receive HTTP "
                             f"{rb.status_code} with {sim:.0%} identical content, and neither "
                             "response contains the requesting user's own identifier. Confirm "
                             "which account owns the object."),
                    impact=("Possibly cross-tenant read. Verify ownership before reporting: "
                            "public catalogs and shared configuration produce the same pattern."),
                    remediation="Add a server-side ownership check and return 403/404 for foreign objects.",
                    steps=[f"Request {url} as {role_a.label}.", f"Repeat as {role_b.label}.",
                           "Confirm the object belongs to a third user, not to the public."],
                    evidence=evidence, meta=meta)
                findings.append(self._report(finding, "needs ownership confirmation"))
                continue

            if 0.5 <= sim < 0.9 and a_owns and not b_owns and _has_pii(b_text):
                finding = Finding(
                    title=f"Partial cross-role data exposure at {urlsplit(url).path}",
                    bug_class="IDOR", severity="low", confidence="low",
                    host=_host(url), url=url,
                    summary=(f"{role_b.label}'s response differs from {role_a.label}'s but still "
                             f"contains {role_a.label}'s identity and PII-like fields "
                             f"({sim:.0%} similarity)."),
                    impact="Soft leak: metadata, counts, or names may be disclosed.",
                    remediation="Return only fields owned by the requesting subject.",
                    steps=[f"Request {url} as each role and diff the JSON."],
                    evidence=evidence, meta=meta)
                findings.append(self._report(finding, "low-confidence candidate"))
        return findings

    # ---------- unauthenticated access ----------

    def check_unauth(self, endpoints: list[dict]) -> list[Finding]:
        if not self.opts.unauth or not self.roles:
            return []
        role_a = self.roles[0]
        findings: list[Finding] = []
        candidates = [ep for ep in self._endpoints_for_object_testing(endpoints)][: self.opts.max_endpoints]
        declared = [ep for ep in endpoints if ep.get("auth_hint") == "required"][:20]
        for ep in {e["url"]: e for e in candidates + declared}.values():
            url = ep["url"]
            if "{" in url or SKIP_PATH_RE.search(url):
                continue
            ra, exa = self._get(url, role_a.headers, note=f"{role_a.label} authenticated")
            if ra is None or not (200 <= ra.status_code < 300):
                continue
            rn, exn = self._get(url, note="unauthenticated")
            if rn is None or not (200 <= rn.status_code < 300):
                continue
            a_text, n_text = self._text(ra), self._text(rn)
            sim = similarity(a_text, n_text)
            if sim < 0.85:
                continue
            if not (_has_pii(n_text) or role_a.identity in n_text):
                continue
            self.stats.tested += 1
            finding = Finding(
                title=f"Unauthenticated access to authenticated data at {urlsplit(url).path}",
                bug_class="Broken Authentication", severity="high", confidence="high",
                host=_host(url), url=url,
                summary=(f"The endpoint returns HTTP {rn.status_code} to an anonymous request "
                         f"with {sim:.0%} the content of {role_a.label}'s authenticated view, "
                         "including user-specific data."),
                impact="Anyone on the internet can read data that is supposed to require login.",
                remediation="Require authentication before resolving the resource and return 401/403.",
                steps=[f"Request {url} without any credentials.",
                       f"Compare with {role_a.label}'s authenticated response."],
                evidence=[Evidence(f"{role_a.label} authenticated", exa),
                          Evidence("anonymous request", exn)],
                meta={"similarity": round(sim, 3),
                      "scope_fingerprint": self.scope.fingerprint})
            findings.append(self._report(finding, "queued as candidate"))
        return findings

    # ---------- CORS ----------

    def check_cors(self, entry_urls: list[str]) -> list[Finding]:
        if not self.opts.cors:
            return []
        findings = []
        probes = [("reflected origin", "https://bb-probe.invalid"),
                  ("null origin", "null")]
        for url in entry_urls[: self.opts.max_assets]:
            origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
            for label, probe in probes:
                resp, ex = self._get(origin + "/", headers={"Origin": probe},
                                     note=f"CORS {label}")
                if resp is None:
                    continue
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
                if not acao:
                    continue
                reflected = acao == probe or (probe == "null" and acao == "null")
                wildcard_cred = acao == "*" and acac
                if not (reflected or wildcard_cred):
                    continue
                finding = Finding(
                    title=f"CORS misconfiguration on {urlsplit(url).netloc} ({label})",
                    bug_class="CORS", severity="medium" if not acac else "high",
                    confidence="high", host=_host(url), url=origin + "/",
                    summary=(f"The server answers Origin: {probe} with "
                             f"Access-Control-Allow-Origin: {acao}"
                             + (" and allows credentials." if acac else ".")),
                    impact=("A malicious site can read authenticated responses from the victim's "
                            "browser" if acac else
                            "Third-party sites can read this endpoint's response."),
                    remediation=("Echo only allow-listed origins; never reflect arbitrary Origin "
                                 "values, and never combine a wildcard with credentials."),
                    steps=[f"curl -H 'Origin: {probe}' -i {origin}/",
                           "Inspect access-control-allow-origin in the response."],
                    evidence=[Evidence(f"CORS probe with Origin: {probe}", ex)],
                    meta={"acao": acao, "acac": acac, "probe": probe,
                          "scope_fingerprint": self.scope.fingerprint})
                findings.append(self._report(finding, "queued as candidate"))
                break
        return findings

    # ---------- exposed files ----------

    def check_exposed(self, entry_urls: list[str]) -> list[Finding]:
        if not self.opts.exposed:
            return []
        findings = []
        signatures = {
            "/.git/config": (re.compile(r"\[core\]", re.I), "high"),
            "/.svn/entries": (re.compile(r"^\s*dir\s*$", re.M), "medium"),
            "/.env": (re.compile(r"(?m)^[A-Z0-9_]{3,}=.+$"), "high"),
            "/.env.local": (re.compile(r"(?m)^[A-Z0-9_]{3,}=.+$"), "high"),
            "/backup.zip": (re.compile(r"^PK\x03\x04", re.S), "medium"),
            "/db.sql": (re.compile(r"CREATE TABLE|INSERT INTO", re.I), "high"),
            "/server-status": (re.compile(r"Apache Server Status", re.I), "low"),
            "/phpinfo.php": (re.compile(r"PHP Version", re.I), "medium"),
            "/package.json": (re.compile(r'"name"\s*:\s*"'), "low"),
            "/composer.json": (re.compile(r'"require"\s*:'), "low"),
            "/config.json": (re.compile(r'"\w+"\s*:\s*[\[{"\d]'), "medium"),
            "/WEB-INF/web.xml": (re.compile(r"<web-app", re.I), "medium"),
            "/.DS_Store": (re.compile(r"Bud1", re.S), "low"),
        }
        for url in entry_urls[: self.opts.max_assets]:
            origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
            for path in self.opts.exposed_paths:
                full = origin + path
                resp, ex = self._get(full, note=f"exposed-file probe {path}")
                if resp is None or resp.status_code != 200:
                    continue
                body = self._text(resp)
                sig, severity = signatures.get(path, (None, "low"))
                if not sig or not sig.search(body):
                    continue
                if "text/html" in resp.headers.get("content-type", "") and "phpinfo" not in path:
                    continue
                finding = Finding(
                    title=f"Exposed sensitive file: {path}",
                    bug_class="Information Disclosure", severity=severity, confidence="high",
                    host=_host(url), url=full,
                    summary=(f"{full} is publicly reachable (HTTP 200) and contains "
                             f"{path.split('/')[-1]}-shaped content."),
                    impact=("Disclosure of source, secrets, or environment configuration"
                            if severity in ("high", "medium") else
                            "Minor information disclosure useful for further enumeration."),
                    remediation=f"Remove {path} from the web root and block dotfiles at the edge.",
                    steps=[f"curl -i {full}"],
                    evidence=[Evidence(f"response body for {path}", ex)],
                    meta={"scope_fingerprint": self.scope.fingerprint})
                findings.append(self._report(finding, "queued as candidate"))
        return findings

    # ---------- GraphQL ----------

    def check_graphql(self, endpoints: list[dict]) -> list[Finding]:
        if not self.opts.graphql:
            return []
        findings = []
        seen = set()
        query = "query BBProbe { __schema { types { name } } }"
        for ep in endpoints:
            url = ep["url"]
            if "graphql" not in url.lower() or "{" in url:
                continue
            origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
            if origin in seen:
                continue
            seen.add(origin)
            resp, ex = self._get(url, method="POST", json_body={"query": query},
                                 note="GraphQL introspection")
            if resp is None or resp.status_code >= 400:
                continue
            body = self._text(resp)
            if '"__schema"' not in body or '"types"' not in body:
                continue
            finding = Finding(
                title=f"GraphQL introspection enabled at {urlsplit(url).path}",
                bug_class="GraphQL", severity="low", confidence="high",
                host=_host(url), url=url,
                summary=("The endpoint answers an introspection query and returns the full "
                         "schema (types and fields)."),
                impact=("Attackers can enumerate every query, mutation, and internal type, "
                        "which shortens discovery for authz and injection bugs."),
                remediation="Disable introspection in production or gate it behind admin auth.",
                steps=[f"POST {url} with {{\"query\":\"{{__schema{{types{{name}}}}}}\"}}"],
                evidence=[Evidence("GraphQL introspection response", ex)],
                meta={"scope_fingerprint": self.scope.fingerprint})
            findings.append(self._report(finding, "queued as candidate"))
        return findings

    # ---------- open redirect ----------

    def check_open_redirect(self, endpoints: list[dict]) -> list[Finding]:
        if not self.opts.open_redirect:
            return []
        findings = []
        marker = "https://bb-oob.invalid/redirect-probe"
        for ep in endpoints[: self.opts.max_endpoints]:
            url = ep["url"]
            if "{" in url:
                continue
            parts = urlsplit(url)
            params = parse_qs(parts.query)
            hit = [p for p in params if p.lower() in {x.lower() for x in REDIRECT_PARAMS}]
            if not hit:
                continue
            for param in hit:
                new_q = {k: v[0] if v else "" for k, v in params.items()}
                new_q[param] = marker
                probe = urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urlencode(new_q), ""))
                resp, ex = self._get(probe, note=f"open-redirect probe ?{param}=")
                if resp is None or not (300 <= resp.status_code < 400):
                    continue
                location = resp.headers.get("location", "")
                if "bb-oob.invalid" not in location:
                    continue
                finding = Finding(
                    title=f"Open redirect via '{param}' parameter at {parts.path}",
                    bug_class="Open Redirect", severity="medium", confidence="high",
                    host=_host(url), url=probe,
                    summary=(f"The server responds {resp.status_code} with Location: {location}, "
                             f"reflecting an attacker-supplied destination."),
                    impact=("Enables credible phishing from the program's own domain and can be "
                            "chained into OAuth token theft."),
                    remediation="Validate redirect targets against an allow-list of paths/hosts.",
                    steps=[f"Request {probe}", "Observe the Location header."],
                    evidence=[Evidence(f"redirect response for ?{param}=", ex)],
                    meta={"param": param, "location": location,
                          "scope_fingerprint": self.scope.fingerprint})
                findings.append(self._report(finding, "queued as candidate"))
                break
        return findings

    # ---------- hygiene (informational, never queued) ----------

    def check_headers(self, entry_urls: list[str]) -> list[Finding]:
        if not self.opts.headers:
            return []
        findings = []
        for url in entry_urls[: self.opts.max_assets]:
            resp, ex = self._get(url, note="security header baseline")
            if resp is None or resp.status_code >= 400:
                continue
            h = {k.lower(): v for k, v in resp.headers.items()}
            missing = [n for n, key in (("content-security-policy", "content-security-policy"),
                                        ("strict-transport-security", "strict-transport-security"),
                                        ("x-content-type-options", "x-content-type-options"))
                       if key not in h]
            if not missing:
                continue
            finding = Finding(
                title=f"Missing security headers on {urlsplit(url).netloc}",
                bug_class="Security Misconfiguration", severity="info", confidence="high",
                status="informational", host=_host(url), url=url,
                summary="Missing: " + ", ".join(missing),
                impact="Defence-in-depth only; not usually bounty-eligible on its own.",
                remediation="Add the missing headers at the edge.",
                steps=[f"curl -I {url}"],
                evidence=[Evidence("response headers", ex)],
                meta={"missing": missing, "scope_fingerprint": self.scope.fingerprint})
            findings.append(self._report(finding, "informational only"))
        return findings

    # ---------- dry-run planning ----------

    def plan(self, entry_urls: list[str], endpoints: list[dict]) -> int:
        """Record the requests the real run would send, without sending anything."""
        planned: list[tuple[str, str]] = []
        self.client.dry_run = True
        try:
            for url in entry_urls[: self.opts.max_assets]:
                origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
                if self.opts.exposed:
                    for path in self.opts.exposed_paths:
                        self._get(origin + path, note="plan: exposed-file probe")
                if self.opts.cors:
                    self._get(origin + "/", headers={"Origin": "https://bb-probe.invalid"},
                              note="plan: CORS probe")
                if self.opts.headers:
                    self._get(origin + "/", note="plan: header baseline")
            for ep in self._endpoints_for_object_testing(endpoints):
                for role in self.roles[:2]:
                    self._get(ep["url"], role.headers, note=f"plan: {role.label} replay")
                if self.opts.unauth:
                    self._get(ep["url"], note="plan: anonymous request")
            if self.opts.graphql:
                for ep in endpoints:
                    if "graphql" in ep["url"].lower() and "{" not in ep["url"]:
                        self._get(ep["url"], method="POST",
                                  json_body={"query": "query BBProbe { __schema { types { name } } }"},
                                  note="plan: GraphQL introspection")
            if self.opts.open_redirect:
                marker = "https://bb-oob.invalid/redirect-probe"
                for ep in endpoints[: self.opts.max_endpoints]:
                    parts = urlsplit(ep["url"])
                    params = parse_qs(parts.query)
                    for param in params:
                        if param.lower() in {x.lower() for x in REDIRECT_PARAMS}:
                            new_q = {k: v[0] if v else "" for k, v in params.items()}
                            new_q[param] = marker
                            self._get(urlunsplit((parts.scheme, parts.netloc, parts.path,
                                                  urlencode(new_q), "")),
                                      note=f"plan: open-redirect ?{param}=")
                            break
            planned = list(self.client.planned)
        finally:
            self.client.dry_run = False
        return len(planned)

    # ---------- orchestration ----------

    def run_all(self, entry_urls: list[str], endpoints: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        order = ["exposed", "cors", "graphql", "open_redirect", "authz", "unauth", "headers"]
        for name in order:
            try:
                if name == "exposed":
                    findings += self.check_exposed(entry_urls)
                elif name == "cors":
                    findings += self.check_cors(entry_urls)
                elif name == "graphql":
                    findings += self.check_graphql(endpoints)
                elif name == "open_redirect":
                    findings += self.check_open_redirect(endpoints)
                elif name == "authz":
                    findings += self.check_authz(endpoints)
                elif name == "unauth":
                    findings += self.check_unauth(endpoints)
                elif name == "headers":
                    findings += self.check_headers(entry_urls)
            except BudgetExceeded:
                self.stats.notes.append(f"budget exhausted during {name}")
                break
            except Exception as exc:
                self.stats.notes.append(f"{name} failed: {type(exc).__name__}: {exc}")
                self.log(f"  [!] {name} check failed: {exc}")
        return findings


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.bug_class, f.url, f.title)
        if key not in seen:
            seen[key] = f
    return sorted(seen.values(), key=lambda f: (-sev_rank(f.severity), f.url))


def finding_fingerprint(f: Finding) -> str:
    blob = json.dumps({"class": f.bug_class, "url": f.url, "title": f.title}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
