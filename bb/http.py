"""The single HTTP choke point.

Every request in this package goes through ScopedClient. It:
  * resolves the URL exactly as it will be sent (so `//evil.com/x` cannot slip past),
  * asks the ScopeEngine about the *resolved* host/port/path,
  * refuses rather than sends on any refusal (and records the refusal),
  * rate-limits, retries 429/5xx with backoff, and enforces a request budget,
  * captures a redacted exchange for the evidence store,
  * supports --dry-run: plan requests without sending.
"""
from __future__ import annotations

import random
import time

import httpx

from bb.config import BODY_CAP, DEFAULT_RATE, DEFAULT_TIMEOUT, USER_AGENT
from bb.models import Exchange
from bb.redact import redact_body, redact_headers
from bb.scope import Scope, ScopeViolation


class BudgetExceeded(RuntimeError):
    pass


class ScopedClient:
    def __init__(self, scope: Scope, *, base_url: str | None = None, proxy: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT, rate: float = DEFAULT_RATE,
                 max_requests: int | None = None, deadline: float | None = None,
                 dry_run: bool = False, store=None, run_id: str | None = None,
                 tool: str = "http", verify: bool = True, user_agent: str | None = None,
                 transport: httpx.BaseTransport | None = None):
        self.scope = scope
        self.base_url = base_url
        self.rate = max(rate, 0.1)
        self.max_requests = max_requests
        self.deadline = deadline
        self.dry_run = dry_run
        self.store = store
        self.run_id = run_id
        self.tool = tool
        self.sent = 0
        self.planned: list[tuple[str, str]] = []
        self.last_exchange: Exchange | None = None
        self._last = 0.0
        self._client = httpx.Client(
            timeout=timeout, follow_redirects=False, verify=verify,
            proxy=proxy, transport=transport,
            headers={"User-Agent": user_agent or USER_AGENT, "Accept": "*/*"},
        )
        if base_url:
            self.origin = str(httpx.URL(base_url))
        else:
            self.origin = ""

    # ---------- lifecycle ----------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ScopedClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------- budget / pacing ----------

    def _reserve(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise BudgetExceeded("time budget exhausted")
        if self.max_requests is not None and self.sent >= self.max_requests:
            raise BudgetExceeded(f"request budget exhausted ({self.max_requests})")
        interval = 1.0 / self.rate
        wait = self._last + interval - time.monotonic()
        if wait > 0:
            time.sleep(wait + random.uniform(0, interval * 0.2))
        self._last = time.monotonic()

    # ---------- request ----------

    def resolve(self, url: str) -> str:
        if url.startswith(("http://", "https://")):
            return url
        if not self.base_url:
            raise ValueError(f"relative URL {url!r} without a base_url")
        return str(httpx.URL(self.base_url).join(url))

    def request(self, method: str, url: str, *, headers: dict | None = None,
                params: dict | None = None, json=None, data=None, content=None,
                follow_redirects: bool = False) -> httpx.Response:
        absolute = self.resolve(url)
        decision = self.scope.check(absolute)
        if not decision.allowed:
            if self.store:
                self.store.audit_scope(self.run_id, absolute, "DENY", decision.reason,
                                       decision.host)
            raise ScopeViolation(f"{method.upper()} {absolute} refused: {decision.reason}")
        if self.store:
            self.store.audit_scope(self.run_id, absolute,
                                   "PLAN" if self.dry_run else "ALLOW",
                                   decision.reason, decision.host)

        req = self._client.build_request(
            method.upper(), absolute, headers=headers, params=params,
            json=json, data=data, content=content)
        if self.dry_run:
            self.planned.append((req.method, str(req.url)))
            return httpx.Response(0, request=req)

        self._reserve()
        self.sent += 1

        started = time.monotonic()
        resp = None
        for attempt in range(3):
            try:
                resp = self._client.send(req, follow_redirects=follow_redirects)
            except httpx.HTTPError as exc:
                if attempt == 2:
                    raise
                time.sleep(0.5 * (attempt + 1))
                continue
            if resp.status_code in (429, 502, 503, 504) and attempt < 2:
                retry_after = resp.headers.get("retry-after", "")
                delay = float(retry_after) if retry_after.isdigit() else 1.5 * (attempt + 1)
                time.sleep(min(delay, 10.0))
                continue
            break
        assert resp is not None
        duration_ms = int((time.monotonic() - started) * 1000)

        ex = Exchange(
            method=req.method, url=str(req.url), status=resp.status_code,
            request_headers=redact_headers(dict(req.headers)),
            request_body=redact_body(_body_text(req.content), cap=BODY_CAP),
            response_headers=redact_headers(dict(resp.headers)),
            response_body=redact_body(_safe_text(resp), cap=BODY_CAP),
            duration_ms=duration_ms,
        )
        self.last_exchange = ex
        if self.store:
            self.store.add_exchange(self.run_id, self.tool, ex)
        return resp

    # ---------- shortcuts ----------

    def get(self, url: str, **kw) -> httpx.Response:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw) -> httpx.Response:
        return self.request("HEAD", url, **kw)

    def post(self, url: str, **kw) -> httpx.Response:
        return self.request("POST", url, **kw)

    def json(self, method: str, url: str, **kw):
        try:
            return self.request(method, url, **kw).json()
        except Exception:
            return None


def _body_text(content) -> str:
    if not content:
        return ""
    if isinstance(content, bytes):
        return content.decode("utf-8", "replace")
    return str(content)


def _safe_text(resp: httpx.Response) -> str:
    try:
        return resp.text
    except Exception:
        return ""
