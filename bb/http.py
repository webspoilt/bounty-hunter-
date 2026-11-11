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
import threading
import time

import httpx

from bb import killswitch
from bb.config import BODY_CAP, DEFAULT_RATE, DEFAULT_TIMEOUT, USER_AGENT
from bb.h1_policy import PolicyComplianceEngine
from bb.models import Exchange
from bb.redact import redact_body, redact_headers
from bb.scope import Scope, ScopeViolation


class PolicyViolation(RuntimeError):
    """Raised when an outbound HTTP request violates HackerOne platform rules or program policy."""
    pass


class BudgetExceeded(RuntimeError):
    pass


class RequestBudget:
    """Shared, thread-safe request accounting: count, deadline and pacing.

    One budget per run, not per client: every client sharing a budget exhausts
    ``max_requests`` collectively and paces at the budget's rate, so the polite
    total stays the operator's setting no matter how many workers exist.
    """

    def __init__(self, rate: float = DEFAULT_RATE, max_requests: int | None = None,
                 deadline: float | None = None):
        # Platform safety floor: Rate ceiling of 10.0 req/sec to prevent DoS (COC-UNSAFE-002)
        rate = min(float(rate), 10.0)
        self.rate = max(rate, 0.1)
        self.max_requests = max_requests
        self.deadline = deadline
        self._used = 0
        self._last = 0.0
        self._lock = threading.Lock()

    def consume(self) -> None:
        """Count exactly one outbound attempt; sleep for global pacing."""
        with self._lock:
            if self.deadline is not None and time.monotonic() > self.deadline:
                raise BudgetExceeded("time budget exhausted (shared)")
            if self.max_requests is not None and self._used >= self.max_requests:
                raise BudgetExceeded(
                    f"request budget exhausted ({self.max_requests}, shared)")
            interval = 1.0 / self.rate
            wait = self._last + interval - time.monotonic()
            if wait > 0:
                time.sleep(wait + random.uniform(0, interval * 0.2))
            self._last = time.monotonic()
            self._used += 1

    @property
    def used(self) -> int:
        with self._lock:
            return self._used


class ScopedClient:
    def __init__(self, scope: Scope, *, base_url: str | None = None, proxy: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT, rate: float = DEFAULT_RATE,
                 max_requests: int | None = None, deadline: float | None = None,
                 dry_run: bool = False, store=None, run_id: str | None = None,
                 tool: str = "http", verify: bool = True, user_agent: str | None = None,
                 transport: httpx.BaseTransport | None = None,
                 resolve_dns: bool | None = None,
                 shared: RequestBudget | None = None,
                 writes_approved: bool = False,
                 max_program_rate: float | None = None,
                 test_type: str = "http_request",
                 is_private_program: bool = False):
        self.scope = scope
        self.base_url = base_url
        self.writes_approved = writes_approved
        self.max_program_rate = max_program_rate if max_program_rate is not None else 10.0
        self.test_type = test_type
        self.is_private_program = is_private_program
        # Enforce platform ceiling (10 req/sec) to adhere to HackerOne CoC unsafe testing rules
        self.rate = min(max(rate, 0.1), 10.0, self.max_program_rate)
        self.max_requests = max_requests
        self.deadline = deadline
        self.shared = shared            # when set, count/deadline/pacing are collective
        self.proxy = proxy
        self.dry_run = dry_run
        self.store = store
        self.run_id = run_id
        self.tool = tool
        self.sent = 0
        self.planned: list[tuple[str, str]] = []
        self.last_exchange: Exchange | None = None
        self._last = 0.0
        # None = auto: validate DNS unless a test transport is injected or this is a
        # dry-run. Explicit True/False overrides the auto decision.
        self._resolve_dns = (transport is None and not dry_run) if resolve_dns is None \
            else bool(resolve_dns)
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
        if self.shared is not None:
            # A shared budget owns counting, deadline and pacing collectively:
            # per-client caps would multiply with every worker (audit F1).
            self.shared.consume()
            return
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

    def _attempt_gate(self, absolute: str, host: str, attempt: int) -> None:
        """Safety gates applied to *every* outbound attempt, not just the first.

        Retries re-check the kill switch and DNS resolution (both can change
        between attempts), and each attempt counts against the request budget
        and passes through the rate limiter.
        """
        if attempt > 0:
            if killswitch.active():
                reason = killswitch.reason() or "kill switch is armed"
                if self.store:
                    self.store.audit_scope(self.run_id, absolute, "STOP", reason, host)
                raise killswitch.AbortRequested(
                    f"{absolute} aborted on retry {attempt + 1}: {reason} "
                    "(clear with `bb resume`)")
            if self._resolve_dns and not self.dry_run:
                dns = self.scope.verify_resolution(absolute)
                if not dns.allowed:
                    if self.store:
                        self.store.audit_scope(self.run_id, absolute, "DENY",
                                               f"dns guard (retry): {dns.reason}", dns.host)
                    raise ScopeViolation(
                        f"{absolute} refused by DNS guard on retry: {dns.reason}")
        self._reserve()
        self.sent += 1

    def request(self, method: str, url: str, *, headers: dict | None = None,
                params: dict | None = None, json=None, data=None, content=None,
                follow_redirects: bool = False) -> httpx.Response:
        absolute = self.resolve(url)

        # Policy Preflight Gate: validate method, rate, prohibited testing types and write authorizations
        # In dry_run mode, requests are planned rather than transmitted to the wire.
        policy_res = PolicyComplianceEngine.validate_testing_action(
            method=method,
            url=absolute,
            program_handle=getattr(self.scope, "program", "unknown"),
            rate_rps=self.rate,
            max_program_rate=self.max_program_rate,
            is_state_changing=(method.upper() in ("POST", "PUT", "PATCH", "DELETE")),
            writes_approved=(self.writes_approved or self.dry_run),
            test_type=self.test_type,
            is_private_program=self.is_private_program,
        )
        if not policy_res.compliant:
            v_msgs = "; ".join(f"[{v.rule_id}] {v.message}" for v in policy_res.violations)
            if self.store:
                self.store.audit_scope(self.run_id, absolute, "POLICY_BLOCK", v_msgs)
            raise PolicyViolation(f"{method.upper()} {absolute} blocked by HackerOne Policy Engine: {v_msgs}")

        decision = self.scope.check(absolute)
        if not decision.allowed:
            if self.store:
                self.store.audit_scope(self.run_id, absolute, "DENY", decision.reason,
                                       decision.host)
            raise ScopeViolation(f"{method.upper()} {absolute} refused: {decision.reason}")

        # DNS rebinding guard: a hostname that matches scope by name may still resolve
        # somewhere the program never approved. Validate the resolution before sending.
        extra_reason = ""
        if self._resolve_dns and not self.dry_run:
            dns = self.scope.verify_resolution(absolute)
            if not dns.allowed:
                if self.store:
                    self.store.audit_scope(self.run_id, absolute, "DENY",
                                           f"dns guard: {dns.reason}", dns.host)
                raise ScopeViolation(
                    f"{method.upper()} {absolute} refused by DNS guard: {dns.reason}")
            extra_reason = f"; dns: {dns.reason}"

        # Kill switch: one marker file stops every client in every process.
        if killswitch.active():
            reason = killswitch.reason() or "kill switch is armed"
            if self.store:
                self.store.audit_scope(self.run_id, absolute, "STOP", reason, decision.host)
            raise killswitch.AbortRequested(
                f"{method.upper()} {absolute} aborted: {reason} (clear with `bb resume`)")

        if self.store:
            self.store.audit_scope(self.run_id, absolute,
                                   "PLAN" if self.dry_run else "ALLOW",
                                   decision.reason + extra_reason, decision.host)

        req = self._client.build_request(
            method.upper(), absolute, headers=headers, params=params,
            json=json, data=data, content=content)
        if self.dry_run:
            self.planned.append((req.method, str(req.url)))
            return httpx.Response(0, request=req)

        started = time.monotonic()
        resp = None
        for attempt in range(3):
            # Every outbound attempt re-crosses budget, deadline, rate-limit,
            # kill-switch and DNS gates before it is actually sent.
            self._attempt_gate(absolute, decision.host, attempt)
            try:
                # follow_redirects is pinned False on purpose: redirects are data
                # here, never hops. A followed Location would leave scope with no
                # scope/DNS/kill-switch revalidation; the open-redirect check
                # records the header instead of chasing it (checks.py).
                resp = self._client.send(req, follow_redirects=False)
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
