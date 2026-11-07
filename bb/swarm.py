"""Bounded, deduplicated agent swarm — 50+ logical workers, one polite traffic budget.

The point of this module is *not* to let 50 processes hammer a target. It is the
opposite, and it is what makes a large agent count safe and useful:

  * every unit of work has a fingerprint and is claimed atomically in SQLite, so two
    workers (or two runs) can never test the same route twice;
  * logical agents can be numbered 50+ while *network concurrency* is capped by the
    rate budget: all workers share one RequestBudget, so the total stays at ``--rate``;
  * each network worker gets its own scoped client and its own SQLite connection, so
    the scope predicate, DNS guard, kill switch, and redaction apply unchanged;
  * no LLM is used by any worker, so a 50-agent run costs exactly nothing in tokens;
  * completed tasks are remembered with timestamps, so a re-run skips work that is
    still fresh (``--retest-hours``) instead of duplicating it.

Checks are still read-only by default (GET/HEAD, GraphQL introspection, header
baseline). Writes belong to scenarios with ``--allow-write``, never to the swarm.
"""
from __future__ import annotations

import hashlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from bb import normalize
from bb.checks import CheckOptions, Checker, SKIP_PATH_RE, REDIRECT_PARAMS
from bb.http import RequestBudget, ScopedClient
from bb.scope import Scope
from bb.store import Store

CHECK_ORDER = {"authz": 0, "unauth": 1, "graphql": 2, "open_redirect": 3,
               "cors": 4, "exposed": 5, "headers": 6}
MIN_RATE = 0.1
DEFAULT_WORKERS = 8
DEFAULT_RETEST_HOURS = 24.0


@dataclass(frozen=True)
class Task:
    kind: str
    target: str
    payload: dict = field(default_factory=dict, hash=False)
    priority: int = 5

    @property
    def fingerprint(self) -> str:
        key = f"{self.kind}|{normalize.normalize_url(self.target)}"
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:20]


def object_shaped(ep: dict) -> bool:
    url = ep.get("url") or ""
    if not url or "{" in url:
        return False
    if (ep.get("method") or "GET").upper() not in ("GET", "HEAD"):
        return False
    if SKIP_PATH_RE.search(url):
        return False
    if re.search(r"/\d{1,10}(/|$|\?)", url):
        return True
    return bool(re.search(
        r"(^|&)(id|user_?id|uid|order_?id|invoice_?id|account_?id)=", url))


def _origin(url: str) -> str:
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _has_redirect_param(url: str) -> bool:
    from urllib.parse import parse_qs, urlsplit
    names = {n.lower() for n in parse_qs(urlsplit(url).query)}
    return bool(names & {p.lower() for p in REDIRECT_PARAMS})


def plan(endpoints: list[dict], entry_urls: list[str], options: CheckOptions,
         *, have_roles: bool) -> list[Task]:
    """Turn inventory into independent, deduplicated units of work."""
    tasks: list[Task] = []
    seen: set[str] = set()

    def add(kind: str, target: str, payload: dict | None = None) -> None:
        task = Task(kind=kind, target=target, payload=payload or {},
                    priority=CHECK_ORDER.get(kind, 9))
        if task.fingerprint in seen:
            return
        seen.add(task.fingerprint)
        tasks.append(task)

    for origin in dict.fromkeys(_origin(u) for u in entry_urls if u):
        if options.exposed:
            add("exposed", origin)
        if options.cors:
            add("cors", origin)
        if options.headers:
            add("headers", origin)

    for ep in endpoints:
        url = ep.get("url") or ""
        if not url:
            continue
        if options.graphql and "graphql" in url.lower() and "{" not in url:
            add("graphql", url, {"endpoint": ep})
        if options.open_redirect and _has_redirect_param(url):
            add("open_redirect", url, {"endpoint": ep})
        if have_roles and object_shaped(ep):
            if options.authz:
                add("authz", url, {"endpoint": ep})
            if options.unauth:
                add("unauth", url, {"endpoint": ep})

    tasks.sort(key=lambda t: (t.priority, normalize.normalize_url(t.target)))
    return tasks


def effective_workers(requested: int, rate: float) -> int:
    """Logical agents can be many; network concurrency is capped by the rate budget."""
    return max(1, min(int(requested), int(max(rate, MIN_RATE) / MIN_RATE)))


def run_tasks(tasks: list[Task], executor, store: Store, run_id: str,
              *, workers: int = DEFAULT_WORKERS, rate: float = 3.0,
              retest_hours: float | None = DEFAULT_RETEST_HOURS, log=print) -> dict:
    """Claim, execute, and record tasks. Claiming is serial (main thread), work is not."""
    claimed: list[Task] = []
    skipped_dupes = 0
    for task in tasks:
        if store.task_claim(task.kind, task.target, run_id=run_id,
                            fingerprint=task.fingerprint,
                            max_age_hours=retest_hours):
            claimed.append(task)
        else:
            skipped_dupes += 1

    concurrency = effective_workers(workers, rate)
    log(f"  [swarm] {len(tasks)} planned, {len(claimed)} claimed, "
        f"{skipped_dupes} already done (deduped), {concurrency} concurrent "
        f"(requested {workers}, capped by {rate:g} req/s)")
    summary = {"planned": len(tasks), "claimed": len(claimed), "deduped": skipped_dupes,
               "done": 0, "failed": 0, "findings": 0, "requests": 0,
               "by_kind": {}, "workers": concurrency}
    if not claimed:
        return summary

    with ThreadPoolExecutor(max_workers=min(concurrency, len(claimed))) as pool:
        futures = {pool.submit(executor, task): task for task in claimed}
        for future in as_completed(futures):
            task = futures[future]
            try:
                result = future.result()
                store.task_finish(task.fingerprint, "done", result)
                summary["done"] += 1
                summary["findings"] += len(result.get("findings") or [])
                summary["requests"] += int(result.get("requests") or 0)
                bucket = summary["by_kind"].setdefault(
                    task.kind, {"done": 0, "findings": 0})
                bucket["done"] += 1
                bucket["findings"] += len(result.get("findings") or [])
                if result.get("findings"):
                    log(f"  [swarm] {task.kind:12} {normalize.normalize_url(task.target)} "
                        f"-> {len(result['findings'])} finding(s)")
            except Exception as exc:                      # noqa: BLE001 — one task must not kill the run
                store.task_finish(task.fingerprint, "failed", {"error": str(exc)})
                summary["failed"] += 1
                log(f"  [swarm] {task.kind:12} {task.target} FAILED: {exc}")

    close = getattr(executor, "close", None)
    if callable(close):
        close()
    return summary


class SwarmExecutor:
    """Per-thread scoped clients + checker over ONE shared traffic budget.

    Worker threads get their own client and SQLite connection, but counting,
    deadline and pacing are collective: whatever the thread count, the run
    never exceeds ``max_requests`` requests at a combined ``rate`` req/s.
    """

    def __init__(self, scope: Scope, run_id: str, base_url: str, roles: list,
                 options: CheckOptions, *, rate: float, max_requests: int | None,
                 deadline: float | None, proxy: str | None = None, log=print):
        self.scope = scope
        self.run_id = run_id
        self.base_url = base_url
        self.roles = roles
        self.options = options
        self.rate = rate
        self.max_requests = max_requests
        self.deadline = deadline
        self.proxy = proxy
        self.log = log
        self.budget = RequestBudget(rate=rate, max_requests=max_requests,
                                    deadline=deadline)
        self._local = threading.local()
        self._clients: list[ScopedClient] = []
        self._stores: list[Store] = []
        self._lock = threading.Lock()

    def _checker(self) -> Checker:
        checker = getattr(self._local, "checker", None)
        if checker is not None:
            return checker
        store = Store()
        client = ScopedClient(self.scope, base_url=self.base_url, proxy=self.proxy,
                              rate=self.rate, max_requests=self.max_requests,
                              deadline=self.deadline, shared=self.budget,
                              store=store, run_id=self.run_id, tool="swarm")
        checker = Checker(client, store, self.run_id, self.scope, roles=self.roles,
                          options=self.options, log=lambda *a, **k: None)
        with self._lock:
            self._stores.append(store)
            self._clients.append(client)
        self._local.checker = checker
        return checker

    def __call__(self, task: Task) -> dict:
        checker = self._checker()
        before = checker.stats.requests
        ep = task.payload.get("endpoint") or {"url": task.target, "method": "GET"}
        if task.kind == "authz":
            findings = checker.check_authz([ep])
        elif task.kind == "unauth":
            findings = checker.check_unauth([ep])
        elif task.kind == "graphql":
            findings = checker.check_graphql([ep])
        elif task.kind == "open_redirect":
            findings = checker.check_open_redirect([ep])
        elif task.kind == "cors":
            findings = checker.check_cors([task.target])
        elif task.kind == "exposed":
            findings = checker.check_exposed([task.target])
        elif task.kind == "headers":
            findings = checker.check_headers([task.target])
        else:
            raise ValueError(f"unknown task kind {task.kind!r}")
        return {"findings": [f.id for f in findings],
                "requests": checker.stats.requests - before,
                "notes": checker.stats.notes[-5:]}

    def close(self) -> None:
        for client in self._clients:
            try:
                client.close()
            except Exception:                             # noqa: BLE001
                pass
        for store in self._stores:
            try:
                store.close()
            except Exception:                             # noqa: BLE001
                pass


def format_plan(tasks: list[Task], workers: int, rate: float) -> str:
    counts: dict[str, int] = {}
    for task in tasks:
        counts[task.kind] = counts.get(task.kind, 0) + 1
    parts = ", ".join(f"{name} {counts[name]}" for name in sorted(
        counts, key=lambda n: CHECK_ORDER.get(n, 9)))
    return (f"{len(tasks)} task(s): {parts or '(none)'}\n"
            f"logical workers: {workers}; concurrent network workers: "
            f"{effective_workers(workers, rate)} (one shared budget, total {rate:g} req/s)")
