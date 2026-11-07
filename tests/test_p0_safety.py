"""Regression tests for audit task P0 Part B fixes (F1/F2/F3).

F1 shared global budget, F2 redirect pin, F3 atomic task claims.
All tests are network-free.
"""
import threading
import time

import httpx
import pytest

from bb.auto import AutoHunter, AutoHunterConfig
from bb.http import BudgetExceeded, RequestBudget, ScopedClient
from bb.scope import Scope
from bb.store import Store
from bb.swarm import SwarmExecutor

TARGET = ["lab.example.com"]


def _client(store, handler, scope, shared=None, **kw):
    return ScopedClient(scope, base_url="https://lab.example.com/",
                        transport=httpx.MockTransport(handler), store=store,
                        shared=shared, rate=100.0, **kw)


# ---------- F1: shared global budget ----------

def test_shared_budget_counts_across_clients(store):
    scope = Scope.from_entries("p", TARGET)
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, text="ok")

    budget = RequestBudget(rate=100.0, max_requests=3)
    a = _client(store, handler, scope, shared=budget)
    b = _client(store, handler, scope, shared=budget)
    a.get("/one")
    b.get("/two")
    a.get("/three")
    assert budget.used == 3
    with pytest.raises(BudgetExceeded):
        b.get("/four")
    assert len(seen) == 3            # refused request never touched the transport


def test_shared_budget_deadline_is_collective(store):
    scope = Scope.from_entries("p", TARGET)
    handler = lambda req: httpx.Response(200)
    budget = RequestBudget(rate=100.0, deadline=0.0)   # already in the past
    a = _client(store, handler, scope, shared=budget)
    b = _client(store, handler, scope, shared=budget)
    for c in (a, b):
        with pytest.raises(BudgetExceeded):
            c.get("/x")


def test_unshared_clients_keep_per_client_budgets(store):
    """Default behaviour must be unchanged when no shared budget is passed."""
    scope = Scope.from_entries("p", TARGET)
    handler = lambda req: httpx.Response(200)
    a = _client(store, handler, scope, max_requests=1)
    b = _client(store, handler, scope, max_requests=1)
    a.get("/x")
    with pytest.raises(BudgetExceeded):
        a.get("/y")
    b.get("/x")                      # independent budget, still allowed


def test_auto_phases_share_one_budget(tmp_path, monkeypatch):
    """AutoHunter's recon and investigation clients must share ONE budget."""
    real = ScopedClient
    created = []

    import bb.auto as auto_mod

    def spy(*a, **kw):
        c = real(*a, **kw)
        created.append(c)
        return c

    monkeypatch.setattr(auto_mod, "ScopedClient", spy)
    store = Store(path=tmp_path / "b.db")
    scope = Scope.from_entries("p", TARGET)
    cfg = AutoHunterConfig(program="example", scope=scope,
                           entry_urls=["https://lab.example.com/"], dry_run=True,
                           llm=False, run_waf_probe=False, cve_match=False,
                           ai_analysis=False, queue=False)
    res = AutoHunter(cfg, store=store, log=lambda m: None).run()
    assert res["status"] == "completed"
    assert len(created) >= 2         # recon + investigation clients
    first = created[0].shared
    assert first is not None
    assert all(c.shared is first for c in created), \
        "auto phases must share one RequestBudget"


# ---------- F1 (swarm) + F3 live in their own modules ----------

def test_swarm_workers_share_one_budget(tmp_path, monkeypatch):
    scope = Scope.from_entries("p", TARGET)
    import bb.swarm as swarm_mod

    monkeypatch.setattr(swarm_mod, "Store", lambda: Store(tmp_path / "swarm.db"))
    ex = SwarmExecutor(scope, run_id="r", base_url="https://lab.example.com/",
                       roles=[], options=None,  # options only used by real Checker
                       rate=4.0, max_requests=8, deadline=None)
    c1 = ex._checker()
    ex._local.checker = None         # simulate a second thread's cache miss
    c2 = ex._checker()
    assert c1.client.shared is ex.budget
    assert c2.client.shared is ex.budget
    assert c1.client.shared is c2.client.shared


# ---------- F2: redirects are data, never hops ----------

def test_redirect_follow_is_refused_by_choke_point(store):
    """Even with follow_redirects=True the client must not follow off-scope hops."""
    scope = Scope.from_entries("p", TARGET)
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        if req.url.path == "/redirect":
            return httpx.Response(302, headers={"Location": "https://evil.example/x"})
        return httpx.Response(200, text="evil roped in")

    client = _client(store, handler, scope)
    resp = client.get("/redirect", follow_redirects=True)
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://evil.example/x"
    assert seen == ["https://lab.example.com/redirect"], \
        "the Location host must never be requested"


# ---------- F3: atomic task claims ----------

def _fp(kind, target):
    from bb.swarm import Task
    return Task(kind=kind, target=target).fingerprint


def test_claim_states_reopen_deterministically(tmp_path):
    store = Store(path=tmp_path / "t.db")
    fp = _fp("exposed", "https://t.example/")

    # done tasks re-claim only when they are stale
    assert store.task_claim("exposed", "https://t.example/", fingerprint=fp) is True
    store.task_finish(fp, "done", {"ok": True})
    assert store.task_claim("exposed", "https://t.example/", fingerprint=fp) is False
    time.sleep(1.1)                  # timestamps have 1 s granularity; now the claim is stale
    assert store.task_claim("exposed", "https://t.example/", fingerprint=fp,
                            max_age_hours=0.0) is True
    # failed tasks re-claim until attempts reaches max_attempts (first claim = 1)
    store.task_finish(fp, "failed", {"e": "x"})
    n = 0
    while store.task_claim("exposed", "https://t.example/", fingerprint=fp):
        store.task_finish(fp, "failed", {})
        n += 1
        assert n <= 4
    assert n == 2, f"max_attempts=3 => {n} re-claims after the first"
    row = store.conn.execute(
        "SELECT state, attempts FROM tasks WHERE fingerprint=?", (fp,)).fetchone()
    assert row["state"] == "failed" and row["attempts"] == 3


def test_reclaim_race_has_single_winner(tmp_path):
    """Two processes observing the same stale row must not both resurrect it."""
    db = tmp_path / "race.db"
    seed = Store(path=db)
    fp = _fp("cors", "https://t.example/")
    seed.task_claim("cors", "https://t.example/", fingerprint=fp)
    seed.task_finish(fp, "done", {"old": True})
    time.sleep(1.1)   # 1s timestamp granularity: make staleness unambiguous
    barrier = threading.Barrier(2)
    winners = []

    def racer():
        try:
            s = Store(path=db)
            barrier.wait(timeout=15)
            winners.append(s.task_claim("cors", "https://t.example/", fingerprint=fp,
                                        max_age_hours=0.0))
        except Exception as exc:                      # noqa: BLE001 — surfaced, not swallowed
            winners.append(f"EXC {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=racer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "racer must not hang on contention"
    assert sorted(winners) == [False, True], \
        f"exactly one racer may win the stale re-claim, got {winners}"


def test_fresh_claim_is_atomic_under_contention(tmp_path):
    db = tmp_path / "fresh.db"
    barrier = threading.Barrier(2)
    winners = []

    def racer():
        try:
            s = Store(path=db)
            barrier.wait(timeout=15)
            winners.append(s.task_claim("graphql", "https://t.example/graphql"))
        except Exception as exc:                      # noqa: BLE001 — surfaced, not swallowed
            winners.append(f"EXC {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=racer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "racer must not hang on contention"
    assert sorted(winners) == [False, True]

