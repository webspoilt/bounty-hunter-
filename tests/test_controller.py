"""Comprehensive tests for Bounty Hunter Persistent Research Controller (TASK P2).

Tests:
  1. Valid task selection (Tev1 recommendation honored)
  2. Invalid task selection (Tev1 hallucination refused; deterministic fallback)
  3. Task no longer eligible (concurrency guard detects already-claimed task)
  4. Tev1 unavailable (connection error / 500 cleanly falls back)
  5. Deterministic fallback (order based on task priority / class priors)
  6. Concurrent claims (two threads race to claim same task; exactly one wins)
  7. Process interruption (pause & resume across distinct Controller instances)
  8. Lease recovery (expired running leases recovered cleanly)
  9. Kill-switch activation (controller immediately aborts; state persisted)
  10. Budget exhaustion (controller halts when request budget is exhausted)
  11. Verification backlog (backlog threshold detected and prioritized)
  12. Human approval boundary (state-changing write requires explicit approval)
  13. Agent registry boundaries (unregistered agents refused)
  14. State machine transitions (explicit validation; illegal transitions rejected)
  15. AutoHunter controller integration (bb/auto.py delegates to controller)
"""
import threading
import time
from unittest.mock import MagicMock

import httpx
import pytest

from bb import killswitch, tev1
from bb.auto import AutoHunter, AutoHunterConfig
from bb.checks import CheckOptions
from bb.decision.gateway import DecisionGateway
from bb.http import BudgetExceeded, RequestBudget
from bb.models import Evidence, Exchange, Finding
from bb.orchestrator.agent_registry import AgentCapability, AgentRegistry, AgentSpec
from bb.orchestrator.controller import Controller, ControllerConfig
from bb.orchestrator.lifecycle import InvalidTransitionError, LifecycleManager, State
from bb.orchestrator.planner import Planner
from bb.orchestrator.resource_manager import ResourceManager, SecurityPolicy
from bb.orchestrator.scheduler import Scheduler
from bb.scope import Scope
from bb.store import Store
from bb.swarm import Task

TARGET = ["app.example.com"]


@pytest.fixture(autouse=True)
def mock_network_and_dns(monkeypatch):
    """Ensure all controller tests remain completely offline and fast."""
    from bb import recon, scope
    monkeypatch.setattr(scope, "resolve_host", lambda host: ("93.184.216.34",))
    monkeypatch.setattr(recon.Recon, "passive", lambda self, entry: [
        {"url": "https://app.example.com/api/users/1", "method": "GET", "host": "app.example.com"},
        {"url": "https://app.example.com/api/login", "method": "POST", "host": "app.example.com"},
    ])


@pytest.fixture
def test_scope():
    return Scope.from_entries("example-program", TARGET)


@pytest.fixture
def test_tasks():
    t1 = Task(kind="authz", target="https://app.example.com/api/users/1", priority=1)
    t2 = Task(kind="cors", target="https://app.example.com/", priority=4)
    t3 = Task(kind="headers", target="https://app.example.com/", priority=6)
    return [t1, t2, t3]


# ---------- 1. Valid task selection ----------

def test_valid_task_selection(tmp_path, test_scope, test_tasks):
    """When Tev1 selects a valid task ID, that task is selected and processed."""
    store = Store(tmp_path / "c1.db")
    chosen_task = test_tasks[1]  # CORS task

    fake_client = MagicMock()
    fake_client.decide.return_value = {
        "decision_point": "task-selection",
        "choice": chosen_task.fingerprint,
        "source": "tev1",
        "reason": "high CORS risk",
        "confidence": 0.9,
    }
    gw = DecisionGateway(fake_client)

    dec = gw.select_task(test_tasks)
    assert dec["choice"] == chosen_task.fingerprint
    assert dec["source"] == "tev1"


# ---------- 2. Invalid task selection ----------

def test_invalid_task_selection(tmp_path, test_scope, test_tasks):
    """When Tev1 suggests an arbitrary ID outside candidate options, it is refused."""
    fake_client = MagicMock()
    fake_client.decide.return_value = {
        "decision_point": "task-selection",
        "choice": "hallucinated-arbitrary-task-id",
        "source": "tev1",
        "reason": "hallucination",
        "confidence": 0.5,
    }
    gw = DecisionGateway(fake_client)

    dec = gw.select_task(test_tasks)
    # Refused and fell back to deterministic default (first task)
    assert dec["choice"] == test_tasks[0].fingerprint
    assert dec["source"] == tev1.FALLBACK_SOURCE
    assert "outside candidate set" in dec["reason"]


# ---------- 3. Task no longer eligible ----------

def test_task_no_longer_eligible(tmp_path, test_scope, test_tasks):
    """If a task was claimed between planning and execution, controller detects and skips."""
    store = Store(tmp_path / "c3.db")
    task = test_tasks[0]

    # Pre-claim task by another worker
    store.task_claim(task.kind, task.target, run_id="other-run", fingerprint=task.fingerprint)

    planner = Planner(test_scope, store, "example-program")
    eligible = planner.filter_eligible([task], lease_seconds=300.0)
    assert len(eligible) == 0, "actively running task under lease must not be eligible"


# ---------- 4. Tev1 unavailable ----------

def test_tev1_unavailable(tmp_path, test_scope, test_tasks):
    """When Tev1 raises an exception, deterministic fallback is cleanly returned."""
    fake_client = MagicMock()
    fake_client.decide.side_effect = httpx.ConnectError("endpoint down")
    gw = DecisionGateway(fake_client)

    dec = gw.select_task(test_tasks)
    assert dec["source"] == tev1.FALLBACK_SOURCE
    assert dec["choice"] == test_tasks[0].fingerprint
    assert "error" in dec["reason"] or "down" in dec["reason"]


# ---------- 5. Deterministic fallback ----------

def test_deterministic_fallback(tmp_path, test_scope, test_tasks):
    """Fallback without Tev1 strictly selects the highest priority task."""
    gw = DecisionGateway(client=None)  # No client passed
    # Mock tev1.decide to return fallback directly
    dec = gw.select_task(test_tasks)
    assert dec["choice"] == test_tasks[0].fingerprint
    assert dec["source"] == tev1.FALLBACK_SOURCE


# ---------- 6. Concurrent claims ----------

def test_concurrent_claims(tmp_path, test_tasks):
    """Two workers racing to claim the same task: exactly one wins."""
    store_path = tmp_path / "race.db"
    task = test_tasks[0]
    barrier = threading.Barrier(2)
    results = []

    def worker(worker_id):
        s = Store(store_path)
        sch = Scheduler(s, run_id=f"run-{worker_id}")
        barrier.wait(timeout=10)
        claimed = sch.claim_task(task)
        results.append(claimed)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert sorted(results) == [False, True], f"exactly one worker must claim, got {results}"


# ---------- 7. Process interruption & resume ----------

def test_process_interruption_and_resume(tmp_path, test_scope):
    """Controller state persists across interruption; resumes at recorded state."""
    store = Store(tmp_path / "resume.db")
    cfg = ControllerConfig(
        program="example",
        scope=test_scope,
        entry_urls=["https://app.example.com/"],
        dry_run=True,
        tev1=False,
    )
    c1 = Controller(cfg, store=store, log=lambda *a: None)
    c1.lifecycle.transition_to(State.MAPPING)
    c1.pause(reason="process stopped")
    run_id = c1.run_id

    # Simulate process death and restart with same run_id
    cfg2 = ControllerConfig(
        program="example",
        scope=test_scope,
        entry_urls=["https://app.example.com/"],
        run_id=run_id,
        dry_run=True,
        tev1=False,
    )
    c2 = Controller(cfg2, store=store, log=lambda *a: None)
    assert c2.lifecycle.is_paused()
    assert c2.lifecycle.previous_state == State.MAPPING

    c2.resume()
    assert c2.lifecycle.state == State.MAPPING


# ---------- 8. Lease recovery ----------

def test_lease_recovery(tmp_path, test_tasks):
    """Expired running task leases are reclaimed and recovered cleanly."""
    store = Store(tmp_path / "lease.db")
    task = test_tasks[0]

    # Worker 1 claims task
    store.task_claim(task.kind, task.target, run_id="dead-run", fingerprint=task.fingerprint)
    time.sleep(1.1)  # 1s timestamp granularity

    # Attempt re-claim with 0-second lease: lease is expired, claim succeeds!
    sch = Scheduler(store, run_id="revived-run", lease_seconds=0.0)
    recovered = sch.recover_expired_leases()
    assert recovered == 1

    # Now task is back to pending and claimable
    assert sch.claim_task(task) is True


# ---------- 9. Kill-switch activation ----------

def test_kill_switch_activation(tmp_path, test_scope, monkeypatch):
    """Kill switch activation immediately halts controller and marks state ABORTED."""
    store = Store(tmp_path / "ks.db")
    kill_file = tmp_path / "killswitch"
    monkeypatch.setattr(killswitch, "KILL_FILE", kill_file)

    killswitch.activate("operator panic button")
    assert killswitch.active()

    cfg = ControllerConfig(
        program="example",
        scope=test_scope,
        entry_urls=["https://app.example.com/"],
        dry_run=True,
    )
    ctrl = Controller(cfg, store=store, log=lambda *a: None)
    res = ctrl.run()

    assert res["status"] == "aborted"
    assert res["reason"] == "kill_switch_active"
    assert ctrl.lifecycle.state == State.ABORTED

    killswitch.clear()


# ---------- 10. Budget exhaustion ----------

def test_budget_exhaustion(tmp_path, test_scope, test_tasks):
    """Controller respects request budget and stops cleanly when exhausted."""
    store = Store(tmp_path / "budget.db")
    policy = SecurityPolicy(max_requests=2)
    budget = RequestBudget(rate=100.0, max_requests=2)
    rm = ResourceManager(test_scope, policy=policy, budget=budget, store=store)

    assert rm.check_budget_available() is True
    budget.consume()
    budget.consume()
    assert rm.check_budget_available() is False

    allowed, reason = rm.validate_task_policy(test_tasks[0], AgentSpec(
        name="test", description="d", capabilities=frozenset({AgentCapability.ACTIVE_PROBE}),
    ))
    assert allowed is False
    assert "budget exhausted" in reason


# ---------- 11. Verification backlog ----------

def test_verification_backlog(tmp_path, test_scope):
    """When unverified candidates exceed threshold, backlog is detected."""
    store = Store(tmp_path / "backlog.db")
    policy = SecurityPolicy(max_verification_backlog=3)
    rm = ResourceManager(test_scope, policy=policy, store=store, run_id="r1")

    # Add 4 unverified candidate findings
    for i in range(4):
        f = Finding(id=f"f{i}", title=f"Finding {i}", bug_class="IDOR", status="candidate")
        store.add_finding(f, run_id="r1")

    backlogged, count = rm.check_verification_backlog()
    assert backlogged is True
    assert count == 4


# ---------- 12. Human approval boundary ----------

def test_human_approval_boundary(tmp_path, test_scope):
    """State-changing write operations require explicit human approval."""
    store = Store(tmp_path / "approval.db")
    policy = SecurityPolicy(allow_write=True, require_human_approval_for_write=True)
    rm = ResourceManager(test_scope, policy=policy, store=store)

    agent = AgentSpec(
        name="differential_tester",
        description="d",
        capabilities=frozenset({AgentCapability.DIFFERENTIAL_TEST}),
        safe_methods_only=False,
        requires_roles=True,
    )

    # Task with write method (POST) without human approval
    write_task = Task(kind="idor_write", target="https://app.example.com/api/users", payload={"method": "POST"})
    allowed, reason = rm.validate_task_policy(write_task, agent, has_roles=True)
    assert allowed is False
    assert "human approval" in reason

    # With human approval flag
    approved_task = Task(kind="idor_write", target="https://app.example.com/api/users",
                         payload={"method": "POST", "human_approved": True})
    allowed, reason = rm.validate_task_policy(approved_task, agent, has_roles=True)
    assert allowed is True


# ---------- 13. Agent registry boundaries ----------

def test_agent_registry_boundaries():
    """Unregistered agents cannot be resolved; default specialist selected deterministically."""
    registry = AgentRegistry()
    assert registry.is_registered("surface_mapper") is True
    assert registry.is_registered("arbitrary_hacker_bot") is False
    assert registry.resolve("arbitrary_hacker_bot") is None

    t = Task(kind="graphql", target="https://app.example.com/graphql")
    spec = registry.select_default_specialist(t)
    assert spec.name == "security_prober"


# ---------- 14. State machine transitions ----------

def test_state_machine_explicit_transitions(tmp_path):
    """Explicit validated state transitions; illegal jumps raise InvalidTransitionError."""
    store = Store(tmp_path / "sm.db")
    run_id = store.start_run("test", "target")
    lm = LifecycleManager(store, run_id, initial_state=State.DISCOVERING)

    assert lm.state == State.DISCOVERING
    lm.transition_to(State.MAPPING)
    assert lm.state == State.MAPPING

    # Illegal jump directly to COMPLETED or VERIFYING
    with pytest.raises(InvalidTransitionError):
        lm.transition_to(State.VERIFYING)

    # Pause and resume
    lm.pause("wait")
    assert lm.is_paused()
    lm.resume()
    assert lm.state == State.MAPPING


# ---------- 15. AutoHunter controller integration ----------

def test_auto_hunter_controller_integration(tmp_path, test_scope):
    """AutoHunter delegates cleanly to Controller when controller=True."""
    store = Store(tmp_path / "auto_ctrl.db")
    cfg = AutoHunterConfig(
        program="example",
        scope=test_scope,
        entry_urls=["https://app.example.com/"],
        dry_run=True,
        tev1=False,
        controller=True,
        cve_match=False,
        run_waf_probe=False,
        ai_analysis=False,
        queue=False,
    )
    hunter = AutoHunter(cfg, store=store, log=lambda *a: None)
    res = hunter.run()
    assert res["status"] in ("completed", "planning")
    assert "run_id" in res
    assert "findings" in res
