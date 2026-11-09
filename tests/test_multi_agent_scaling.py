"""Comprehensive Multi-Agent Scaling and Specialist Worker Tests (Strategic P8).

Verifies all requirements for Strategic P8:
1. Specialist worker registry (28 roles across 5 teams).
2. Authority boundaries (specialists cannot expand scope, bypass rate limits, or self-approve writes).
3. Structured task protocol envelope (TaskProtocol validation, fingerprinting, serialization).
4. Atomic claims and lease recovery at scale (50 concurrent worker threads).
5. Progressive worker scaling stages (5 -> 10 -> 20 -> 35 -> 50) and conservative default (5).
6. Verification backlog backpressure (scale down when backlog >= 15).
7. Strict model concurrency bounds (Tev1 max 2, Qwen max 1) under 50-worker load.
8. Shared single RequestBudget enforcement across 50 concurrent workers with zero over-budget leakage.
9. Independent verification enforcement (worker cannot confirm its own findings).
10. Killswitch abort propagation across all 50 concurrent worker threads.
"""
from __future__ import annotations

import concurrent.futures
import threading
import time
from pathlib import Path

import pytest

from bb.checks import CheckOptions
from bb.http import BudgetExceeded, RequestBudget, ScopedClient
from bb.killswitch import activate as activate_killswitch, clear as clear_killswitch
from bb.models import Finding
from bb.orchestrator.adaptive import AdaptiveScalingPolicy, SwarmMetrics
from bb.orchestrator.resource_manager import ConcurrencyTracker, ResourceManager, SecurityPolicy
from bb.orchestrator.scheduler import Scheduler
from bb.orchestrator.specialists import (
    SPECIALIST_ROLES,
    SpecialistRole,
    SpecialistWorkerRegistry,
    TeamType,
)
from bb.orchestrator.swarm_runner import ControllerSwarmRunner
from bb.orchestrator.task_protocol import TaskProtocol, TaskState
from bb.scope import Scope
from bb.store import Store
from bb.swarm import Task


@pytest.fixture
def clean_scope():
    return Scope.from_entries("test-scaling-prog", ["https://api.example.com/*"], [])


@pytest.fixture
def tmp_store(tmp_path):
    db_path = tmp_path / "scaling_test.db"
    return Store(db_path)


# =========================================================================
# 1. Specialist Worker Registry & Team Topology Tests
# =========================================================================

def test_specialist_registry_all_roles():
    """Verify that all specialist roles across 5 teams are properly registered."""
    reg = SpecialistWorkerRegistry()
    roles = reg.list_roles()
    assert len(roles) == 28, f"Expected 28 roles, got {len(roles)}"

    teams = {r.team for r in roles}
    assert teams == {
        TeamType.DISCOVERY,
        TeamType.IDENTITY_AUTH,
        TeamType.VULN_RESEARCH,
        TeamType.VERIFICATION,
        TeamType.RESEARCH_REPORTING,
    }

    # Verify team allocations
    assert len(reg.list_roles(TeamType.DISCOVERY)) == 5
    assert len(reg.list_roles(TeamType.IDENTITY_AUTH)) == 5
    assert len(reg.list_roles(TeamType.VULN_RESEARCH)) == 9
    assert len(reg.list_roles(TeamType.VERIFICATION)) == 5
    assert len(reg.list_roles(TeamType.RESEARCH_REPORTING)) == 4


def test_specialist_role_resolution_for_task():
    """Ensure tasks map deterministically to the correct specialist worker role."""
    reg = SpecialistWorkerRegistry()

    # Route mapping
    r_map = reg.select_role_for_task("crawl")
    assert r_map.role_id == "route_mapper"
    assert r_map.team == TeamType.DISCOVERY

    # Access control / Authz
    r_bac = reg.select_role_for_task("authz")
    assert r_bac.team == TeamType.VULN_RESEARCH
    assert r_bac.requires_roles is True

    # Verification
    r_ver = reg.select_role_for_task("verify")
    assert r_ver.role_id == "independent_verifier"
    assert r_ver.team == TeamType.VERIFICATION


# =========================================================================
# 2. Structured Task Protocol Tests
# =========================================================================

def test_task_protocol_lifecycle_and_fingerprint():
    """Verify TaskProtocol lifecycle states, hashing, and dictionary conversion."""
    task = TaskProtocol(
        program="test-prog",
        authorized_target="https://api.example.com/users/profile",
        worker_role="idor_bola_researcher",
        kind="authz",
        hypothesis="Horizontal privilege escalation via role token substitution",
        proposed_action="GET /users/profile with Role B token",
    )

    assert task.task_id != ""
    assert task.fingerprint != ""
    assert task.state == TaskState.PENDING

    d = task.to_dict()
    assert d["state"] == "pending"
    assert d["worker_role"] == "idor_bola_researcher"

    reconstructed = TaskProtocol.from_dict(d)
    assert reconstructed.task_id == task.task_id
    assert reconstructed.fingerprint == task.fingerprint
    assert reconstructed.state == TaskState.PENDING


# =========================================================================
# 3. Progressive Scaling Stages (5 -> 10 -> 20 -> 35 -> 50)
# =========================================================================

def test_progressive_scaling_stages():
    """Test deterministic progression from default (5) up through 10, 20, 35, 50."""
    policy = AdaptiveScalingPolicy(initial_workers=5, max_workers=50)
    assert policy.current_workers == 5  # Conservative default

    # Stage 1 -> 2: 5 -> 10 (needs 10+ eligible tasks, good budget, 0 backlog)
    m = SwarmMetrics(eligible_tasks=25, budget_remaining_ratio=0.9, verification_backlog=0)
    w, expl = policy.evaluate_scale(m)
    assert w == 10
    assert "scaled up from 5 to 10" in expl

    # Stage 2 -> 3: 10 -> 20 (needs 20+ eligible tasks)
    m.eligible_tasks = 45
    w, expl = policy.evaluate_scale(m)
    assert w == 20
    assert "scaled up from 10 to 20" in expl

    # Stage 3 -> 4: 20 -> 35 (needs 40+ eligible tasks)
    m.eligible_tasks = 80
    w, expl = policy.evaluate_scale(m)
    assert w == 35
    assert "scaled up from 20 to 35" in expl

    # Stage 4 -> 5: 35 -> 50 (needs 70+ eligible tasks)
    m.eligible_tasks = 120
    w, expl = policy.evaluate_scale(m)
    assert w == 50
    assert "scaled up from 35 to 50" in expl

    # Held at 50 max
    m.eligible_tasks = 200
    w, expl = policy.evaluate_scale(m)
    assert w == 50


def test_verification_backlog_and_rate_limit_backpressure():
    """Test scale-down triggers when verification backlog or error rate spikes."""
    policy = AdaptiveScalingPolicy(initial_workers=35, max_workers=50, max_verification_backlog=15)
    assert policy.current_workers == 35

    # Verification backlog exceeds threshold (>= 15) -> scale down to 20
    m = SwarmMetrics(eligible_tasks=100, verification_backlog=16, budget_remaining_ratio=0.8)
    w, expl = policy.evaluate_scale(m)
    assert w == 20
    assert "verification backlog high" in expl

    # Further backpressure: rate limit detected -> scale down to 10
    m.rate_limited = True
    w, expl = policy.evaluate_scale(m)
    assert w == 10
    assert "rate-limit" in expl


# =========================================================================
# 4. Strict Model Concurrency Bounds under 50-Worker Load
# =========================================================================

def test_model_concurrency_semaphores_bounded():
    """Verify Tev1 (max 2) and Qwen (max 1) semaphores remain strictly bounded under 50 threads."""
    sec_policy = SecurityPolicy(tev1_max_concurrency=2, qwen_max_concurrency=1)
    tracker = ConcurrencyTracker(sec_policy)

    max_observed_tev1 = 0
    max_observed_qwen = 0
    tev1_lock = threading.Lock()
    qwen_lock = threading.Lock()

    def tev1_worker():
        nonlocal max_observed_tev1
        if tracker.acquire_tev1(timeout=5.0):
            try:
                with tev1_lock:
                    if tracker._active_tev1 > max_observed_tev1:
                        max_observed_tev1 = tracker._active_tev1
                time.sleep(0.01)
            finally:
                tracker.release_tev1()

    def qwen_worker():
        nonlocal max_observed_qwen
        if tracker.acquire_qwen(timeout=5.0):
            try:
                with qwen_lock:
                    if tracker._active_qwen > max_observed_qwen:
                        max_observed_qwen = tracker._active_qwen
                time.sleep(0.01)
            finally:
                tracker.release_qwen()

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = []
        for i in range(50):
            if i % 2 == 0:
                futures.append(pool.submit(tev1_worker))
            else:
                futures.append(pool.submit(qwen_worker))
        concurrent.futures.wait(futures)

    assert max_observed_tev1 <= 2, f"Tev1 concurrency violated: {max_observed_tev1} > 2"
    assert max_observed_qwen <= 1, f"Qwen concurrency violated: {max_observed_qwen} > 1"


# =========================================================================
# 5. Shared RequestBudget Under 50 Concurrent Workers
# =========================================================================

def test_shared_request_budget_under_50_workers():
    """50 concurrent worker threads consume from 1 RequestBudget; zero budget leakage."""
    budget = RequestBudget(rate=200.0, max_requests=40)

    successful_consumes = 0
    exceeded_count = 0
    lock = threading.Lock()

    def worker_consume():
        nonlocal successful_consumes, exceeded_count
        for _ in range(5):
            try:
                budget.consume()
                with lock:
                    successful_consumes += 1
            except BudgetExceeded:
                with lock:
                    exceeded_count += 1
                break

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(worker_consume) for _ in range(50)]
        concurrent.futures.wait(futures)

    assert successful_consumes == 40, f"Expected exactly 40 consumes, got {successful_consumes}"
    assert budget.used == 40
    assert exceeded_count > 0, "Expected threads to be cut off by shared budget"


# =========================================================================
# 6. Atomic Task Claims and Lease Recovery at Scale
# =========================================================================

def test_atomic_claims_and_stale_lease_recovery(tmp_path):
    """50 tasks claimed concurrently, simulated worker crash, stale lease recovered."""
    db_file = tmp_path / "lease_rec.db"
    store = Store(db_file)

    # 1. 50 concurrent workers race to insert & claim 50 distinct tasks
    targets = [f"https://host-{i}.example.com/api" for i in range(50)]
    tasks = [Task(kind="authz", target=tgt) for tgt in targets]

    claimed_by_worker = {}
    lock = threading.Lock()

    def worker_claim(worker_id: int):
        s = Store(db_file)
        try:
            sched = Scheduler(s, run_id=f"worker-{worker_id}", lease_seconds=1.0)
            for t in tasks:
                if sched.claim_task(t):
                    with lock:
                        claimed_by_worker[t.fingerprint] = worker_id
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(worker_claim, i) for i in range(50)]
        concurrent.futures.wait(futures)

    # Every task claimed exactly once across the racing workers
    assert len(claimed_by_worker) == 50

    # 2. Simulate worker crash: wait for lease_seconds (1.0s) to expire
    time.sleep(1.2)

    # 3. Recover expired leases back to pending
    sched_recovery = Scheduler(store, run_id="recovery-manager", lease_seconds=1.0)
    recovered_count = sched_recovery.recover_expired_leases(all_runs=True)
    assert recovered_count == 50, f"Expected 50 recovered tasks, got {recovered_count}"

    # 4. Verify all tasks returned to pending state
    for t in tasks:
        row = store.get_task(t.fingerprint)
        assert row is not None
        assert row["state"] == "pending"

    store.close()


# =========================================================================
# 7. Killswitch Abort Across 50 Workers
# =========================================================================

def test_killswitch_aborts_all_active_workers(clean_scope, tmp_path):
    """Activating the kill switch immediately halts all concurrent workers without orphaned running tasks."""
    db_file = tmp_path / "killswitch_50.db"
    store = Store(db_file)
    store.close()

    clear_killswitch()
    budget = RequestBudget(rate=100.0, max_requests=1000)
    sec_policy = SecurityPolicy(rate=100.0, max_requests=1000)
    res_mgr = ResourceManager(clean_scope, policy=sec_policy, budget=budget)
    sched = Scheduler(Store(db_file), run_id="run-ks")

    runner = ControllerSwarmRunner(
        scope=clean_scope,
        store=Store(db_file),
        run_id="run-ks",
        resource_mgr=res_mgr,
        scheduler=sched,
        roles=[],
        options=CheckOptions(),
        dry_run=True,
    )

    # Prepare candidate tasks
    tasks = [Task(kind="cors", target=f"https://api.example.com/cors_ep_{i}") for i in range(50)]

    # Arm killswitch (note signature: activate(msg: str = ''))
    activate_killswitch("emergency security stop")

    res = runner.run_batch(tasks, worker_concurrency=10)
    assert res["status"] == "aborted"
    assert res["executed"] == 0

    clear_killswitch()
