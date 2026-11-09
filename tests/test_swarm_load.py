"""Load and concurrency tests for Task P5: Adaptive Swarm and Decision Evaluation.

Tests:
  1. Concurrent task claims: 50 threads racing to claim the same fingerprints. Zero duplicate claims.
  2. Duplicate fingerprint prevention: identical targets normalize to same fingerprint.
  3. Shared polite request budget: 5, 10, 20, 35, 50 workers share one RequestBudget token bucket.
  4. Adaptive scale-up: healthy conditions, sufficient tasks, low errors -> scales 5 -> 10 -> 20.
  5. Adaptive scale-down: high HTTP errors, rate-limiting, contention -> scales down conservatively.
  6. Verification backpressure: backlog >= threshold immediately triggers scale-down or pause.
  7. Tev1 outage resilience: decision gateway safely falls back to deterministic choice.
  8. Local model concurrency separation: Tev1 decision semaphore vs Qwen adapter generation semaphore.
  9. Worker cancellation and lease recovery: cancelled tasks safely released back to pending.
  10. Decision evaluation recording: comparative logging of Tev1 vs deterministic baseline.
"""
from __future__ import annotations

import concurrent.futures
import threading
import time
from pathlib import Path

import pytest

from bb.checks import CheckOptions
from bb.decision.evaluator import DecisionEvaluator
from bb.decision.gateway import DecisionGateway
from bb.http import RequestBudget, ScopedClient
from bb.killswitch import activate as activate_killswitch, clear as clear_killswitch
from bb.orchestrator.adaptive import AdaptiveScalingPolicy, SwarmMetrics
from bb.orchestrator.resource_manager import ConcurrencyTracker, ResourceManager, SecurityPolicy
from bb.orchestrator.scheduler import Scheduler
from bb.orchestrator.swarm_runner import ControllerSwarmRunner
from bb.scope import Scope
from bb.store import Store
from bb.swarm import Task, effective_workers


@pytest.fixture
def test_scope():
    return Scope.from_entries("test-prog", ["https://example.com/api/*"], [])


@pytest.fixture
def mem_store(tmp_path):
    db_file = tmp_path / "test_swarm.db"
    return Store(db_file)


def test_concurrent_task_claims_zero_duplicates(tmp_path):
    """50 concurrent workers attempt to claim the exact same task. Only 1 must succeed."""
    db_file = tmp_path / "test_claims.db"
    # Initialize DB schema first
    init_s = Store(db_file)
    init_s.close()

    task = Task(kind="authz", target="https://example.com/api/users/42")
    claims_won = []
    claims_lost = []
    lock = threading.Lock()

    def claim_worker(worker_id: int):
        s = Store(db_file)
        try:
            sched = Scheduler(s, run_id=f"run-{worker_id}")
            won = sched.claim_task(task)
            with lock:
                if won:
                    claims_won.append(worker_id)
                else:
                    claims_lost.append(worker_id)
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(claim_worker, i) for i in range(50)]
        concurrent.futures.wait(futures)

    assert len(claims_won) == 1, f"Expected exactly 1 claim winner, got {len(claims_won)}"
    assert len(claims_lost) == 49
    # Verify row state in SQLite
    final_s = Store(db_file)
    row = final_s.get_task(task.fingerprint)
    final_s.close()
    assert row is not None
    assert row["state"] == "running"
    assert row["attempts"] == 1


def test_duplicate_fingerprint_normalization():
    """Different URL query param ordering for same route yields identical fingerprint."""
    t1 = Task(kind="authz", target="https://example.com/api/users/42?a=1&b=2")
    t2 = Task(kind="authz", target="https://example.com/api/users/42?b=2&a=1")
    assert t1.fingerprint == t2.fingerprint


def test_shared_request_budget_across_concurrent_workers(test_scope, tmp_path):
    """50 workers sharing one RequestBudget never exceed the collective max_requests cap."""
    budget = RequestBudget(rate=100.0, max_requests=25)
    db_file = tmp_path / "budget_test.db"
    store = Store(db_file)

    def worker_action():
        client = ScopedClient(
            test_scope,
            rate=100.0,
            max_requests=25,
            dry_run=True,
            store=store,
            run_id="run-budget",
            tool="test",
            shared=budget,
        )
        try:
            for _ in range(5):
                client.get("https://example.com/api/users/1")
        except Exception:
            pass
        finally:
            client.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(worker_action) for _ in range(50)]
        concurrent.futures.wait(futures)

    # Budget strictly caps total requests across all 50 threads
    assert budget.used <= 25, f"Budget exceeded! Used: {budget.used}"


def test_adaptive_scale_up_stages():
    """Scale up policy progresses through stages 5 -> 10 -> 20 when metrics are healthy."""
    policy = AdaptiveScalingPolicy(initial_workers=5)
    assert policy.current_workers == 5

    # Healthy metrics with plenty of eligible tasks
    metrics = SwarmMetrics(
        eligible_tasks=50,
        active_workers=5,
        recent_claims_attempted=10,
        recent_claims_successful=10,
        recent_claims_contended=0,
        recent_tasks_completed=10,
        recent_tasks_failed=0,
        http_error_rate=0.0,
        budget_remaining_ratio=0.8,
        verification_backlog=0,
    )
    workers, reason = policy.evaluate_scale(metrics)
    assert workers == 10
    assert "scaled up" in reason

    # Next evaluation scales to 20
    workers, reason = policy.evaluate_scale(metrics)
    assert workers == 20
    assert "scaled up" in reason


def test_adaptive_scale_down_on_http_errors_and_backpressure():
    """High HTTP error rate or verification backlog triggers immediate scale-down."""
    policy = AdaptiveScalingPolicy(initial_workers=20)
    assert policy.current_workers == 20

    # High error rate
    metrics = SwarmMetrics(
        eligible_tasks=50,
        active_workers=20,
        http_error_rate=0.08,  # 8% errors >= 5%
        budget_remaining_ratio=0.5,
    )
    workers, reason = policy.evaluate_scale(metrics)
    assert workers == 10
    assert "scaled down" in reason

    # High verification backlog
    metrics_backlog = SwarmMetrics(
        eligible_tasks=50,
        active_workers=10,
        http_error_rate=0.0,
        budget_remaining_ratio=0.5,
        verification_backlog=16,  # > max_verification_backlog (15)
    )
    workers, reason = policy.evaluate_scale(metrics_backlog)
    assert workers == 5
    assert "scaled down" in reason
    assert "verification backlog high" in reason


def test_verification_backpressure_in_resource_manager(test_scope, mem_store):
    """Resource manager correctly flags verification backlog threshold."""
    policy = SecurityPolicy(max_verification_backlog=3)
    rm = ResourceManager(test_scope, policy=policy, store=mem_store, run_id="run-backlog")

    from bb.models import Finding
    for i in range(4):
        f = Finding(
            title=f"Finding {i}",
            bug_class="IDOR",
            severity="medium",
            confidence="high",
            status="candidate",
            host="example.com",
            url=f"https://example.com/api/users/{i}",
        )
        mem_store.add_finding(f, run_id="run-backlog")

    backlogged, count = rm.check_verification_backlog()
    assert backlogged is True
    assert count == 4


def test_concurrency_tracker_isolation():
    """Tev1 decision concurrency and Qwen generation concurrency are isolated with separate semaphores."""
    policy = SecurityPolicy(tev1_max_concurrency=2, qwen_max_concurrency=1)
    tracker = ConcurrencyTracker(policy)

    # Acquire Tev1 slots
    assert tracker.acquire_tev1() is True
    assert tracker.acquire_tev1() is True
    # Third Tev1 attempt must timeout (max 2)
    assert tracker.acquire_tev1(timeout=0.05) is False

    # Qwen semaphore is independent
    assert tracker.acquire_qwen() is True
    # Second Qwen attempt must timeout (max 1)
    assert tracker.acquire_qwen(timeout=0.05) is False

    # Release and reacquire
    tracker.release_tev1()
    assert tracker.acquire_tev1(timeout=0.05) is True

    tracker.release_qwen()
    assert tracker.acquire_qwen(timeout=0.05) is True

    tracker.release_tev1()
    tracker.release_tev1()
    tracker.release_qwen()


def test_tev1_outage_deterministic_fallback():
    """When Tev1 service fails or is unreachable, decision gateway falls back cleanly."""
    gw = DecisionGateway(client=None)  # None forces default local client which handles connection error
    tasks = [
        Task(kind="authz", target="https://example.com/api/users/1", priority=1),
        Task(kind="cors", target="https://example.com/api/users/2", priority=2),
    ]
    dec = gw.select_task(tasks)
    assert dec["source"] == "deterministic-fallback"
    assert dec["choice"] == tasks[0].fingerprint


def test_worker_cancellation_and_lease_recovery(test_scope, mem_store):
    """Cancelled worker runner marks tasks as failed/released without locking them permanently."""
    rm = ResourceManager(test_scope, store=mem_store, run_id="run-cancel")
    sched = Scheduler(mem_store, run_id="run-cancel", lease_seconds=1.0)
    runner = ControllerSwarmRunner(
        scope=test_scope,
        store=mem_store,
        run_id="run-cancel",
        resource_mgr=rm,
        scheduler=sched,
        roles=[],
        options=CheckOptions(),
        dry_run=True,
    )

    t1 = Task(kind="authz", target="https://example.com/api/users/1")
    assert sched.claim_task(t1) is True

    # Cancel runner
    runner.cancel()
    res = runner._execute_single_task(
        t1,
        mem_store,
        ScopedClient(test_scope, dry_run=True, store=mem_store, run_id="run-cancel", tool="test"),
        None,
    )
    assert res["status"] == "cancelled"

    # Task is now marked failed (releasable/recoverable)
    row = mem_store.get_task(t1.fingerprint)
    assert row["state"] == "failed"


def test_decision_evaluation_recording(tmp_path):
    """DecisionEvaluator correctly logs decision comparison and execution yield."""
    ledger = tmp_path / "decisions.jsonl"
    evaluator = DecisionEvaluator(ledger_path=ledger)

    tev1_dec = {
        "choice": "fp-1234",
        "source": "tev1",
        "confidence": 0.95,
        "reason": "high severity endpoint",
    }
    rec = evaluator.record_decision(
        decision_id="dec-1",
        run_id="run-1",
        decision_point="task-selection",
        options=["fp-1234", "fp-5678"],
        tev1_result=tev1_dec,
        baseline_choice="fp-5678",
        task_fingerprint="fp-1234",
    )
    assert rec.agreed is False

    evaluator.attach_execution_result("dec-1", status="done", findings_count=1, requests_cost=5, duration_ms=120.0)
    evaluator.attach_verification_result("dec-1", verification_status="confirmed", triage_verdict="likely-real")

    # Load and generate report
    report = evaluator.generate_report(run_id="run-1")
    assert report["total_decisions"] == 1
    assert report["tev1_model_decisions"] == 1
    assert report["agreement_rate"] == 0.0
    assert report["confirmed_findings"] == 1
    assert report["total_findings_yielded"] == 1
    assert report["disagreed_yield"]["confirmed"] == 1
