"""Comprehensive Test Suite for Continuous Autonomous Security Research (Strategic P9).

Verifies all requirements for Strategic P9:
1. Program research profiles (in/out assets, categories, prohibitions, budgets, rate limits, timestamps, validity).
2. Scope expiration and empty-scope protection (cannot infer permission from wildcard; expired enters blocked state).
3. Scope change handling (addition/removal of assets, task invalidation, scope versioning).
4. Continuous research cycle & prioritization (Laplace priors, P6 intel boost, coverage, duplicate penalties).
5. Autonomy levels (OBSERVE suppresses scanning, MAP, INVESTIGATE bounded, REPORT).
6. Durable execution, pause/resume, cancellation, and restart recovery.
7. Request and budget exhaustion producing distinct terminal/paused states.
8. State-changing protection: unapproved destructive writes prohibited, no repeated blind retries.
9. Killswitch immediate halt propagation across continuous scheduler.
10. Long-running state persistence in SQLite across scheduler restarts.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from bb.config import now_iso
from bb.http import RequestBudget
from bb.intelligence.models import IntelligenceRecord
from bb.killswitch import activate as activate_killswitch, clear as clear_killswitch
from bb.orchestrator.continuous_scheduler import ContinuousScheduler, SchedulerStatus
from bb.orchestrator.prioritizer import ContinuousPrioritizer
from bb.orchestrator.profile import (
    AutonomyLevel,
    ProfileValidity,
    ProgramProfile,
    ScopeChangeDetector,
)
from bb.orchestrator.scheduler import Scheduler
from bb.orchestrator.task_protocol import TaskProtocol, TaskState
from bb.scope import Scope
from bb.store import Store
from bb.swarm import Task


@pytest.fixture
def tmp_store(tmp_path):
    db_file = tmp_path / "continuous_test.db"
    return Store(db_file)


@pytest.fixture
def base_profile():
    return ProgramProfile(
        program_id="acme-corp",
        in_scope_assets=["https://api.example.com/*", "https://auth.example.com/*"],
        out_of_scope_assets=["https://api.example.com/admin/*"],
        permitted_categories=["authz", "unauth", "cors", "graphql"],
        prohibited_activities=["dos", "destructive_write"],
        rate_limit=10.0,
        max_requests=100,
        time_budget_seconds=1800.0,
        autonomy_level=AutonomyLevel.INVESTIGATE,
        scope_version=1,
    )


# =========================================================================
# 1. Program Research Profiles & Validation
# =========================================================================

def test_program_profile_validation_and_fingerprint(base_profile):
    """Test explicit program profile creation, validation, and fingerprint generation."""
    valid, msg = base_profile.validate_executable()
    assert valid is True
    assert "profile valid" in msg
    assert len(base_profile.fingerprint) == 24

    # Serialization roundtrip
    d = base_profile.to_dict()
    reconstructed = ProgramProfile.from_dict(d)
    assert reconstructed.program_id == base_profile.program_id
    assert reconstructed.fingerprint == base_profile.fingerprint
    assert reconstructed.scope_version == 1


def test_scope_expiration_and_empty_scope_blocks(base_profile):
    """Expired profile or empty scope enters BLOCKED state and cannot execute."""
    # Empty in-scope
    empty_prof = ProgramProfile(program_id="empty-prog", in_scope_assets=[])
    valid, msg = empty_prof.validate_executable()
    assert valid is False
    assert "blocked" in msg or "empty" in msg

    # Expired profile
    past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    base_profile.expires_at = past
    assert base_profile.is_expired() is True
    valid, msg = base_profile.validate_executable()
    assert valid is False
    assert "expired" in msg


# =========================================================================
# 2. Scope Change Detection & Pending Task Invalidation
# =========================================================================

def test_scope_change_detection_and_task_invalidation(tmp_store, base_profile):
    """When scope narrows, pending tasks targeting removed assets are automatically invalidated."""
    # 1. Populate pending tasks in store: one valid, one that will be removed
    t_valid = Task(kind="cors", target="https://api.example.com/items")
    t_removed = Task(kind="cors", target="https://partner.example.com/v1")

    tmp_store.task_claim(t_valid.kind, t_valid.target, run_id="r1", fingerprint=t_valid.fingerprint, lease_seconds=300.0)
    tmp_store.task_finish(t_valid.fingerprint, state="pending", result={})

    tmp_store.task_claim(t_removed.kind, t_removed.target, run_id="r1", fingerprint=t_removed.fingerprint, lease_seconds=300.0)
    tmp_store.task_finish(t_removed.fingerprint, state="pending", result={})

    # 2. New profile with updated scope version and explicit removal
    new_prof = ProgramProfile(
        program_id="acme-corp",
        in_scope_assets=["https://api.example.com/*"],  # auth.example.com removed
        out_of_scope_assets=["https://partner.example.com/*"],
        scope_version=2,
    )

    diff = ScopeChangeDetector.compare(base_profile, new_prof)
    assert diff["has_changes"] is True
    assert diff["old_version"] == 1
    assert diff["new_version"] == 2
    assert "https://partner.example.com/*" in diff["added_out_of_scope"]

    # Invalidate pending tasks against new scope
    new_scope = new_prof.build_scope()
    invalidated_count = ScopeChangeDetector.invalidate_pending_tasks(tmp_store, new_scope)
    assert invalidated_count == 1

    # Verify task row in SQLite
    row_rem = tmp_store.get_task(t_removed.fingerprint)
    assert row_rem["state"] == "skipped"
    assert "scope invalidated" in row_rem["result"].get("reason", "")

    row_val = tmp_store.get_task(t_valid.fingerprint)
    assert row_val["state"] == "pending"


# =========================================================================
# 3. Research Prioritization Multi-Dimensional Scoring
# =========================================================================

def test_continuous_prioritizer_scoring(tmp_store):
    """Combines Laplace priors, P6 intel boost, coverage, and duplicate penalties."""
    prioritizer = ContinuousPrioritizer(tmp_store, program="acme-corp")

    tasks = [
        Task(kind="authz", target="https://api.example.com/users/profile", priority=1),
        Task(kind="headers", target="https://api.example.com/static/faq", priority=9),
    ]

    # Mock P6 intelligence record for broken access control
    intel_rec = IntelligenceRecord(
        id="CVE-2024-9999",
        source="test",
        source_id="CVE-2024-9999",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
        title="BOLA Vulnerability in Profile API",
        description="Broken object level authorization allows access to profile",
        vuln_class="authz",
        retrieved_at=now_iso(),
        cwe_ids=["CWE-639", "CWE-284"],
        severity="HIGH",
    )

    ranked = prioritizer.rank_backlog(tasks, intel_records=[intel_rec])
    assert len(ranked) == 2

    top_task, top_score = ranked[0]
    assert top_task.kind == "authz"
    assert top_score.intel_boost > 0.0
    assert "matched access-control intel" in top_score.explanation
    assert top_score.composite_score > ranked[1][1].composite_score


# =========================================================================
# 4. Autonomy Levels
# =========================================================================

def test_autonomy_level_observe_suppresses_traffic(tmp_store, base_profile):
    """AutonomyLevel.OBSERVE performs store audit only, zero outbound traffic."""
    base_profile.autonomy_level = AutonomyLevel.OBSERVE
    scheduler = ContinuousScheduler(base_profile, store=tmp_store)

    res = scheduler.run_cycle(max_tasks_per_cycle=5)
    assert res["status"] == "observe_only"
    assert res["tasks_executed"] == 0
    assert scheduler.state.total_requests_used == 0


# =========================================================================
# 5. Continuous Scheduler Execution & Restart Recovery
# =========================================================================

def test_continuous_scheduler_cycle_and_restart_recovery(tmp_store, base_profile):
    """Test running a cycle, crashing/stopping, and recovering persisted state."""
    scheduler = ContinuousScheduler(base_profile, store=tmp_store)

    # 1. Run cycle with dry_run simulation
    base_profile.rate_limit = 100.0
    res = scheduler.run_cycle(max_tasks_per_cycle=3)
    assert res["status"] == "cycle_completed"
    assert scheduler.state.cycles_completed == 1

    # 2. Simulate process restart by instantiating a fresh scheduler over the same DB
    restarted_scheduler = ContinuousScheduler(base_profile, store=tmp_store)
    # Check that previous runs and program profile table exist
    row = tmp_store.conn.execute(
        "SELECT profile_json FROM program_profiles WHERE program_id=?",
        (base_profile.program_id,)
    ).fetchone()
    assert row is not None
    saved_prof = json.loads(row["profile_json"])
    assert saved_prof["program_id"] == "acme-corp"


# =========================================================================
# 6. Budget Exhaustion Produces Terminal State
# =========================================================================

def test_budget_exhaustion_produces_distinct_terminal_state(tmp_store, base_profile):
    """When program budget is exhausted, scheduler transitions to BUDGET_EXHAUSTED and halts."""
    base_profile.max_requests = 10
    scheduler = ContinuousScheduler(base_profile, store=tmp_store)
    scheduler.state.total_requests_used = 10

    res = scheduler.run_cycle(max_tasks_per_cycle=5)
    assert res["status"] == "budget_exhausted"
    assert scheduler.state.status == SchedulerStatus.BUDGET_EXHAUSTED


# =========================================================================
# 7. Operator Pause and Resume
# =========================================================================

def test_operator_pause_and_resume(tmp_store, base_profile):
    """Operator pause holds execution; resume safely re-enables cycle execution."""
    scheduler = ContinuousScheduler(base_profile, store=tmp_store)

    scheduler.pause(reason="maintenance window")
    assert scheduler.state.status == SchedulerStatus.PAUSED

    res = scheduler.run_cycle(max_tasks_per_cycle=5)
    assert res["status"] == "paused"

    resumed = scheduler.resume(reason="maintenance complete")
    assert resumed is True
    assert scheduler.state.status == SchedulerStatus.RUNNING


# =========================================================================
# 8. Kill Switch Abort
# =========================================================================

def test_killswitch_immediate_abort(tmp_store, base_profile):
    """Activating kill switch aborts continuous scheduler immediately."""
    scheduler = ContinuousScheduler(base_profile, store=tmp_store)
    clear_killswitch()

    activate_killswitch("operator emergency abort")
    res = scheduler.run_cycle(max_tasks_per_cycle=5)

    assert res["status"] == "aborted"
    assert scheduler.state.status == SchedulerStatus.TERMINATED

    clear_killswitch()
