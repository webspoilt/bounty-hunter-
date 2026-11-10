"""Persistent Continuous Research Scheduler (Strategic P9).

Orchestrates continuous research across authorized programs:
- Maintains persistent research backlog
- Validates program authorization & scope validity on every cycle
- Detects scope modifications & invalidates affected pending tasks
- Recovers orphaned leases on restart
- Honors autonomy levels (OBSERVE, MAP, INVESTIGATE, REPORT)
- Respects polite request budgets, rate limits, model limits, and deadlines
- Halts gracefully on operator pause, cancellation, budget exhaustion, or kill switch
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from bb import feedback, normalize
from bb.checks import CheckOptions
from bb.config import now_iso
from bb.http import BudgetExceeded, RequestBudget, ScopedClient
from bb.intelligence.engine import IntelligenceEngine
from bb.killswitch import AbortRequested, active as kill_active
from bb.models import Finding
from bb.orchestrator.controller import Controller, ControllerConfig
from bb.orchestrator.lifecycle import State
from bb.orchestrator.prioritizer import ContinuousPrioritizer, ResearchPriorityScore
from bb.orchestrator.profile import AutonomyLevel, ProfileValidity, ProgramProfile, ScopeChangeDetector
from bb.orchestrator.resource_manager import ResourceManager, SecurityPolicy
from bb.orchestrator.scheduler import Scheduler
from bb.orchestrator.specialists import SpecialistWorkerRegistry
from bb.orchestrator.task_protocol import TaskProtocol, TaskState
from bb.scope import Scope
from bb.store import Store


class SchedulerStatus(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    BLOCKED = "BLOCKED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TERMINATED = "TERMINATED"
    SCOPE_INVALID = "SCOPE_INVALID"


@dataclass
class ContinuousSchedulerState:
    """Persistent state of the continuous scheduler."""
    status: SchedulerStatus = SchedulerStatus.IDLE
    program_id: str = ""
    scope_fingerprint: str = ""
    scope_version: int = 1
    cycles_completed: int = 0
    total_tasks_executed: int = 0
    total_findings_discovered: int = 0
    total_requests_used: int = 0
    last_cycle_at: str = ""
    pause_reason: str = ""
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class ContinuousScheduler:
    """Persistent, auditable continuous research scheduler for authorized programs."""

    def __init__(
        self,
        profile: ProgramProfile,
        store: Store | None = None,
        intel_engine: IntelligenceEngine | None = None,
        log: Callable[[str], None] = print,
    ):
        self.profile = profile
        self.store = store or Store()
        self.intel_engine = intel_engine
        self.log = log

        self.scope = self.profile.build_scope()
        self.specialists = SpecialistWorkerRegistry()
        self.prioritizer = ContinuousPrioritizer(self.store, self.profile.program_id)

        self._shutdown_event = threading.Event()
        self._pause_event = threading.Event()
        self._state = ContinuousSchedulerState(
            program_id=self.profile.program_id,
            scope_fingerprint=self.profile.fingerprint,
            scope_version=self.profile.scope_version,
            status=SchedulerStatus.IDLE,
        )

        self._controller: Controller | None = None
        self._init_program_record()

    def _init_program_record(self) -> None:
        """Record or update program profile state in SQLite."""
        self.store.conn.execute(
            "CREATE TABLE IF NOT EXISTS program_profiles ("
            "program_id TEXT PRIMARY KEY, profile_json TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, version INTEGER NOT NULL, updated_at TEXT NOT NULL)"
        )
        self.store.conn.execute(
            "CREATE TABLE IF NOT EXISTS continuous_scheduler_state ("
            "program_id TEXT PRIMARY KEY, state_json TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        self.store.conn.execute(
            "INSERT OR REPLACE INTO program_profiles (program_id, profile_json, fingerprint, version, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                self.profile.program_id,
                json.dumps(self.profile.to_dict()),
                self.profile.fingerprint,
                self.profile.scope_version,
                now_iso(),
            )
        )
        self.store.conn.commit()

    @property
    def state(self) -> ContinuousSchedulerState:
        return self._state

    def pause(self, reason: str = "operator pause") -> None:
        """Cleanly pause continuous research."""
        self._state.status = SchedulerStatus.PAUSED
        self._state.pause_reason = reason
        self._pause_event.set()
        if self._controller:
            self._controller.pause(reason=reason)
        self._save_state()
        self.log(f"[*] ContinuousScheduler paused: {reason}")

    def resume(self, reason: str = "operator resume") -> bool:
        """Resume execution from paused state if profile is valid."""
        valid, msg = self.profile.validate_executable()
        if not valid:
            self.log(f"[!] Cannot resume: {msg}")
            self._state.status = SchedulerStatus.BLOCKED
            self._state.error_message = msg
            self._save_state()
            return False

        self._state.status = SchedulerStatus.RUNNING
        self._state.pause_reason = ""
        self._pause_event.clear()
        if self._controller:
            self._controller.resume(reason=reason)
        self._save_state()
        self.log(f"[*] ContinuousScheduler resumed: {reason}")
        return True

    def abort(self, reason: str = "operator abort") -> None:
        """Emergency stop of continuous research."""
        self._state.status = SchedulerStatus.TERMINATED
        self._state.error_message = reason
        self._shutdown_event.set()
        if self._controller:
            self._controller.abort(reason=reason)
        self._save_state()
        self.log(f"[!] ContinuousScheduler aborted: {reason}")

    def update_profile(self, new_profile: ProgramProfile) -> dict[str, Any]:
        """Apply an updated scope/policy profile and handle task invalidation."""
        diff = ScopeChangeDetector.compare(self.profile, new_profile)
        self.profile = new_profile
        self.scope = new_profile.build_scope()
        self._state.scope_fingerprint = new_profile.fingerprint
        self._state.scope_version = new_profile.scope_version

        # Invalidate pending tasks for removed assets
        invalidated = ScopeChangeDetector.invalidate_pending_tasks(self.store, self.scope)
        diff["tasks_invalidated"] = invalidated

        if diff["policy_modified"] or new_profile.validity == ProfileValidity.SCOPE_CHANGED:
            self.pause("scope/policy modified: human verification required")
            self._state.status = SchedulerStatus.SCOPE_INVALID

        self._init_program_record()
        self._save_state()
        self.log(f"[*] Profile updated: {diff}")
        return diff

    def _save_state(self) -> None:
        self.store.conn.execute(
            "INSERT OR REPLACE INTO continuous_scheduler_state (program_id, state_json, updated_at) "
            "VALUES (?, ?, ?)",
            (self.profile.program_id, json.dumps(self._state.to_dict()), now_iso())
        )
        self.store.conn.commit()

    def run_cycle(self, max_tasks_per_cycle: int = 10) -> dict[str, Any]:
        """Execute one complete cycle of the durable continuous research loop."""
        if self._shutdown_event.is_set():
            return {"status": "terminated", "reason": self._state.error_message}
        if self._pause_event.is_set() or self._state.status == SchedulerStatus.PAUSED:
            return {"status": "paused", "reason": self._state.pause_reason}

        # Step 1: Validate program and current authorization
        valid, msg = self.profile.validate_executable()
        if not valid:
            self._state.status = SchedulerStatus.BLOCKED
            self._state.error_message = msg
            self._save_state()
            return {"status": "blocked", "reason": msg}

        # Step 2: Check kill switch
        if kill_active():
            self.abort("kill switch is active")
            return {"status": "aborted", "reason": "kill_switch_active"}

        # Step 3: Check request budget remaining
        shared_budget = RequestBudget(
            rate=self.profile.rate_limit,
            max_requests=self.profile.max_requests,
        )
        if self._state.total_requests_used >= self.profile.max_requests:
            self._state.status = SchedulerStatus.BUDGET_EXHAUSTED
            self._save_state()
            self.log("[!] Program request budget exhausted. Cycle halted.")
            return {"status": "budget_exhausted", "used": self._state.total_requests_used}

        # Step 4: Respect Autonomy Level
        if self.profile.autonomy_level == AutonomyLevel.OBSERVE:
            self.log("[*] Autonomy Level OBSERVE: scanning suppressed, auditing local store & intelligence.")
            self._state.status = SchedulerStatus.IDLE
            self._state.cycles_completed += 1
            self._state.last_cycle_at = now_iso()
            self._save_state()
            return {"status": "observe_only", "tasks_executed": 0}

        # Step 5: Checkpoint & recover stale task leases
        run_id = self.store.start_run(
            program=self.profile.program_id,
            target=",".join(self.profile.in_scope_assets[:5]),
            scope_fingerprint=self.profile.fingerprint,
            meta={"continuous": True, "scope_version": self.profile.scope_version, "cycle": self._state.cycles_completed + 1}
        )
        sched = Scheduler(self.store, run_id=run_id, lease_seconds=300.0)
        recovered = sched.recover_expired_leases(all_runs=True)
        if recovered > 0:
            self.log(f"[*] Recovered {recovered} stale task leases across runs")

        # Step 6: Initialize / Configure Controller for this cycle
        cfg = ControllerConfig(
            program=self.profile.program_id,
            scope=self.scope,
            entry_urls=self.profile.in_scope_assets,
            run_id=run_id,
            accounts=self.profile.accounts,
            rate=self.profile.rate_limit,
            max_requests=min(max_tasks_per_cycle * 5, self.profile.max_requests - self._state.total_requests_used),
            allow_write=False,  # Continuous autonomous cycle never performs unapproved destructive writes
            require_human_approval=self.profile.require_human_approval_for_write,
            max_iterations=max_tasks_per_cycle,
        )
        self._controller = Controller(cfg, store=self.store, log=self.log)

        # Step 7: Retrieve intelligence records if engine provided
        intel_records = []
        if self.intel_engine:
            try:
                intel_records = self.intel_engine.store.query_text(self.profile.program_id, limit=10)
            except Exception:
                pass

        # Step 8: Execute controller loop for this cycle
        cycle_res = self._controller.run()

        # Step 9: Update metrics & state
        used = cycle_res.get("budget_used", 0)
        self._state.total_requests_used += used
        self._state.total_tasks_executed += cycle_res.get("tasks_executed", 0)
        self._state.total_findings_discovered += cycle_res.get("findings", 0)
        self._state.cycles_completed += 1
        self._state.last_cycle_at = now_iso()
        self._state.status = SchedulerStatus.IDLE

        self._save_state()
        return {
            "status": "cycle_completed",
            "cycle": self._state.cycles_completed,
            "tasks_executed": cycle_res.get("tasks_executed", 0),
            "findings": cycle_res.get("findings", 0),
            "requests_used": used,
            "total_requests": self._state.total_requests_used,
        }
