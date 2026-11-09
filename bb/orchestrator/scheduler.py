"""Task Scheduler with Atomic Leases & Crash Recovery.

Reuses the existing SQLite task ledger in `bb/store.py` without schema changes
or duplicate task stores. Ensures exactly-once execution across runs and workers,
with support for lease renewals and recovery from aborted or crashed processes.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from bb.store import Store
    from bb.swarm import Task


DEFAULT_LEASE_SECONDS = 300.0  # 5 minutes


class Scheduler:
    """Schedules, claims, renews, and recovers tasks in the persistent store."""

    def __init__(self, store: Store, run_id: str, lease_seconds: float = DEFAULT_LEASE_SECONDS):
        self.store = store
        self.run_id = run_id
        self.lease_seconds = lease_seconds

    def claim_task(self, task: Task, max_attempts: int = 3,
                   max_age_hours: float | None = 24.0) -> bool:
        """Atomically claim a task unit in SQLite with lease protection.

        Returns True only if this caller successfully claimed the task. Lost races,
        already-running tasks under active lease, or fresh done tasks return False.
        """
        return self.store.task_claim(
            kind=task.kind,
            target=task.target,
            run_id=self.run_id,
            fingerprint=task.fingerprint,
            max_attempts=max_attempts,
            max_age_hours=max_age_hours,
            lease_seconds=self.lease_seconds,
        )

    def renew_lease(self, task_fingerprint: str) -> bool:
        """Extend the lease timestamp for an in-flight running task."""
        return self.store.task_renew(task_fingerprint)

    def finish_task(self, task_fingerprint: str, state: str = "done",
                    result: dict[str, Any] | None = None) -> None:
        """Mark a claimed task as completed (done, failed, or skipped)."""
        self.store.task_finish(task_fingerprint, state=state, result=result or {})

    def recover_expired_leases(self, all_runs: bool = True) -> int:
        """Scan and recover running tasks whose worker crashed or abandoned the lease."""
        return self.store.recover_stale_tasks(
            lease_seconds=self.lease_seconds,
            run_id=None if all_runs else self.run_id,
        )
