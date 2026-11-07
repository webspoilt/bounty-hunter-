"""Investigation Planner for Bounty Hunter Orchestration.

Discovers work units, builds candidate tasks from existing endpoints/routes/scenarios,
creates compact decision states for Tev1, and constructs bounded investigation plans.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from bb import feedback, swarm
from bb.checks import CheckOptions
from bb.swarm import Task

if TYPE_CHECKING:
    from bb.orchestrator.agent_registry import AgentSpec
    from bb.scope import Scope
    from bb.store import Store


class Planner:
    """Plans, discovers, and shapes units of work for the controller."""

    def __init__(self, scope: Scope, store: Store, program: str):
        self.scope = scope
        self.store = store
        self.program = program

    def discover_candidates(self, entry_urls: list[str], endpoints: list[dict] | None = None,
                            options: CheckOptions | None = None,
                            have_roles: bool = False,
                            scenario_paths: list[str] | None = None) -> list[Task]:
        """Build a prioritized, deduplicated list of candidate tasks from store inventory."""
        opts = options or CheckOptions()
        eps = endpoints if endpoints is not None else self.store.endpoints()

        # Turn endpoints and origins into candidate tasks using existing swarm logic
        tasks = swarm.plan(eps, entry_urls, opts, have_roles=have_roles)

        # Also incorporate scenario files if provided
        if scenario_paths:
            for sp in scenario_paths:
                tasks.append(Task(
                    kind="scenario",
                    target=sp,
                    payload={"file": sp},
                    priority=1,
                ))

        return tasks

    def filter_eligible(self, tasks: list[Task], run_id: str | None = None,
                        max_age_hours: float | None = 24.0,
                        lease_seconds: float = 300.0) -> list[Task]:
        """Filter candidate tasks to only those currently eligible to be claimed."""
        eligible: list[Task] = []
        for task in tasks:
            record = self.store.get_task(task.fingerprint)
            if not record:
                # Fresh, never seen
                eligible.append(task)
                continue

            state = record.get("state")
            if state in ("failed", "skipped") and record.get("attempts", 0) < 3:
                eligible.append(task)
            elif state == "done":
                # Stale done check
                if max_age_hours is not None:
                    from datetime import datetime, timedelta, timezone
                    try:
                        seen = datetime.fromisoformat(record["updated_at"])
                        if seen.tzinfo is None:
                            seen = seen.replace(tzinfo=timezone.utc)
                        if datetime.now(timezone.utc) - seen > timedelta(hours=max_age_hours):
                            eligible.append(task)
                    except Exception:
                        eligible.append(task)
            elif state == "running":
                # Check for expired lease
                from datetime import datetime, timedelta, timezone
                try:
                    seen = datetime.fromisoformat(record["updated_at"])
                    if seen.tzinfo is None:
                        seen = seen.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) - seen > timedelta(seconds=lease_seconds):
                        eligible.append(task)
                except Exception:
                    eligible.append(task)

        return eligible

    def build_decision_context(self, candidates: list[Task], limit: int = 10) -> dict[str, Any]:
        """Construct compact, redacted decision state for Tev1 ranking."""
        priors = feedback.class_priors(self.store, program=self.program)
        task_summaries = []
        for t in candidates[:limit]:
            prior = priors.get(t.kind, {}).get("weight", 0.5)
            task_summaries.append({
                "id": t.fingerprint,
                "kind": t.kind,
                "target": t.target[:80],
                "priority": t.priority,
                "prior_weight": prior,
            })

        return {
            "program": self.program,
            "eligible_count": len(candidates),
            "candidates": task_summaries,
        }

    def build_investigation_plan(self, task: Task, agent: AgentSpec,
                                 max_requests: int = 20) -> dict[str, Any]:
        """Construct a bounded, constrained plan for executing a single task."""
        return {
            "task_id": task.fingerprint,
            "kind": task.kind,
            "target": task.target,
            "agent": agent.name,
            "max_requests": min(max_requests, 50),
            "safe_methods_only": agent.safe_methods_only,
            "payload": task.payload,
        }
