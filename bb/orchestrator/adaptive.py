"""Adaptive Swarm Scaling Policy & Worker Concurrency Controller.

Defines deterministic scaling stages: 5 -> 10 -> 20 -> 35 -> 50.
Enforces that logical worker scaling is purely dynamic based on real metrics:
  - Task availability (sufficient independent tasks to work on)
  - Traffic budget headroom (remaining request quota)
  - Atomic claim contention & race loss rate
  - Execution success & error rates
  - Verification backlog backpressure
  - Zero safety invariant or killswitch violations

Tev1 may recommend a worker count, but the deterministic AdaptiveScalingPolicy
calculates and enforces the allowed count.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

SCALING_STAGES = (5, 10, 20, 35, 50)
DEFAULT_WORKERS = 5
MAX_WORKERS = 50
MIN_WORKERS = 1


@dataclass
class SwarmMetrics:
    """Snapshot of execution metrics used for adaptive scaling decisions."""
    eligible_tasks: int = 0
    active_workers: int = 0
    recent_claims_attempted: int = 0
    recent_claims_successful: int = 0
    recent_claims_contended: int = 0
    recent_tasks_completed: int = 0
    recent_tasks_failed: int = 0
    http_error_rate: float = 0.0
    budget_remaining_ratio: float = 1.0
    verification_backlog: int = 0
    model_queue_time_ms: float = 0.0
    model_timeouts: int = 0
    rate_limited: bool = False
    killswitch_active: bool = False


class AdaptiveScalingPolicy:
    """Calculates deterministic worker limits based on swarm execution health."""

    def __init__(
        self,
        stages: tuple[int, ...] = SCALING_STAGES,
        initial_workers: int = DEFAULT_WORKERS,
        min_workers: int = MIN_WORKERS,
        max_workers: int = MAX_WORKERS,
        max_verification_backlog: int = 15,
    ):
        self.stages = stages
        self.current_workers = min(max_workers, max(min_workers, initial_workers))
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.max_verification_backlog = max_verification_backlog
        self.history: list[dict[str, Any]] = []

    def evaluate_scale(
        self,
        metrics: SwarmMetrics,
        tev1_recommendation: int | None = None,
    ) -> tuple[int, str]:
        """Compute the next worker count. Returns (allowed_workers, explanation)."""
        # Safety overrides: scale down to 0/1 immediately if killswitch or budget dead
        if metrics.killswitch_active:
            self.current_workers = 0
            return 0, "killswitch active; all workers stopped"

        if metrics.budget_remaining_ratio <= 0.0:
            self.current_workers = 0
            return 0, "request budget exhausted; workers stopped"

        # Check scale-down conditions first (conservative safety)
        reasons_down: list[str] = []

        if metrics.rate_limited or metrics.http_error_rate >= 0.05:
            reasons_down.append(f"HTTP error/rate-limit rate high ({metrics.http_error_rate:.1%})")

        if metrics.verification_backlog >= self.max_verification_backlog:
            reasons_down.append(f"verification backlog high ({metrics.verification_backlog} items)")

        if metrics.budget_remaining_ratio < 0.15:
            reasons_down.append(f"request budget low ({metrics.budget_remaining_ratio:.1%} remaining)")

        if metrics.recent_claims_attempted >= 5:
            contention_rate = metrics.recent_claims_contended / metrics.recent_claims_attempted
            if contention_rate >= 0.25:
                reasons_down.append(f"task claim contention high ({contention_rate:.1%})")

        if metrics.model_timeouts > 0 or metrics.model_queue_time_ms > 20000.0:
            reasons_down.append("local model memory pressure / timeout detected")

        if reasons_down:
            next_stage = self._previous_stage(self.current_workers)
            old = self.current_workers
            self.current_workers = max(self.min_workers, next_stage)
            expl = f"scaled down from {old} to {self.current_workers}: " + "; ".join(reasons_down)
            self._record(self.current_workers, expl, metrics)
            return self.current_workers, expl

        # Check scale-up conditions
        reasons_up: list[str] = []
        can_scale_up = True

        # Need enough independent work to justify scale-up (at least 2x tasks per current worker)
        if metrics.eligible_tasks < self.current_workers * 2:
            can_scale_up = False
            reasons_up.append(f"insufficient pending tasks ({metrics.eligible_tasks} available)")

        if metrics.budget_remaining_ratio < 0.25:
            can_scale_up = False
            reasons_up.append("budget headroom < 25%")

        if metrics.verification_backlog >= (self.max_verification_backlog // 2):
            can_scale_up = False
            reasons_up.append(f"verification backlog non-empty ({metrics.verification_backlog})")

        if metrics.recent_tasks_failed > 0 and metrics.recent_tasks_completed > 0:
            fail_rate = metrics.recent_tasks_failed / (metrics.recent_tasks_completed + metrics.recent_tasks_failed)
            if fail_rate >= 0.05:
                can_scale_up = False
                reasons_up.append(f"recent task failure rate {fail_rate:.1%} >= 5%")

        if can_scale_up:
            target_stage = self._next_stage(self.current_workers)
            if tev1_recommendation is not None:
                # Tev1 can advise, but cannot exceed target_stage
                bounded_advise = min(target_stage, max(self.min_workers, tev1_recommendation))
                if bounded_advise > self.current_workers:
                    target_stage = bounded_advise
            old = self.current_workers
            if target_stage > self.current_workers:
                self.current_workers = min(self.max_workers, target_stage)
                expl = f"scaled up from {old} to {self.current_workers} (workload and capacity healthy)"
                self._record(self.current_workers, expl, metrics)
                return self.current_workers, expl

        # Maintain current stage
        expl = f"held at {self.current_workers} workers: " + ("; ".join(reasons_up) or "steady state")
        self._record(self.current_workers, expl, metrics)
        return self.current_workers, expl

    def _next_stage(self, current: int) -> int:
        for s in self.stages:
            if s > current:
                return s
        return self.max_workers

    def _previous_stage(self, current: int) -> int:
        for s in reversed(self.stages):
            if s < current:
                return s
        return self.min_workers

    def _record(self, workers: int, reason: str, metrics: SwarmMetrics) -> None:
        self.history.append({
            "timestamp": time.time(),
            "workers": workers,
            "reason": reason,
            "eligible": metrics.eligible_tasks,
            "backlog": metrics.verification_backlog,
            "budget_ratio": round(metrics.budget_remaining_ratio, 3),
        })
        if len(self.history) > 100:
            self.history.pop(0)
