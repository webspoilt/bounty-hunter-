"""Resource Manager & Security Policy Enforcement.

Authority Boundaries:
The Resource Manager and Security Policy exclusively own:
  - Scope boundaries and exclusion rules.
  - Request rate, budget and deadline management.
  - Kill-switch monitoring and immediate abort enforcement.
  - State-changing write authorization and human approval gates.
  - Verification backlog management.
  - Concurrency dimensions and adaptive scaling limits.
  - Local model concurrency bounds (Tev1 vs Qwen Coder).

Tev1 cannot modify or bypass any rule defined here.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from bb.config import DEFAULT_MAX_REQUESTS, DEFAULT_RATE
from bb.http import BudgetExceeded, RequestBudget
from bb.killswitch import AbortRequested, active as kill_active, reason as kill_reason
from bb.orchestrator.adaptive import AdaptiveScalingPolicy, SwarmMetrics
from bb.scope import Scope, ScopeDecision

if TYPE_CHECKING:
    from bb.orchestrator.agent_registry import AgentSpec
    from bb.store import Store
    from bb.swarm import Task


@dataclass
class SecurityPolicy:
    """Deterministic security and safety constraints."""
    allow_write: bool = False
    require_human_approval_for_write: bool = True
    max_verification_backlog: int = 15
    rate: float = DEFAULT_RATE
    max_requests: int = DEFAULT_MAX_REQUESTS
    deadline: float | None = None
    min_rate: float = 0.1
    # Concurrency boundaries
    initial_workers: int = 5
    max_workers: int = 50
    min_workers: int = 1
    tev1_max_concurrency: int = 2
    qwen_max_concurrency: int = 1


class PolicyViolation(RuntimeError):
    """Raised when an operation violates security policy or boundaries."""


class ConcurrencyTracker:
    """Independently tracks the 4 distinct concurrency dimensions:

    1. Logical worker count (swarm execution units)
    2. Tev1 decision concurrency (lightweight structured JSON)
    3. Qwen generation concurrency (heavy local model code gen)
    4. HTTP request concurrency (active in-flight network requests)
    """

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self._lock = threading.Lock()
        self.logical_workers: int = policy.initial_workers
        self.active_logical_workers: int = 0
        self.active_http_requests: int = 0
        self.tev1_semaphore = threading.BoundedSemaphore(value=policy.tev1_max_concurrency)
        self.qwen_semaphore = threading.BoundedSemaphore(value=policy.qwen_max_concurrency)
        self._active_tev1: int = 0
        self._active_qwen: int = 0

    def acquire_tev1(self, timeout: float = 30.0) -> bool:
        acquired = self.tev1_semaphore.acquire(timeout=timeout)
        if acquired:
            with self._lock:
                self._active_tev1 += 1
        return acquired

    def release_tev1(self) -> None:
        with self._lock:
            self._active_tev1 = max(0, self._active_tev1 - 1)
        self.tev1_semaphore.release()

    def acquire_qwen(self, timeout: float = 60.0) -> bool:
        acquired = self.qwen_semaphore.acquire(timeout=timeout)
        if acquired:
            with self._lock:
                self._active_qwen += 1
        return acquired

    def release_qwen(self) -> None:
        with self._lock:
            self._active_qwen = max(0, self._active_qwen - 1)
        self.qwen_semaphore.release()

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "logical_workers": self.logical_workers,
                "active_logical_workers": self.active_logical_workers,
                "active_http_requests": self.active_http_requests,
                "active_tev1": self._active_tev1,
                "active_qwen": self._active_qwen,
            }


class ResourceManager:
    """Central guardian for all execution resources, safety boundaries, and gates."""

    def __init__(self, scope: Scope, policy: SecurityPolicy | None = None,
                 budget: RequestBudget | None = None, store: Store | None = None,
                 run_id: str | None = None):
        self.scope = scope
        self.policy = policy or SecurityPolicy()
        self.budget = budget or RequestBudget(
            rate=self.policy.rate,
            max_requests=self.policy.max_requests,
            deadline=self.policy.deadline,
        )
        self.store = store
        self.run_id = run_id
        self.concurrency = ConcurrencyTracker(self.policy)
        self.adaptive_policy = AdaptiveScalingPolicy(
            initial_workers=self.policy.initial_workers,
            min_workers=self.policy.min_workers,
            max_workers=self.policy.max_workers,
            max_verification_backlog=self.policy.max_verification_backlog,
        )

    # ---------- kill switch & budget checks ----------

    def check_killswitch(self) -> None:
        """Enforce the global panic button immediately."""
        if kill_active():
            msg = kill_reason() or "armed by operator"
            if self.store and self.run_id:
                self.store.audit_scope(self.run_id, "KILLSWITCH", "DENY", f"abort: {msg}")
            raise AbortRequested(f"kill switch active: {msg}")

    def check_budget_available(self) -> bool:
        """Check whether requests remain under the shared budget."""
        if self.policy.deadline is not None:
            if time.monotonic() > self.policy.deadline:
                return False
        if self.policy.max_requests is not None:
            if self.budget.used >= self.policy.max_requests:
                return False
        return True

    def budget_remaining_ratio(self) -> float:
        """Ratio of remaining requests against maximum allowed."""
        if self.policy.max_requests is None or self.policy.max_requests <= 0:
            return 1.0
        used = self.budget.used
        remaining = max(0, self.policy.max_requests - used)
        return remaining / float(self.policy.max_requests)

    # ---------- scope & DNS validation ----------

    def validate_target(self, target: str) -> ScopeDecision:
        """Validate target against scope rules and DNS anti-rebinding guard."""
        self.check_killswitch()
        dec = self.scope.check(target)
        if not dec.allowed:
            if self.store:
                self.store.audit_scope(self.run_id, target, "DENY", dec.reason, dec.host)
            return dec

        # Recheck DNS resolution if host target
        if "://" in target or "." in target.split("/")[0]:
            dns_dec = self.scope.verify_resolution(target)
            if not dns_dec.allowed:
                if self.store:
                    self.store.audit_scope(self.run_id, target, "DENY", dns_dec.reason, dns_dec.host)
                return dns_dec

        if self.store:
            self.store.audit_scope(self.run_id, target, "ALLOW", dec.reason, dec.host)
        return dec

    # ---------- task & specialist policy validation ----------

    def validate_task_policy(self, task: Task, agent: AgentSpec,
                             has_roles: bool = False) -> tuple[bool, str]:
        """Apply deterministic policy checks to a planned task before claim/execution."""
        self.check_killswitch()

        if not self.check_budget_available():
            return False, "request budget exhausted"

        # 1. Target scope
        dec = self.validate_target(task.target)
        if not dec.allowed:
            return False, f"target out of scope: {dec.reason}"

        # 2. Roles requirement
        if agent.requires_roles and not has_roles:
            return False, f"agent '{agent.name}' requires authenticated roles for testing"

        # 3. State-changing / Write safety
        is_write = self.is_state_changing(task)
        if is_write:
            if not self.policy.allow_write:
                return False, "state-changing write operation refused (--allow-write not enabled)"
            if agent.safe_methods_only:
                return False, f"agent '{agent.name}' is strictly read-only; cannot perform writes"
            if self.policy.require_human_approval_for_write:
                # Requires explicit human approval gate
                if not task.payload.get("human_approved", False):
                    return False, "state-changing write requires human approval gate confirmation"

        return True, "policy validated"

    def is_state_changing(self, task: Task) -> bool:
        """Determine if a task involves state-changing write operations."""
        method = (task.payload.get("method") or "GET").upper()
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return True
        if task.kind in ("idor_write", "state_change"):
            return True
        if task.payload.get("allow_write", False):
            return True
        return False

    def check_verification_backlog(self) -> tuple[bool, int]:
        """Check if unverified candidate findings exceed the backlog threshold."""
        if not self.store:
            return False, 0
        candidates = self.store.findings(status="candidate", run_id=self.run_id)
        count = len(candidates)
        backlogged = count >= self.policy.max_verification_backlog
        return backlogged, count

    # ---------- adaptive scaling computation ----------

    def effective_network_concurrency(self, logical_workers: int) -> int:
        """Calculate network worker cap governed by the polite rate budget."""
        rate = max(self.policy.rate, self.policy.min_rate)
        # Network concurrency is bounded by rate / MIN_RATE (e.g. 3.0 / 0.1 = 30)
        return max(1, min(int(logical_workers), int(rate / self.policy.min_rate)))

    def evaluate_scaling(
        self,
        metrics: SwarmMetrics,
        tev1_recommendation: int | None = None,
    ) -> tuple[int, str]:
        """Calculate allowed logical worker count deterministically."""
        self.check_killswitch()
        # Backlog update
        backlogged, backlog_count = self.check_verification_backlog()
        metrics.verification_backlog = backlog_count
        metrics.budget_remaining_ratio = self.budget_remaining_ratio()
        metrics.killswitch_active = kill_active()

        allowed_workers, explanation = self.adaptive_policy.evaluate_scale(
            metrics, tev1_recommendation=tev1_recommendation
        )
        self.concurrency.logical_workers = allowed_workers
        return allowed_workers, explanation
