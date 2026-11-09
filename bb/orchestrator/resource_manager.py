"""Resource Manager & Security Policy Enforcement.

Authority Boundaries:
The Resource Manager and Security Policy exclusively own:
  - Scope boundaries and exclusion rules.
  - Request rate, budget and deadline management.
  - Kill-switch monitoring and immediate abort enforcement.
  - State-changing write authorization and human approval gates.
  - Verification backlog management.

Tev1 cannot modify or bypass any rule defined here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from bb.config import DEFAULT_MAX_REQUESTS, DEFAULT_RATE
from bb.http import BudgetExceeded, RequestBudget
from bb.killswitch import AbortRequested, active as kill_active, reason as kill_reason
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


class PolicyViolation(RuntimeError):
    """Raised when an operation violates security policy or boundaries."""


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
            import time
            if time.monotonic() > self.policy.deadline:
                return False
        if self.policy.max_requests is not None:
            if self.budget.used >= self.policy.max_requests:
                return False
        return True

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
