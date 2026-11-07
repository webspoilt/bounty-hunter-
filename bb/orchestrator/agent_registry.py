"""Specialist Agent Registry for Bounty Hunter Orchestration.

Authority Boundaries:
Tev1 may recommend which registered specialist to dispatch.
Tev1 CANNOT register arbitrary agents or invoke unregistered tools.

Every specialist in this registry is pre-configured with explicit capability
flags, safety constraints, role requirements, and method restrictions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bb.swarm import Task


class AgentCapability(str, Enum):
    PASSIVE_RECON = "PASSIVE_RECON"
    ACTIVE_PROBE = "ACTIVE_PROBE"
    PARAMETER_MAPPING = "PARAMETER_MAPPING"
    AUTH_ANALYSIS = "AUTH_ANALYSIS"
    DIFFERENTIAL_TEST = "DIFFERENTIAL_TEST"
    WAF_PROBE = "WAF_PROBE"
    OFFLINE_AUDIT = "OFFLINE_AUDIT"
    ONLINE_REPLAY = "ONLINE_REPLAY"
    QUEUE_MANAGEMENT = "QUEUE_MANAGEMENT"


@dataclass(frozen=True)
class AgentSpec:
    name: str
    description: str
    capabilities: frozenset[AgentCapability]
    safe_methods_only: bool = True
    requires_roles: bool = False
    supported_task_kinds: frozenset[str] = field(default_factory=frozenset)


# Built-in, vetted specialists adhering to architecture specifications
DEFAULT_SPECIALISTS: tuple[AgentSpec, ...] = (
    AgentSpec(
        name="surface_mapper",
        description="Crawls entrypoints, maps routes, and extracts JS AST endpoints.",
        capabilities=frozenset({AgentCapability.PASSIVE_RECON, AgentCapability.ACTIVE_PROBE}),
        safe_methods_only=True,
        requires_roles=False,
        supported_task_kinds=frozenset({"recon", "discovery", "crawl"}),
    ),
    AgentSpec(
        name="parameter_analyst",
        description="Classifies parameter schemas and normalizes routes into path templates.",
        capabilities=frozenset({AgentCapability.PARAMETER_MAPPING}),
        safe_methods_only=True,
        requires_roles=False,
        supported_task_kinds=frozenset({"normalize", "params"}),
    ),
    AgentSpec(
        name="auth_analyst",
        description="Manages authentication flows and validates multi-role session tokens.",
        capabilities=frozenset({AgentCapability.AUTH_ANALYSIS}),
        safe_methods_only=True,
        requires_roles=True,
        supported_task_kinds=frozenset({"auth", "session"}),
    ),
    AgentSpec(
        name="differential_tester",
        description="Executes dual-role authorization tests (IDOR/BOLA) across roles.",
        capabilities=frozenset({AgentCapability.DIFFERENTIAL_TEST}),
        safe_methods_only=False,  # writes permitted only with explicit --allow-write & gate
        requires_roles=True,
        supported_task_kinds=frozenset({"authz", "unauth", "scenario", "idor"}),
    ),
    AgentSpec(
        name="security_prober",
        description="Runs deterministic stateless checks (CORS, GraphQL, headers, WAF canary).",
        capabilities=frozenset({AgentCapability.ACTIVE_PROBE, AgentCapability.WAF_PROBE}),
        safe_methods_only=True,
        requires_roles=False,
        supported_task_kinds=frozenset({"cors", "exposed", "headers", "graphql", "open_redirect", "waf_probe"}),
    ),
    AgentSpec(
        name="verifier",
        description="Independent verifier: performs offline evidence audit and online replay.",
        capabilities=frozenset({AgentCapability.OFFLINE_AUDIT, AgentCapability.ONLINE_REPLAY}),
        safe_methods_only=True,
        requires_roles=False,  # optional roles for online replay
        supported_task_kinds=frozenset({"verify"}),
    ),
    AgentSpec(
        name="report_agent",
        description="Generates sanitized HackerOne Markdown reports and queues for human gate.",
        capabilities=frozenset({AgentCapability.QUEUE_MANAGEMENT}),
        safe_methods_only=True,
        requires_roles=False,
        supported_task_kinds=frozenset({"report", "queue"}),
    ),
)


class AgentRegistry:
    """Fixed registry of vetted specialist agents."""

    def __init__(self, specialists: tuple[AgentSpec, ...] = DEFAULT_SPECIALISTS):
        self._specialists: dict[str, AgentSpec] = {s.name: s for s in specialists}

    def resolve(self, name: str) -> AgentSpec | None:
        """Resolve a specialist by exact name. Returns None for unregistered agents."""
        return self._specialists.get(name)

    def is_registered(self, name: str) -> bool:
        return name in self._specialists

    def list_specialists(self, capability: AgentCapability | None = None) -> list[AgentSpec]:
        """List registered specialists, optionally filtered by capability."""
        if capability is None:
            return list(self._specialists.values())
        return [s for s in self._specialists.values() if capability in s.capabilities]

    def for_task_kind(self, task_kind: str) -> list[AgentSpec]:
        """Find registered specialists capable of handling a given task kind."""
        kind = task_kind.lower()
        return [s for s in self._specialists.values() if kind in s.supported_task_kinds]

    def select_default_specialist(self, task: Task) -> AgentSpec:
        """Deterministic resolution of the best default specialist for a task."""
        matches = self.for_task_kind(task.kind)
        if matches:
            return matches[0]
        # Fallbacks based on kind
        if task.kind in ("authz", "unauth"):
            return self._specialists["differential_tester"]
        if task.kind in ("cors", "headers", "exposed", "graphql", "open_redirect", "waf_probe"):
            return self._specialists["security_prober"]
        if task.kind == "verify":
            return self._specialists["verifier"]
        return self._specialists["security_prober"]
