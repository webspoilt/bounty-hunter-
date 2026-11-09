"""Structured Multi-Agent Task Protocol for Bounty Hunter V2.

Defines the complete, crash-safe, persistent task lifecycle schema:
- task_id
- investigation_id
- program
- authorized_target
- worker_role
- hypothesis
- supporting_observations
- preconditions
- proposed_action
- required_approvals
- resource_estimate
- expected_evidence
- stop_conditions
- current_state
- result
- provenance
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from bb import normalize
from bb.config import now_iso


class TaskState(str, Enum):
    PENDING = "pending"
    CLAIMED = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


@dataclass
class TaskProtocol:
    """Standardized task protocol envelope across all specialist teams and workers."""
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    investigation_id: str = ""
    program: str = ""
    authorized_target: str = ""
    worker_role: str = "general_worker"
    kind: str = "check"
    priority: int = 5
    hypothesis: str = ""
    supporting_observations: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    proposed_action: str = ""
    required_approvals: list[str] = field(default_factory=list)
    resource_estimate: dict[str, Any] = field(default_factory=lambda: {"estimated_requests": 1, "timeout_sec": 15.0})
    expected_evidence: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=list)
    state: TaskState = TaskState.PENDING
    attempts: int = 0
    result: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def __post_init__(self):
        if not self.fingerprint:
            norm_target = normalize.normalize_url(self.authorized_target) if self.authorized_target else ""
            key = f"{self.worker_role}|{self.kind}|{norm_target}|{self.proposed_action}"
            self.fingerprint = hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:24]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value if isinstance(self.state, TaskState) else str(self.state)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaskProtocol:
        state_val = data.get("state", TaskState.PENDING.value)
        try:
            state = TaskState(state_val)
        except ValueError:
            state = TaskState.PENDING

        return cls(
            task_id=data.get("task_id") or data.get("id") or uuid.uuid4().hex[:16],
            investigation_id=data.get("investigation_id") or data.get("run_id") or "",
            program=data.get("program", ""),
            authorized_target=data.get("authorized_target") or data.get("target") or "",
            worker_role=data.get("worker_role", "general_worker"),
            kind=data.get("kind", "check"),
            priority=int(data.get("priority", 5)),
            hypothesis=data.get("hypothesis", ""),
            supporting_observations=data.get("supporting_observations") or [],
            preconditions=data.get("preconditions") or [],
            proposed_action=data.get("proposed_action", ""),
            required_approvals=data.get("required_approvals") or [],
            resource_estimate=data.get("resource_estimate") or {"estimated_requests": 1, "timeout_sec": 15.0},
            expected_evidence=data.get("expected_evidence") or [],
            stop_conditions=data.get("stop_conditions") or [],
            state=state,
            attempts=int(data.get("attempts", 0)),
            result=data.get("result") or {},
            provenance=data.get("provenance") or {},
            fingerprint=data.get("fingerprint", ""),
            created_at=data.get("created_at") or now_iso(),
            updated_at=data.get("updated_at") or now_iso(),
        )
