"""Typed application entities, relationships, and provenance tracking for authorization testing.

Models the target application observed through traffic and researcher configuration:
- Role
- Identity
- Endpoint
- Parameter
- ObjectRef
- Workflow
- ScenarioSpec
- EvidenceRef
- Hypothesis

Every relationship carries explicit provenance: 'observed', 'operator-confirmed', or 'inferred'.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

from bb.config import now_iso

Provenance = Literal["observed", "operator-confirmed", "inferred"]


@dataclass
class Role:
    """A distinct security persona or privilege level in the application."""
    name: str  # e.g., "A", "B", "admin", "regular"
    label: str = ""
    description: str = ""
    provenance: Provenance = "operator-confirmed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label or self.name,
            "description": self.description,
            "provenance": self.provenance,
        }


@dataclass
class Identity:
    """An identity principal bound to a role and authentication credentials/markers."""
    role: str  # References Role.name
    identifier: str  # Unique identity marker (e.g., user id, email, account number, username)
    headers: dict[str, str] = field(default_factory=dict)
    provenance: Provenance = "operator-confirmed"
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        # Never serialize raw authorization tokens or secrets if present
        safe_meta = {k: v for k, v in self.meta.items() if not any(
            sec in k.lower() for sec in ("token", "password", "secret", "auth", "key")
        )}
        return {
            "role": self.role,
            "identifier": self.identifier,
            "provenance": self.provenance,
            "meta": safe_meta,
        }


@dataclass
class Endpoint:
    """An HTTP endpoint observed in traffic."""
    method: str
    url_pattern: str  # e.g., "https://app.example.com/api/orders/{id}"
    host: str
    path: str
    provenance: Provenance = "observed"
    is_state_changing: bool = False
    auth_required: bool = True
    parameters: list[str] = field(default_factory=list)  # Parameter names

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.url_pattern}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url_pattern": self.url_pattern,
            "host": self.host,
            "path": self.path,
            "provenance": self.provenance,
            "is_state_changing": self.is_state_changing,
            "auth_required": self.auth_required,
            "parameters": self.parameters,
        }


@dataclass
class Parameter:
    """A parameter observed in requests or responses."""
    name: str
    kind: str  # "path", "query", "body_json", "header"
    endpoint_key: str  # References Endpoint.key
    example_value: str = ""
    is_object_identifier: bool = False
    provenance: Provenance = "observed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "endpoint_key": self.endpoint_key,
            "example_value": self.example_value,
            "is_object_identifier": self.is_object_identifier,
            "provenance": self.provenance,
        }


@dataclass
class ObjectRef:
    """A domain entity or resource instance owned by an identity or shared."""
    object_id: str
    object_type: str  # e.g. "order", "basket", "profile", "document"
    owner_identity: str | None = None  # References Identity.identifier, or None if public/shared
    origin_url: str = ""
    provenance: Provenance = "observed"
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_id": self.object_id,
            "object_type": self.object_type,
            "owner_identity": self.owner_identity,
            "origin_url": self.origin_url,
            "provenance": self.provenance,
            "meta": self.meta,
        }


@dataclass
class Workflow:
    """An ordered multi-step operation (e.g. Create -> Read -> Mutate -> Delete)."""
    name: str
    description: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    provenance: Provenance = "inferred"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "steps": self.steps,
            "provenance": self.provenance,
        }


@dataclass
class ScenarioSpec:
    """An executable scenario specification compliant with bb.scenario schema."""
    name: str
    base_url: str
    steps: list[dict[str, Any]]
    claim: dict[str, Any]
    cleanup: list[dict[str, Any]] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    provenance: Provenance = "inferred"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "base_url": self.base_url,
            "steps": self.steps,
            "claim": self.claim,
            "variables": self.variables,
            "provenance": self.provenance,
        }
        if self.cleanup:
            data["cleanup"] = self.cleanup
        return data


@dataclass
class EvidenceRef:
    """Provenance pointer to recorded HTTP exchange and differential test observations."""
    exchange_id: int | None
    step_id: str
    status: int
    summary: str
    provenance: Provenance = "observed"
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exchange_id": self.exchange_id,
            "step_id": self.step_id,
            "status": self.status,
            "summary": self.summary,
            "provenance": self.provenance,
            "created_at": self.created_at,
        }


@dataclass
class Hypothesis:
    """An authorization testing hypothesis derived from observed application model."""
    id: str
    title: str
    description: str
    kind: str  # "idor_read", "idor_write", "tenant_crossing", "privilege_escalation"
    target_endpoint: str
    target_method: str
    object_id: str
    owner_role: str
    attacker_role: str
    scenario: ScenarioSpec
    is_state_changing: bool = False
    requires_approval: bool = False
    priority_score: int = 5
    provenance: Provenance = "inferred"
    status: str = "proposed"  # "proposed", "approved", "rejected", "verified", "inconclusive"
    decision_provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        key = f"{self.kind}|{self.target_method}|{self.target_endpoint}|{self.object_id}"
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "kind": self.kind,
            "target_endpoint": self.target_endpoint,
            "target_method": self.target_method,
            "object_id": self.object_id,
            "owner_role": self.owner_role,
            "attacker_role": self.attacker_role,
            "is_state_changing": self.is_state_changing,
            "requires_approval": self.requires_approval,
            "priority_score": self.priority_score,
            "provenance": self.provenance,
            "status": self.status,
            "fingerprint": self.fingerprint,
            "decision_provenance": self.decision_provenance,
            "scenario": self.scenario.to_dict(),
        }


class ApplicationModel:
    """Unified application graph modeling entities, interactions, and relationships."""

    def __init__(self, program: str):
        self.program = program
        self.roles: dict[str, Role] = {}
        self.identities: dict[str, Identity] = {}
        self.endpoints: dict[str, Endpoint] = {}
        self.parameters: dict[str, Parameter] = {}
        self.objects: dict[str, ObjectRef] = {}
        self.workflows: list[Workflow] = []
        self.hypotheses: dict[str, Hypothesis] = {}
        self.evidence: list[EvidenceRef] = []

    def add_role(self, role: Role) -> None:
        self.roles[role.name] = role

    def add_identity(self, identity: Identity) -> None:
        self.identities[identity.identifier] = identity

    def add_endpoint(self, endpoint: Endpoint) -> None:
        self.endpoints[endpoint.key] = endpoint

    def add_parameter(self, param: Parameter) -> None:
        key = f"{param.endpoint_key}#{param.kind}#{param.name}"
        self.parameters[key] = param

    def add_object(self, obj: ObjectRef) -> None:
        self.objects[obj.object_id] = obj

    def add_workflow(self, workflow: Workflow) -> None:
        self.workflows.append(workflow)

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self.hypotheses[hypothesis.id] = hypothesis

    def add_evidence(self, ev: EvidenceRef) -> None:
        self.evidence.append(ev)

    def to_dict(self) -> dict[str, Any]:
        return {
            "program": self.program,
            "roles": {k: v.to_dict() for k, v in self.roles.items()},
            "identities": {k: v.to_dict() for k, v in self.identities.items()},
            "endpoints": {k: v.to_dict() for k, v in self.endpoints.items()},
            "parameters": {k: v.to_dict() for k, v in self.parameters.items()},
            "objects": {k: v.to_dict() for k, v in self.objects.items()},
            "workflows": [w.to_dict() for w in self.workflows],
            "hypotheses": {k: v.to_dict() for k, v in self.hypotheses.items()},
            "evidence": [e.to_dict() for e in self.evidence],
        }
