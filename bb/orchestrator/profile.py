"""Program Research Profile & Scope Change Management (Strategic P9).

Defines:
- ProgramProfile: Explicit program specification with in/out assets, categories,
  prohibitions, authentication, rate limits, budgets, approvals, validity, and scope review timestamps.
- ScopeChangeDetector: Detects additions, removals, and modifications of in-scope assets,
  and manages pending task invalidation when scope narrows.
- AutonomyLevel: Explicit operational levels (OBSERVE, MAP, INVESTIGATE, REPORT).
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from bb.config import now_iso
from bb.scope import Scope, normalize_host, parse_target


class AutonomyLevel(str, Enum):
    """Explicit operational boundaries for autonomous execution."""
    OBSERVE = "OBSERVE"          # Review stored evidence, intel, program config. Zero target traffic.
    MAP = "MAP"                  # Approved bounded discovery, route/parameter surface mapping.
    INVESTIGATE = "INVESTIGATE"  # Narrowly defined vulnerability tests under policy & budget controls.
    REPORT = "REPORT"            # Prepare finding drafts and evidence for human review. No auto-submit.


class ProfileValidity(str, Enum):
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"
    SCOPE_CHANGED = "SCOPE_CHANGED"
    PENDING_REVIEW = "PENDING_REVIEW"


@dataclass
class ProgramProfile:
    """Explicit program research profile for authorized continuous bug bounty research."""
    program_id: str
    in_scope_assets: list[str]
    out_of_scope_assets: list[str] = field(default_factory=list)
    permitted_categories: list[str] = field(default_factory=lambda: [
        "authz", "unauth", "cors", "exposed", "headers", "graphql", "open_redirect", "waf_probe"
    ])
    prohibited_activities: list[str] = field(default_factory=lambda: [
        "dos", "credential_stuffing", "unrestricted_fuzzing", "destructive_write"
    ])
    authentication_required: bool = False
    accounts: dict | None = None
    rate_limit: float = 3.0
    max_requests: int = 500
    time_budget_seconds: float = 3600.0  # 1 hour default
    model_cost_limit: float = 10.0      # USD / token equivalent limit
    require_human_approval_for_write: bool = True
    scope_reviewed_at: str = field(default_factory=now_iso)
    expires_at: str | None = None
    validity: ProfileValidity = ProfileValidity.VALID
    autonomy_level: AutonomyLevel = AutonomyLevel.INVESTIGATE
    scope_version: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.in_scope_assets:
            self.validity = ProfileValidity.BLOCKED

    @property
    def fingerprint(self) -> str:
        """Deterministic fingerprint of scope and policy rules."""
        in_sorted = sorted(self.in_scope_assets)
        out_sorted = sorted(self.out_of_scope_assets)
        cats_sorted = sorted(self.permitted_categories)
        prohib_sorted = sorted(self.prohibited_activities)
        blob = json.dumps([
            self.program_id, in_sorted, out_sorted, cats_sorted, prohib_sorted,
            self.rate_limit, self.max_requests, self.scope_version
        ], sort_keys=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]

    def build_scope(self) -> Scope:
        """Construct the authoritative Scope object with deny-by-default semantics."""
        return Scope.from_entries(
            program=self.program_id,
            in_scope=self.in_scope_assets,
            out_of_scope=self.out_of_scope_assets,
        )

    def is_expired(self) -> bool:
        """Check if profile has exceeded its explicit expiration timestamp."""
        if not self.expires_at:
            return False
        from datetime import datetime, timezone
        try:
            exp = datetime.fromisoformat(self.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) > exp
        except Exception:
            return True

    def validate_executable(self) -> tuple[bool, str]:
        """Validate whether this profile can legally execute research tests."""
        if self.validity == ProfileValidity.BLOCKED:
            return False, "program profile is blocked"
        if self.validity == ProfileValidity.EXPIRED or self.is_expired():
            return False, "program profile or scope review timestamp has expired"
        if self.validity == ProfileValidity.SCOPE_CHANGED:
            return False, "program scope changed; human review required before continuing"
        if not self.in_scope_assets:
            return False, "empty in-scope assets (cannot infer permission from wildcard)"
        return True, "profile valid for research"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["validity"] = self.validity.value
        d["autonomy_level"] = self.autonomy_level.value
        d["fingerprint"] = self.fingerprint
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProgramProfile:
        val_str = data.get("validity", ProfileValidity.VALID.value)
        try:
            val = ProfileValidity(val_str)
        except ValueError:
            val = ProfileValidity.VALID

        auto_str = data.get("autonomy_level", AutonomyLevel.INVESTIGATE.value)
        try:
            auto = AutonomyLevel(auto_str)
        except ValueError:
            auto = AutonomyLevel.INVESTIGATE

        return cls(
            program_id=data["program_id"],
            in_scope_assets=data.get("in_scope_assets") or [],
            out_of_scope_assets=data.get("out_of_scope_assets") or [],
            permitted_categories=data.get("permitted_categories") or [
                "authz", "unauth", "cors", "exposed", "headers", "graphql", "open_redirect", "waf_probe"
            ],
            prohibited_activities=data.get("prohibited_activities") or [
                "dos", "credential_stuffing", "unrestricted_fuzzing", "destructive_write"
            ],
            authentication_required=bool(data.get("authentication_required", False)),
            accounts=data.get("accounts"),
            rate_limit=float(data.get("rate_limit", 3.0)),
            max_requests=int(data.get("max_requests", 500)),
            time_budget_seconds=float(data.get("time_budget_seconds", 3600.0)),
            model_cost_limit=float(data.get("model_cost_limit", 10.0)),
            require_human_approval_for_write=bool(data.get("require_human_approval_for_write", True)),
            scope_reviewed_at=data.get("scope_reviewed_at") or now_iso(),
            expires_at=data.get("expires_at"),
            validity=val,
            autonomy_level=auto,
            scope_version=int(data.get("scope_version", 1)),
            metadata=data.get("metadata") or {},
        )


class ScopeChangeDetector:
    """Compares scope revisions, identifies added/removed targets, and handles task invalidation."""

    @staticmethod
    def compare(old_profile: ProgramProfile, new_profile: ProgramProfile) -> dict[str, Any]:
        """Detect differences in scope and permitted categories."""
        old_in = set(old_profile.in_scope_assets)
        new_in = set(new_profile.in_scope_assets)
        old_out = set(old_profile.out_of_scope_assets)
        new_out = set(new_profile.out_of_scope_assets)

        added_in = list(new_in - old_in)
        removed_in = list(old_in - new_in)
        added_out = list(new_out - old_out)
        removed_out = list(old_out - new_out)

        old_cats = set(old_profile.permitted_categories)
        new_cats = set(new_profile.permitted_categories)
        policy_modified = (old_cats != new_cats) or (old_profile.prohibited_activities != new_profile.prohibited_activities)

        changed = bool(added_in or removed_in or added_out or removed_out or policy_modified)

        return {
            "has_changes": changed,
            "added_in_scope": added_in,
            "removed_in_scope": removed_in,
            "added_out_of_scope": added_out,
            "removed_out_of_scope": removed_out,
            "policy_modified": policy_modified,
            "old_version": old_profile.scope_version,
            "new_version": new_profile.scope_version,
        }

    @staticmethod
    def invalidate_pending_tasks(store: Any, new_scope: Scope, run_id: str | None = None) -> int:
        """Scan pending tasks in SQLite and cancel/block any whose target is no longer in scope."""
        # Find all pending/running tasks
        rows = store.conn.execute(
            "SELECT fingerprint, target, state FROM tasks WHERE state IN ('pending', 'running')"
        ).fetchall()
        invalidated = 0
        for r in rows:
            tgt = r["target"]
            fp = r["fingerprint"]
            dec = new_scope.check(tgt)
            if not dec.allowed:
                store.task_finish(
                    fp,
                    state="skipped",
                    result={"reason": f"scope invalidated: {dec.reason}"}
                )
                invalidated += 1
        return invalidated
