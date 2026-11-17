"""Draft rule registry with review lifecycle and approval enforcement."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import time
from typing import Any, Dict, List, Optional
import yaml


@dataclass
class DraftRule:
    """Semgrep rule awaiting human review and approval before activation."""
    rule_id: str
    yaml_content: str
    cwe_id: str
    status: str  # "DRAFT", "VALIDATED", "APPROVED", "REJECTED"
    created_at: float
    reviewed_at: Optional[float] = None
    reviewer: Optional[str] = None
    review_notes: str = ""
    validation_results: Dict[str, Any] = field(default_factory=dict)


class RuleRegistry:
    """Manages draft and approved custom static analysis rules."""

    def __init__(self):
        self.rules: Dict[str, DraftRule] = {}

    def register_draft(self, rule_id: str, yaml_content: str, cwe_id: str) -> DraftRule:
        rule = DraftRule(
            rule_id=rule_id,
            yaml_content=yaml_content,
            cwe_id=cwe_id,
            status="DRAFT",
            created_at=time.time(),
        )
        self.rules[rule_id] = rule
        return rule

    def approve_rule(self, rule_id: str, reviewer: str, notes: str = "") -> Optional[DraftRule]:
        rule = self.rules.get(rule_id)
        if not rule:
            return None
        rule.status = "APPROVED"
        rule.reviewed_at = time.time()
        rule.reviewer = reviewer
        rule.review_notes = notes
        return rule

    def reject_rule(self, rule_id: str, reviewer: str, notes: str = "") -> Optional[DraftRule]:
        rule = self.rules.get(rule_id)
        if not rule:
            return None
        rule.status = "REJECTED"
        rule.reviewed_at = time.time()
        rule.reviewer = reviewer
        rule.review_notes = notes
        return rule

    def list_approved_rules(self) -> List[DraftRule]:
        return [r for r in self.rules.values() if r.status == "APPROVED"]

    def list_draft_rules(self) -> List[DraftRule]:
        return [r for r in self.rules.values() if r.status in ("DRAFT", "VALIDATED")]
