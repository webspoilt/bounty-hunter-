"""Data shapes shared by every layer."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from bb.config import now_iso

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def sev_rank(severity: str) -> int:
    return _SEV_RANK.get(severity.lower(), 0)


@dataclass
class Exchange:
    """One request/response pair, already redacted before it ever gets here."""
    method: str
    url: str
    status: int
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    duration_ms: int = 0
    at: str = field(default_factory=now_iso)
    note: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d: dict) -> "Exchange":
        keys = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in keys})


@dataclass
class Evidence:
    summary: str
    exchange: Exchange | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "exchange": self.exchange.to_dict() if self.exchange else None,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        ex = d.get("exchange")
        return cls(summary=d.get("summary", ""),
                   exchange=Exchange.from_dict(ex) if ex else None,
                   extra=d.get("extra") or {})


@dataclass
class Finding:
    title: str
    bug_class: str
    severity: str = "medium"
    confidence: str = "medium"
    host: str = ""
    url: str = ""
    status: str = "candidate"          # candidate | informational | confirmed | rejected
    summary: str = ""
    impact: str = ""
    remediation: str = ""
    steps: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "bug_class": self.bug_class,
            "severity": self.severity, "confidence": self.confidence,
            "host": self.host, "url": self.url, "status": self.status,
            "summary": self.summary, "impact": self.impact,
            "remediation": self.remediation, "steps": self.steps,
            "evidence": [e.to_dict() for e in self.evidence],
            "meta": self.meta, "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            id=d.get("id") or uuid.uuid4().hex[:12],
            title=d.get("title", ""), bug_class=d.get("bug_class", ""),
            severity=d.get("severity", "medium"), confidence=d.get("confidence", "medium"),
            host=d.get("host", ""), url=d.get("url", ""), status=d.get("status", "candidate"),
            summary=d.get("summary", ""), impact=d.get("impact", ""),
            remediation=d.get("remediation", ""), steps=d.get("steps") or [],
            evidence=[Evidence.from_dict(e) for e in (d.get("evidence") or [])],
            meta=d.get("meta") or {}, created_at=d.get("created_at") or now_iso(),
        )
