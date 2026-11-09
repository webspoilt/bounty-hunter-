"""Security Intelligence Models.

Normalized intelligence models and data structures for vulnerability intelligence,
weaknesses, attack patterns, advisories, disclosed research, and adaptive feedback.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from bb.config import now_iso


@dataclass
class VersionConstraint:
    """Explicit version applicability constraint.

    A product-name match alone must NEVER establish vulnerability applicability.
    """
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    exact_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VersionConstraint:
        return cls(
            version_start_including=data.get("version_start_including"),
            version_start_excluding=data.get("version_start_excluding"),
            version_end_including=data.get("version_end_including"),
            version_end_excluding=data.get("version_end_excluding"),
            exact_version=data.get("exact_version"),
        )


@dataclass
class IntelligenceRecord:
    """Normalized security intelligence record preserving source provenance and validity."""
    id: str                                  # Stable primary identifier: e.g. CVE-2023-1234, CWE-89, CAPEC-63, GHSA-...
    source: str                              # Source name: nvd, cve, cwe, capec, advisory, patch, disclosure, research
    source_id: str                           # Stable identifier in the source repository
    source_url: str                          # Provenance URL
    title: str                               # Descriptive title
    description: str                         # Technical description
    vuln_class: str                          # Normalized vulnerability / weakness class (e.g. IDOR, SQLi, XSS)
    retrieved_at: str                        # Retrieval timestamp (ISO-8601)
    published_at: str | None = None          # Publication date if available
    updated_at: str | None = None            # Modification date if available
    affected_product: str | None = None      # Target product name
    affected_component: str | None = None    # Specific component / module / endpoint
    version_constraints: list[VersionConstraint] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)        # Associated CWE identifiers
    capec_ids: list[str] = field(default_factory=list)      # Associated CAPEC attack patterns
    references: list[str] = field(default_factory=list)     # Reference URLs / advisories
    cvss_score: float | None = None          # Base CVSS score if available
    severity: str | None = None              # critical, high, medium, low, info
    data_freshness: str | None = None        # fresh, stale, archived
    parse_status: str = "valid"              # valid, incomplete, malformed
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["version_constraints"] = [vc.to_dict() for vc in self.version_constraints]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IntelligenceRecord:
        vcs = [
            VersionConstraint.from_dict(vc) if isinstance(vc, dict) else vc
            for vc in data.get("version_constraints") or []
        ]
        return cls(
            id=data["id"],
            source=data["source"],
            source_id=data.get("source_id", data["id"]),
            source_url=data.get("source_url", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            vuln_class=data.get("vuln_class", "unknown"),
            retrieved_at=data.get("retrieved_at") or now_iso(),
            published_at=data.get("published_at"),
            updated_at=data.get("updated_at"),
            affected_product=data.get("affected_product"),
            affected_component=data.get("affected_component"),
            version_constraints=vcs,
            cwe_ids=data.get("cwe_ids") or [],
            capec_ids=data.get("capec_ids") or [],
            references=data.get("references") or [],
            cvss_score=data.get("cvss_score"),
            severity=data.get("severity"),
            data_freshness=data.get("data_freshness"),
            parse_status=data.get("parse_status", "valid"),
            meta=data.get("meta") or {},
        )


@dataclass
class HypothesisOutcomeRecord:
    """Historical record of an investigated hypothesis for adaptive feedback."""
    hypothesis_id: str                       # Unique hypothesis ID
    program: str                             # Target program or application name
    endpoint: str                            # Target endpoint (e.g. /api/v1/user)
    method: str                              # HTTP method
    vuln_class: str                          # Category: IDOR, Broken Authentication, etc.
    supporting_intelligence_ids: list[str]   # Intelligence IDs referenced (CVE, CWE, CAPEC, etc.)
    supporting_observations: list[str]       # Observed evidence or parameters
    proposed_test: str                       # Description or identifier of proposed test
    executed: bool = False                   # Whether the test was actually executed
    result: str = "unknown"                  # confirmed, rejected, inconclusive, duplicate, unknown
    verification_result: str | None = None   # confirmed, rejected, inconclusive, none
    researcher_review: str | None = None     # approved, rejected, modified, unreviewed
    final_report_outcome: str | None = None  # accepted, duplicate, informative, rejected, none
    model_version: str | None = None         # Model name/version used for generation
    prompt_version: str | None = None        # Prompt version
    requests_cost: int = 0                   # Number of HTTP requests consumed
    duration_ms: float = 0.0                 # Latency in ms
    created_at: str = field(default_factory=now_iso)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HypothesisOutcomeRecord:
        return cls(
            hypothesis_id=data["hypothesis_id"],
            program=data.get("program", ""),
            endpoint=data.get("endpoint", ""),
            method=data.get("method", "GET"),
            vuln_class=data.get("vuln_class", "unknown"),
            supporting_intelligence_ids=data.get("supporting_intelligence_ids") or [],
            supporting_observations=data.get("supporting_observations") or [],
            proposed_test=data.get("proposed_test", ""),
            executed=bool(data.get("executed", False)),
            result=data.get("result", "unknown"),
            verification_result=data.get("verification_result"),
            researcher_review=data.get("researcher_review"),
            final_report_outcome=data.get("final_report_outcome"),
            model_version=data.get("model_version"),
            prompt_version=data.get("prompt_version"),
            requests_cost=int(data.get("requests_cost", 0)),
            duration_ms=float(data.get("duration_ms", 0.0)),
            created_at=data.get("created_at") or now_iso(),
            notes=data.get("notes", ""),
        )
