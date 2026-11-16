"""Data models for HexBrain intelligence records, techniques, and weakness entities."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class HexBrainReport:
    """Disclosed vulnerability report metadata and content from HexBrain or public indices."""
    report_id: str
    title: str
    source: str  # e.g. "hexbrain", "hackerone", "h1-disclosed"
    source_url: str
    cwe_id: Optional[str] = None  # e.g. "CWE-89"
    cwe_title: Optional[str] = None
    vulnerability_type: str = "generic"
    severity: str = "unknown"  # none, low, medium, high, critical
    bounty_amount: float = 0.0
    disclosed_at: Optional[str] = None
    program_handle: Optional[str] = None
    program_name: Optional[str] = None
    summary: str = ""
    vulnerability_details: str = ""
    reproduction_steps: str = ""
    impact: str = ""
    remediation: str = ""
    affected_components: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    license: str = "custom"  # "custom", "cc-by", "mit", "public_metadata"
    training_eligible: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "source": self.source,
            "source_url": self.source_url,
            "cwe_id": self.cwe_id,
            "cwe_title": self.cwe_title,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "bounty_amount": self.bounty_amount,
            "disclosed_at": self.disclosed_at,
            "program_handle": self.program_handle,
            "program_name": self.program_name,
            "summary": self.summary,
            "vulnerability_details": self.vulnerability_details,
            "reproduction_steps": self.reproduction_steps,
            "impact": self.impact,
            "remediation": self.remediation,
            "affected_components": self.affected_components,
            "technologies": self.technologies,
            "tags": self.tags,
            "license": self.license,
            "training_eligible": self.training_eligible,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HexBrainReport:
        return cls(
            report_id=str(data.get("report_id", "")),
            title=data.get("title", ""),
            source=data.get("source", "hexbrain"),
            source_url=data.get("source_url", ""),
            cwe_id=data.get("cwe_id"),
            cwe_title=data.get("cwe_title"),
            vulnerability_type=data.get("vulnerability_type", "generic"),
            severity=data.get("severity", "unknown"),
            bounty_amount=float(data.get("bounty_amount", 0.0) or 0.0),
            disclosed_at=data.get("disclosed_at"),
            program_handle=data.get("program_handle"),
            program_name=data.get("program_name"),
            summary=data.get("summary", ""),
            vulnerability_details=data.get("vulnerability_details", ""),
            reproduction_steps=data.get("reproduction_steps", ""),
            impact=data.get("impact", ""),
            remediation=data.get("remediation", ""),
            affected_components=list(data.get("affected_components", [])),
            technologies=list(data.get("technologies", [])),
            tags=list(data.get("tags", [])),
            license=data.get("license", "custom"),
            training_eligible=bool(data.get("training_eligible", False)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class HexBrainTechnique:
    """Security testing technique, methodology, or exploit pattern."""
    technique_id: str
    name: str
    cwe_id: Optional[str] = None
    vulnerability_type: str = "generic"
    description: str = ""
    prerequisites: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    payload_examples: List[str] = field(default_factory=list)
    remediation_guidance: str = ""
    source: str = "hexbrain"
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "cwe_id": self.cwe_id,
            "vulnerability_type": self.vulnerability_type,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "detection_patterns": self.detection_patterns,
            "payload_examples": self.payload_examples,
            "remediation_guidance": self.remediation_guidance,
            "source": self.source,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HexBrainTechnique:
        return cls(
            technique_id=str(data.get("technique_id", "")),
            name=data.get("name", ""),
            cwe_id=data.get("cwe_id"),
            vulnerability_type=data.get("vulnerability_type", "generic"),
            description=data.get("description", ""),
            prerequisites=list(data.get("prerequisites", [])),
            detection_patterns=list(data.get("detection_patterns", [])),
            payload_examples=list(data.get("payload_examples", [])),
            remediation_guidance=data.get("remediation_guidance", ""),
            source=data.get("source", "hexbrain"),
            confidence=float(data.get("confidence", 1.0)),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class SearchQuery:
    """Structured query for hybrid intelligence retrieval."""
    query: str
    cwe_id: Optional[str] = None
    vulnerability_type: Optional[str] = None
    technology: Optional[str] = None
    program: Optional[str] = None
    min_bounty: Optional[float] = None
    limit: int = 10
    offset: int = 0
    require_training_eligible: bool = False
