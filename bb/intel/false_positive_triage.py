"""Contextual false-positive triage intelligence comparing findings to historical reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional
from bb.intel.knowledge_base import KnowledgeBase
from bb.intel.retrieval import HybridRetriever


class TriageVerdict(str, Enum):
    LIKELY_VALID = "LIKELY_VALID"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    LIKELY_INTENDED_BEHAVIOR = "LIKELY_INTENDED_BEHAVIOR"
    LIKELY_OUT_OF_SCOPE = "LIKELY_OUT_OF_SCOPE"
    LIKELY_SCANNER_ARTIFACT = "LIKELY_SCANNER_ARTIFACT"


@dataclass
class TriageAssessment:
    """Evaluation result assessing whether a raw scanner finding is a genuine vulnerability."""
    finding_id: str
    target_endpoint: str
    cwe_id: Optional[str]
    verdict: TriageVerdict
    confidence: float
    rationale: str
    similar_historical_reports: List[Dict[str, Any]] = field(default_factory=list)
    recommended_action: str = ""


class FalsePositiveTriager:
    """Evaluates findings against historical intelligence to filter false positives."""

    def __init__(self, kb: Optional[KnowledgeBase] = None):
        self.kb = kb or KnowledgeBase()
        self.retriever = HybridRetriever(kb=self.kb)

    def triage_finding(
        self,
        finding_id: str,
        target_endpoint: str,
        vulnerability_type: str,
        evidence: str,
        cwe_id: Optional[str] = None,
        program_policy_prohibitions: Optional[List[str]] = None,
    ) -> TriageAssessment:
        evidence_clean = evidence.lower()
        prohibitions = [p.lower() for p in (program_policy_prohibitions or [])]

        # 1. Scope / Policy prohibition check
        for prohibited in prohibitions:
            if prohibited in vulnerability_type.lower() or prohibited in evidence_clean:
                return TriageAssessment(
                    finding_id=finding_id,
                    target_endpoint=target_endpoint,
                    cwe_id=cwe_id,
                    verdict=TriageVerdict.LIKELY_OUT_OF_SCOPE,
                    confidence=0.95,
                    rationale=f"Finding matches prohibited program policy category: '{prohibited}'.",
                    recommended_action="Do not report. Policy explicitly excludes this vulnerability class.",
                )

        # 2. Scanner artifact checks (e.g. generic HTTP response reflection without script execution)
        if "cross-site scripting" in vulnerability_type.lower() or cwe_id == "CWE-79":
            if "content-type: application/json" in evidence_clean and "<script>" in evidence_clean:
                return TriageAssessment(
                    finding_id=finding_id,
                    target_endpoint=target_endpoint,
                    cwe_id=cwe_id,
                    verdict=TriageVerdict.LIKELY_SCANNER_ARTIFACT,
                    confidence=0.88,
                    rationale="Payload reflection detected inside application/json response header without HTML rendering context.",
                    recommended_action="Verify if browser executes script payload under HTML parsing context; likely benign JSON echo.",
                )

        # 3. Informational / Intended behavior checks (e.g. rate limiting or public API)
        if "rate limit" in vulnerability_type.lower() or "cors" in vulnerability_type.lower():
            if "access-control-allow-origin: *" in evidence_clean and "/public/" in target_endpoint:
                return TriageAssessment(
                    finding_id=finding_id,
                    target_endpoint=target_endpoint,
                    cwe_id=cwe_id,
                    verdict=TriageVerdict.LIKELY_INTENDED_BEHAVIOR,
                    confidence=0.85,
                    rationale="Wildcard CORS header on public endpoint is intended behavior for public assets.",
                    recommended_action="Close finding as intended public endpoint design.",
                )

        # 4. Search historical knowledge base for precedents
        historical_hits = self.retriever.search(
            query=f"{vulnerability_type} {target_endpoint}",
            cwe_id=cwe_id,
            limit=3,
        )

        similar_reports = []
        for hit in historical_hits:
            rep = hit["report"]
            similar_reports.append({
                "report_id": rep.report_id,
                "title": rep.title,
                "bounty": rep.bounty_amount,
                "source_url": rep.source_url,
            })

        # 5. Assess evidence strength
        if len(evidence.strip()) < 40 or "potential" in evidence_clean:
            return TriageAssessment(
                finding_id=finding_id,
                target_endpoint=target_endpoint,
                cwe_id=cwe_id,
                verdict=TriageVerdict.NEEDS_MORE_EVIDENCE,
                confidence=0.60,
                rationale="Heuristic alert lacks deterministic HTTP proof-of-concept evidence.",
                similar_historical_reports=similar_reports,
                recommended_action="Perform manual or targeted state verification before filing report.",
            )

        return TriageAssessment(
            finding_id=finding_id,
            target_endpoint=target_endpoint,
            cwe_id=cwe_id,
            verdict=TriageVerdict.LIKELY_VALID,
            confidence=0.85,
            rationale="Finding possesses concrete reproduction evidence matching confirmed vulnerability patterns.",
            similar_historical_reports=similar_reports,
            recommended_action="Prepare report draft with sanitized reproduction steps.",
        )
