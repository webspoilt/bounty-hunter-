"""Common schema mapping and entity normalization for heterogeneous security records."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from bb.intel.hexbrain_models import HexBrainReport
from bb.intel.hexbrain_search import normalize_cwe_id
from bb.intel.ingestion.provenance import ProvenanceTracker


SEVERITY_MAP = {
    "none": "none",
    "info": "none",
    "informational": "none",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "important": "high",
    "critical": "critical",
}

TECH_KEYWORDS = [
    "wordpress", "php", "nodejs", "python", "flask", "django", "fastapi",
    "react", "angular", "vue", "graphql", "rest", "oauth", "jwt",
    "saml", "aws", "s3", "azure", "gcp", "docker", "kubernetes",
    "mysql", "postgres", "mongodb", "redis", "nginx", "apache", "ruby", "rails"
]


def map_severity(raw: Optional[str]) -> str:
    if not raw:
        return "unknown"
    cleaned = raw.strip().lower()
    return SEVERITY_MAP.get(cleaned, "unknown")


def extract_technologies(text: str) -> List[str]:
    """Detect mentioned technologies in vulnerability descriptions."""
    found = []
    text_lower = text.lower()
    for tech in TECH_KEYWORDS:
        if re.search(r"\b" + re.escape(tech) + r"\b", text_lower):
            found.append(tech)
    return sorted(list(set(found)))


def normalize_record(
    raw_data: Dict[str, Any],
    source_name: str,
    default_license: str = "public_metadata",
) -> HexBrainReport:
    """Normalize raw heterogeneous record into canonical HexBrainReport schema."""
    report_id = str(raw_data.get("id") or raw_data.get("report_id") or raw_data.get("h1_id") or "")
    title = str(raw_data.get("title") or raw_data.get("name") or "Untitled Vulnerability Report").strip()
    
    # Extract & normalize CWE
    raw_cwe = raw_data.get("cwe") or raw_data.get("cwe_id") or raw_data.get("weakness")
    cwe_id = normalize_cwe_id(str(raw_cwe)) if raw_cwe else None
    if not cwe_id:
        # Search in title
        m = re.search(r"\b(CWE-\d+)\b", title, re.IGNORECASE)
        if m:
            cwe_id = m.group(1).upper()

    summary = ProvenanceTracker.sanitize_text(str(raw_data.get("summary") or ""))
    details = ProvenanceTracker.sanitize_text(str(raw_data.get("details") or raw_data.get("vulnerability_details") or raw_data.get("body") or ""))
    repro = ProvenanceTracker.sanitize_text(str(raw_data.get("reproduction_steps") or raw_data.get("steps") or ""))
    impact = ProvenanceTracker.sanitize_text(str(raw_data.get("impact") or ""))
    remediation = ProvenanceTracker.sanitize_text(str(raw_data.get("remediation") or ""))

    combined_text = f"{title} {summary} {details}"
    techs = extract_technologies(combined_text)

    # Determine licensing & training eligibility
    training_ok, _ = ProvenanceTracker.determine_training_eligibility(default_license, source_name)

    bounty = 0.0
    raw_bounty = raw_data.get("bounty_amount") or raw_data.get("bounty")
    if raw_bounty:
        try:
            # Handle string like "$1,500.00"
            clean_b = re.sub(r"[^\d.]", "", str(raw_bounty))
            if clean_b:
                bounty = float(clean_b)
        except Exception:
            bounty = 0.0

    return HexBrainReport(
        report_id=report_id,
        title=title,
        source=source_name,
        source_url=str(raw_data.get("url") or raw_data.get("source_url") or ""),
        cwe_id=cwe_id,
        cwe_title=raw_data.get("cwe_title"),
        vulnerability_type=str(raw_data.get("vuln_type") or raw_data.get("type") or "generic"),
        severity=map_severity(raw_data.get("severity")),
        bounty_amount=bounty,
        disclosed_at=str(raw_data.get("disclosed_at") or raw_data.get("date") or ""),
        program_handle=raw_data.get("program") or raw_data.get("program_handle"),
        program_name=raw_data.get("program_name"),
        summary=summary,
        vulnerability_details=details,
        reproduction_steps=repro,
        impact=impact,
        remediation=remediation,
        technologies=techs,
        tags=list(raw_data.get("tags", [])),
        license=default_license,
        training_eligible=training_ok,
        metadata={"normalized": True, "raw_keys": list(raw_data.keys())},
    )
