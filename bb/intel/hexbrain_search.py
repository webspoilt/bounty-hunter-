"""Query normalization, facet validation, and search builder for HexBrain."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from bb.intel.hexbrain_models import SearchQuery

CWE_PATTERN = re.compile(r"^(CWE-)?(\d+)$", re.IGNORECASE)


def normalize_cwe_id(cwe_val: Optional[str]) -> Optional[str]:
    """Normalize user input like '89', 'cwe89', 'cwe-89' to canonical 'CWE-89'."""
    if not cwe_val:
        return None
    cleaned = cwe_val.strip()
    m = CWE_PATTERN.match(cleaned)
    if m:
        return f"CWE-{m.group(2)}"
    return cleaned.upper()


def build_search_query(
    raw_query: str,
    cwe: Optional[str] = None,
    vuln_type: Optional[str] = None,
    technology: Optional[str] = None,
    program: Optional[str] = None,
    limit: int = 10,
    offset: int = 0,
    training_eligible: bool = False,
) -> SearchQuery:
    """Sanitize and construct a validated SearchQuery."""
    clean_query = raw_query.strip()
    norm_cwe = normalize_cwe_id(cwe)
    
    # Auto-extract CWE if embedded in query string (e.g. "CWE-79 reflected XSS")
    if not norm_cwe:
        cwe_match = re.search(r"\b(CWE-\d+)\b", clean_query, re.IGNORECASE)
        if cwe_match:
            norm_cwe = cwe_match.group(1).upper()

    return SearchQuery(
        query=clean_query,
        cwe_id=norm_cwe,
        vulnerability_type=vuln_type.strip().lower() if vuln_type else None,
        technology=technology.strip().lower() if technology else None,
        program=program.strip().lower() if program else None,
        limit=max(1, min(100, limit)),
        offset=max(0, offset),
        require_training_eligible=training_eligible,
    )
