"""bb.intelligence package.

Security Intelligence Engine, ingestion adapters, version checking, and adaptive learning.
"""
from __future__ import annotations

from bb.intelligence.adapters import (
    AdvisoryAdapter,
    CapecAdapter,
    CweAdapter,
    NvdCveAdapter,
    ResearchDisclosureAdapter,
)
from bb.intelligence.engine import IntelligenceEngine
from bb.intelligence.learning import (
    compute_hypothesis_priors,
    rank_hypotheses_with_intelligence,
)
from bb.intelligence.models import (
    HypothesisOutcomeRecord,
    IntelligenceRecord,
    VersionConstraint,
)
from bb.intelligence.store import IntelligenceStore
from bb.intelligence.versions import (
    STATE_CLASS_MISMATCH,
    STATE_COMPONENT_MISMATCH,
    STATE_INSUFFICIENT_INFORMATION,
    STATE_POSSIBLY_RELEVANT,
    STATE_PRODUCT_MISMATCH,
    STATE_RELEVANT,
    STATE_VERSION_MATCH_ONLY,
    VALID_RELATIONSHIP_STATES,
    check_version_applicable,
    evaluate_intelligence_relevance,
    record_matches_component,
)

__all__ = [
    "AdvisoryAdapter",
    "CapecAdapter",
    "CweAdapter",
    "HypothesisOutcomeRecord",
    "IntelligenceEngine",
    "IntelligenceRecord",
    "IntelligenceStore",
    "NvdCveAdapter",
    "ResearchDisclosureAdapter",
    "STATE_CLASS_MISMATCH",
    "STATE_COMPONENT_MISMATCH",
    "STATE_INSUFFICIENT_INFORMATION",
    "STATE_POSSIBLY_RELEVANT",
    "STATE_PRODUCT_MISMATCH",
    "STATE_RELEVANT",
    "STATE_VERSION_MATCH_ONLY",
    "VALID_RELATIONSHIP_STATES",
    "VersionConstraint",
    "check_version_applicable",
    "compute_hypothesis_priors",
    "evaluate_intelligence_relevance",
    "rank_hypotheses_with_intelligence",
    "record_matches_component",
]
