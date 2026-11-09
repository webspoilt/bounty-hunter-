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
from bb.intelligence.versions import check_version_applicable, record_matches_component

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
    "VersionConstraint",
    "check_version_applicable",
    "compute_hypothesis_priors",
    "rank_hypotheses_with_intelligence",
    "record_matches_component",
]
