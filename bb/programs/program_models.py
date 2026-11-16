"""Data models for HackerOne program discovery, eligibility, attack surface, and ranking."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ProgramEligibilityState(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    INACTIVE = "INACTIVE"
    PRIVATE = "PRIVATE"
    NO_MONETARY_BOUNTY = "NO_MONETARY_BOUNTY"
    NO_QUALIFYING_WEB_OR_API_ASSET = "NO_QUALIFYING_WEB_OR_API_ASSET"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    SCOPE_UNCLEAR = "SCOPE_UNCLEAR"
    AUTHORIZATION_UNCLEAR = "AUTHORIZATION_UNCLEAR"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    EXCLUDED = "EXCLUDED"


class AIClassification(str, Enum):
    CONFIRMED_AI_BUILT = "CONFIRMED_AI_BUILT"
    PROBABLE_AI_BUILT = "PROBABLE_AI_BUILT"
    AI_PRODUCT = "AI_PRODUCT"
    UNKNOWN = "UNKNOWN"


class PriorityTier(str, Enum):
    HIGH_PRIORITY = "HIGH_PRIORITY"      # 80 - 100
    GOOD_CANDIDATE = "GOOD_CANDIDATE"    # 65 - 79
    MODERATE = "MODERATE"                # 50 - 64
    LOW_PRIORITY = "LOW_PRIORITY"        # < 50


@dataclass
class AIEvidenceRecord:
    """Documented public evidence regarding an application's development methodology."""
    classification: AIClassification
    evidence_description: str
    source_url: str
    source_organization: str
    publication_date: Optional[str] = None
    retrieval_date: str = ""
    evidence_confidence: float = 0.0  # 0.0 to 1.0
    supporting_summary: str = ""
    is_primary: bool = True


@dataclass
class ProgramAsset:
    """Represents an in-scope or out-of-scope asset."""
    asset_identifier: str
    asset_type: str  # URL, CIDR, DOMAIN, OTHER
    eligible_for_bounty: bool = True
    instruction: str = ""
    max_severity: Optional[str] = None


@dataclass
class ScoreCriterion:
    """Individual component score of the 100-point opportunity rating."""
    name: str
    weight: float
    raw_score: float         # 0 - 100
    normalized_score: float  # raw_score * weight / 100
    confidence: float        # 0 - 100
    explanation: str
    evidence_source: str


@dataclass
class ResearchOpportunity:
    """Potential security research hypothesis for an application."""
    category: str
    cwe_id: str
    supporting_observation: str
    matching_engine: str
    confidence: float
    expected_access: str
    why_relevant: str


@dataclass
class DiscoveredProgram:
    """Normalized, enriched HackerOne bounty program entity."""
    program_id: str
    handle: str
    name: str
    url: str
    state: str  # public_mode, etc.
    submission_state: str  # open, paused, etc.
    offers_bounties: bool
    currency: str = "USD"
    min_bounty: Optional[float] = None
    max_bounty: Optional[float] = None
    policy_text: str = ""
    policy_hash: str = ""
    retrieved_at: str = ""
    
    # Eligibility & Gate
    eligibility_state: ProgramEligibilityState = ProgramEligibilityState.MANUAL_REVIEW_REQUIRED
    eligibility_reasons: List[str] = field(default_factory=list)
    
    # Scope & Assets
    in_scope_assets: List[ProgramAsset] = field(default_factory=list)
    out_of_scope_assets: List[ProgramAsset] = field(default_factory=list)
    prohibited_techniques: List[str] = field(default_factory=list)
    testing_instructions: str = ""
    safe_harbor: str = ""
    
    # AI Development & Technology
    ai_classification: AIClassification = AIClassification.UNKNOWN
    ai_evidence: List[AIEvidenceRecord] = field(default_factory=list)
    product_type: str = "SaaS"
    technologies: List[str] = field(default_factory=list)
    features_detected: List[str] = field(default_factory=list)
    
    # Attack Surface
    has_rest_api: bool = False
    has_graphql: bool = False
    is_multi_tenant: bool = False
    has_auth_workflows: bool = False
    has_ai_features: bool = False
    
    # Scoring & Opportunities
    opportunity_score: float = 0.0
    evidence_confidence: float = 0.0
    priority_tier: PriorityTier = PriorityTier.LOW_PRIORITY
    score_breakdown: List[ScoreCriterion] = field(default_factory=list)
    research_opportunities: List[ResearchOpportunity] = field(default_factory=list)
    
    # Metadata & User Selection
    is_selected: bool = False
    is_rejected: bool = False
    selection_notes: str = ""
    raw_attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_id": self.program_id,
            "handle": self.handle,
            "name": self.name,
            "url": self.url,
            "state": self.state,
            "submission_state": self.submission_state,
            "offers_bounties": self.offers_bounties,
            "currency": self.currency,
            "min_bounty": self.min_bounty,
            "max_bounty": self.max_bounty,
            "policy_hash": self.policy_hash,
            "retrieved_at": self.retrieved_at,
            "eligibility_state": self.eligibility_state.value,
            "eligibility_reasons": self.eligibility_reasons,
            "in_scope_count": len(self.in_scope_assets),
            "out_of_scope_count": len(self.out_of_scope_assets),
            "ai_classification": self.ai_classification.value,
            "opportunity_score": round(self.opportunity_score, 1),
            "evidence_confidence": round(self.evidence_confidence, 1),
            "priority_tier": self.priority_tier.value,
            "is_selected": self.is_selected,
            "is_rejected": self.is_rejected,
        }
