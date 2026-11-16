"""
Startup intelligence data models for Bounty Hunter Phase 14.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any


class SourceAccessMode(str, Enum):
    OFFICIAL_API = "OFFICIAL_API"
    OFFICIAL_FEED = "OFFICIAL_FEED"
    PERMITTED_PUBLIC_PAGE = "PERMITTED_PUBLIC_PAGE"
    RESEARCHER_ASSISTED = "RESEARCHER_ASSISTED"
    MANUAL_IMPORT = "MANUAL_IMPORT"
    BLOCKED_BY_SOURCE_POLICY = "BLOCKED_BY_SOURCE_POLICY"


class HiringCategory(str, Enum):
    BACKEND = "BACKEND"
    FRONTEND = "FRONTEND"
    INFRASTRUCTURE = "INFRASTRUCTURE"  # DevOps, Platform, SRE, Cloud
    SECURITY = "SECURITY"              # AppSec, Product Security, SecOps
    AI_ML = "AI_ML"                    # LLM, Agent, ML, AI Platform
    GENERAL_ENGINEERING = "GENERAL_ENGINEERING"


class AIClassification(str, Enum):
    CONFIRMED_AI_BUILT = "CONFIRMED_AI_BUILT"
    PROBABLE_AI_BUILT = "PROBABLE_AI_BUILT"
    AI_PRODUCT = "AI_PRODUCT"
    UNKNOWN = "UNKNOWN"


class GrowthConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    REPORTED_BY_RELIABLE_SOURCE = "REPORTED_BY_RELIABLE_SOURCE"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class ResearchSaturation(str, Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


@dataclass
class JobListing:
    company_name: str
    job_title: str
    source_url: str
    hiring_category: HiringCategory
    posting_date: Optional[str] = None
    retrieval_date: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    location: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    source_name: str = "unknown"
    is_active: bool = True
    confidence: float = 1.0


@dataclass
class GrowthSignal:
    company_name: str
    signal_type: str  # funding_round, product_launch, api_announcement, team_expansion
    title: str
    details: str
    source_url: str
    source_date: Optional[str] = None
    confidence: GrowthConfidence = GrowthConfidence.REPORTED_BY_RELIABLE_SOURCE


@dataclass
class StartupProfile:
    company_name: str
    canonical_domain: str
    website: str
    description: str = ""
    yc_batch: Optional[str] = None
    launch_date: Optional[str] = None
    funding_info: Optional[str] = None
    funding_confidence: GrowthConfidence = GrowthConfidence.UNKNOWN
    product_category: str = "SaaS"
    is_multi_tenant: bool = False
    has_apis: bool = False
    ai_classification: AIClassification = AIClassification.UNKNOWN
    ai_evidence: str = ""
    
    # Hiring Signals
    job_listings: List[JobListing] = field(default_factory=list)
    hiring_categories: List[HiringCategory] = field(default_factory=list)
    is_currently_hiring: bool = False
    
    # Growth Signals
    growth_signals: List[GrowthSignal] = field(default_factory=list)
    
    # Bounty / VDP Cross-reference
    bounty_program_platform: Optional[str] = None  # HackerOne, Bugcrowd, Intigriti, Self-hosted
    bounty_program_handle: Optional[str] = None
    bounty_status: str = "NO_ACTIVE_AUTHORIZED_PROGRAM"
    bounty_min: Optional[int] = None
    bounty_max: Optional[int] = None
    in_scope_assets: List[str] = field(default_factory=list)
    out_of_scope_assets: List[str] = field(default_factory=list)
    policy_fingerprint: Optional[str] = None
    
    # HexBrain Intelligence
    hexbrain_report_count: int = 0
    hexbrain_top_cwes: List[str] = field(default_factory=list)
    hexbrain_payouts_total: float = 0.0
    
    # Scoring & Saturation
    opportunity_score: float = 0.0
    score_breakdown: Dict[str, float] = field(default_factory=dict)
    research_saturation: ResearchSaturation = ResearchSaturation.UNKNOWN
    evidence_confidence: float = 0.8
    research_recommendations: List[str] = field(default_factory=list)
    ranking_rationale: str = ""
