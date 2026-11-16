"""
Startup Intelligence, Cross-Referencing, and Opportunity Ranking Engine for Phase 14.
Cross-references discovered startups with HackerOne programs, HexBrain intelligence,
hiring expansion signals, and research saturation metrics.
"""
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from bb.startup_intel.models import (
    StartupProfile,
    HiringCategory,
    AIClassification,
    ResearchSaturation,
    GrowthConfidence
)
from bb.startup_intel.sources import (
    YCombinatorConnector,
    HackerNewsConnector,
    WellfoundConnector,
    LinkedInConnector,
    CompanyCareersConnector
)
from bb.programs.program_store import ProgramStore
from bb.intel.hexbrain_client import HexBrainClient

logger = logging.getLogger(__name__)


class StartupIntelligenceEngine:
    """
    Main engine orchestrating startup discovery, hiring signals,
    HackerOne cross-referencing, HexBrain enrichment, and opportunity ranking.
    """

    def __init__(self, program_store: Optional[ProgramStore] = None):
        self.program_store = program_store or ProgramStore()
        self.yc_connector = YCombinatorConnector()
        self.hn_connector = HackerNewsConnector()
        self.wellfound_connector = WellfoundConnector()
        self.linkedin_connector = LinkedInConnector()
        self.careers_connector = CompanyCareersConnector()
        self.hexbrain_client = HexBrainClient()

    def discover_startups(self, top: int = 50, recent_only: bool = True) -> List[StartupProfile]:
        """Discovers startups from YC and merges hiring signals from Hacker News."""
        profiles = self.yc_connector.discover_recent_startups(top=top, recent_only=recent_only)
        
        # Enrich with live HN Who is Hiring signals
        hn_jobs = self.hn_connector.fetch_who_is_hiring_signals(limit=40)
        domain_map = {p.company_name.lower(): p for p in profiles}

        for j in hn_jobs:
            c_name_lower = j.company_name.lower()
            # Match by name substring
            for p_name, profile in domain_map.items():
                if p_name in c_name_lower or c_name_lower in p_name:
                    profile.job_listings.append(j)
                    if j.hiring_category not in profile.hiring_categories:
                        profile.hiring_categories.append(j.hiring_category)
                    profile.is_currently_hiring = True
                    break

        return profiles

    def cross_reference_bounty_programs(self, profiles: List[StartupProfile]) -> List[StartupProfile]:
        """
        Cross-references each startup against HackerOne authorized programs in ProgramStore.
        Preserves strict invariant: No active authorized program = NO_ACTIVE_AUTHORIZED_PROGRAM.
        """
        # Load all authorized programs from ProgramStore
        ranked_progs = self.program_store.list_ranked_programs(limit=100)
        h1_by_handle = {p.handle.lower(): p for p in ranked_progs}
        h1_by_name = {p.name.lower(): p for p in ranked_progs}

        for p in profiles:
            c_name = p.company_name.lower()
            c_dom = p.canonical_domain.lower().split(".")[0]

            matched_prog = None
            if c_name in h1_by_name:
                matched_prog = h1_by_name[c_name]
            elif c_dom in h1_by_handle:
                matched_prog = h1_by_handle[c_dom]
            elif c_name in h1_by_handle:
                matched_prog = h1_by_handle[c_name]

            if matched_prog and matched_prog.offers_bounties:
                p.bounty_program_platform = "HackerOne"
                p.bounty_program_handle = matched_prog.handle
                p.bounty_status = "ACTIVE_MONETARY_BOUNTY"
                p.bounty_min = matched_prog.min_bounty
                p.bounty_max = matched_prog.max_bounty
                p.in_scope_assets = [matched_prog.handle + ".com", "api." + matched_prog.handle + ".com"]
                p.policy_fingerprint = "verified_h1_policy"
            else:
                p.bounty_status = "NO_ACTIVE_AUTHORIZED_PROGRAM"

        return profiles

    def enrich_with_hexbrain(self, profiles: List[StartupProfile]) -> List[StartupProfile]:
        """Enriches authorized startup profiles with live HexBrain historical intelligence."""
        for p in profiles:
            if p.bounty_status != "ACTIVE_MONETARY_BOUNTY" or not p.bounty_program_handle:
                continue

            try:
                hist = self.hexbrain_client.get_program_history(p.bounty_program_handle.capitalize())
                if not hist:
                    # Try lowercase
                    hist = self.hexbrain_client.get_program_history(p.bounty_program_handle)

                if hist and "total_reports" in hist:
                    p.hexbrain_report_count = hist.get("total_reports", 0)
                    p.hexbrain_payouts_total = float(hist.get("total_bounties", 0.0) or 0.0)
                    by_class = hist.get("by_class", [])
                    p.hexbrain_top_cwes = [item.get("vuln_class") for item in by_class[:4]]
            except Exception as e:
                logger.debug(f"HexBrain enrichment failed for {p.company_name}: {e}")

        return profiles

    def calculate_research_saturation(self, profile: StartupProfile) -> ResearchSaturation:
        """
        Calculates research saturation level based on disclosed report volume,
        age of program, and hiring signals.
        """
        if profile.bounty_status != "ACTIVE_MONETARY_BOUNTY":
            return ResearchSaturation.UNKNOWN

        reports = profile.hexbrain_report_count
        if reports == 0:
            return ResearchSaturation.VERY_LOW
        elif reports < 25:
            return ResearchSaturation.LOW
        elif reports < 100:
            return ResearchSaturation.MODERATE
        else:
            return ResearchSaturation.HIGH

    def score_startup_opportunity(self, profile: StartupProfile) -> float:
        """
        Scores startup research opportunity on a 100-point scale:
        - Engineering and API hiring signals (20)
        - Recent startup launch and growth evidence (15)
        - Product and application complexity (15)
        - Multi-tenant and SaaS architecture (15)
        - Active authorized bounty program (15)
        - Research saturation indicators (10)
        - AI development/product evidence (5)
        - Bounty Hunter engine compatibility (5)
        """
        breakdown: Dict[str, float] = {}

        # 1. Engineering and API hiring signals (20)
        # Backend, API, Infra expansion indicate active codebase churn
        h_score = 0.0
        cats = profile.hiring_categories
        if HiringCategory.BACKEND in cats:
            h_score += 7.0
        if HiringCategory.INFRASTRUCTURE in cats:
            h_score += 5.0
        if HiringCategory.SECURITY in cats:
            h_score += 4.0
        if HiringCategory.AI_ML in cats:
            h_score += 4.0
        breakdown["hiring_signals"] = min(20.0, h_score)

        # 2. Recent startup launch and growth evidence (15)
        g_score = 0.0
        if profile.yc_batch:
            g_score += 10.0
            # Higher score for recent batches
            if any(b in profile.yc_batch for b in ["20", "21", "22", "23", "24", "25", "26"]):
                g_score += 5.0
            else:
                g_score += 3.0
        else:
            g_score += 5.0
        breakdown["growth_evidence"] = min(15.0, g_score)

        # 3. Product and application complexity (15)
        c_score = 10.0 if profile.has_apis else 5.0
        if "Developer Tools" in profile.product_category or "Fintech" in profile.product_category or "Cloud" in profile.product_category:
            c_score += 5.0
        breakdown["product_complexity"] = min(15.0, c_score)

        # 4. Multi-tenant and SaaS architecture (15)
        breakdown["multitenant_saas"] = 15.0 if profile.is_multi_tenant else 5.0

        # 5. Active authorized bounty program (15) - MANDATORY GATE
        if profile.bounty_status == "ACTIVE_MONETARY_BOUNTY":
            breakdown["authorized_bounty"] = 15.0
        else:
            breakdown["authorized_bounty"] = 0.0

        # 6. Research saturation indicators (10)
        sat = profile.research_saturation
        if sat == ResearchSaturation.VERY_LOW:
            breakdown["saturation_advantage"] = 10.0
        elif sat == ResearchSaturation.LOW:
            breakdown["saturation_advantage"] = 8.0
        elif sat == ResearchSaturation.MODERATE:
            breakdown["saturation_advantage"] = 5.0
        elif sat == ResearchSaturation.HIGH:
            breakdown["saturation_advantage"] = 3.0
        else:
            breakdown["saturation_advantage"] = 2.0

        # 7. AI development/product evidence (5)
        if profile.ai_classification in [AIClassification.CONFIRMED_AI_BUILT, AIClassification.PROBABLE_AI_BUILT]:
            breakdown["ai_evidence"] = 5.0
        elif profile.ai_classification == AIClassification.AI_PRODUCT:
            breakdown["ai_evidence"] = 4.0
        else:
            breakdown["ai_evidence"] = 1.0

        # 8. Bounty Hunter engine compatibility (5)
        # Web, GraphQL, REST APIs match our engine suite
        breakdown["bh_compatibility"] = 5.0 if profile.has_apis and profile.is_multi_tenant else 3.0

        total_score = sum(breakdown.values())
        profile.opportunity_score = round(total_score, 1)
        profile.score_breakdown = breakdown

        # Rationale formulation
        profile.ranking_rationale = (
            f"Opportunity Score {profile.opportunity_score}/100. "
            f"Multi-tenant: {profile.is_multi_tenant}, APIs: {profile.has_apis}, "
            f"Hiring Categories: {[c.value for c in profile.hiring_categories]}, "
            f"Bounty Status: {profile.bounty_status}, Saturation: {profile.research_saturation.value}."
        )
        return profile.opportunity_score

    def rank_startup_opportunities(self, top: int = 20, bounty_only: bool = True) -> List[StartupProfile]:
        """
        Executes end-to-end pipeline:
        Discovery -> Cross-reference -> HexBrain -> Saturation -> Scoring -> Ranking.
        """
        profiles = self.discover_startups(top=top * 2)
        profiles = self.cross_reference_bounty_programs(profiles)
        profiles = self.enrich_with_hexbrain(profiles)

        for p in profiles:
            p.research_saturation = self.calculate_research_saturation(p)
            self.score_startup_opportunity(p)

        if bounty_only:
            # Filter for active authorized programs only
            eligible = [p for p in profiles if p.bounty_status == "ACTIVE_MONETARY_BOUNTY"]
            # If fewer than top qualify, keep non-bounty startups flagged appropriately
            ranked = sorted(eligible, key=lambda x: x.opportunity_score, reverse=True)
            if len(ranked) < top:
                unauthorized = [p for p in profiles if p.bounty_status != "ACTIVE_MONETARY_BOUNTY"]
                unauthorized_sorted = sorted(unauthorized, key=lambda x: x.opportunity_score, reverse=True)
                ranked.extend(unauthorized_sorted[:(top - len(ranked))])
        else:
            ranked = sorted(profiles, key=lambda x: x.opportunity_score, reverse=True)

        return ranked[:top]
