"""Explainable 100-point opportunity scoring and separate evidence confidence engine."""
from __future__ import annotations

from typing import List, Tuple
from bb.programs.program_models import (
    AIClassification,
    DiscoveredProgram,
    PriorityTier,
    ScoreCriterion,
)


class OpportunityScorer:
    """Calculates weighted opportunity score (0-100) and evidence confidence (0-100)."""

    @classmethod
    def score_program(cls, program: DiscoveredProgram) -> Tuple[float, float, List[ScoreCriterion]]:
        criteria: List[ScoreCriterion] = []

        # -------------------------------------------------------------
        # 1. Attack surface & authorization complexity (Weight: 25)
        # -------------------------------------------------------------
        raw_as = 20.0
        if program.is_multi_tenant:
            raw_as += 35.0
        if program.has_rest_api:
            raw_as += 25.0
        if program.has_graphql:
            raw_as += 10.0
        if program.has_auth_workflows:
            raw_as += 10.0
        raw_as = min(100.0, raw_as)
        criteria.append(
            ScoreCriterion(
                name="Attack Surface & Authz Complexity",
                weight=25.0,
                raw_score=raw_as,
                normalized_score=round(raw_as * 0.25, 2),
                confidence=85.0,
                explanation=f"Evaluated features: {', '.join(program.features_detected) or 'Basic web presence'}.",
                evidence_source="Public Policy & In-Scope Asset Inspection",
            )
        )

        # -------------------------------------------------------------
        # 2. Scope clarity & testing accessibility (Weight: 20)
        # -------------------------------------------------------------
        raw_sc = 50.0
        in_count = len(program.in_scope_assets)
        if in_count > 0:
            raw_sc += min(30.0, in_count * 5.0)
        if program.testing_instructions:
            raw_sc += 15.0
        if "gold_standard_safe_harbor" in program.raw_attributes or program.safe_harbor:
            raw_sc += 5.0
        raw_sc = min(100.0, raw_sc)
        criteria.append(
            ScoreCriterion(
                name="Scope Clarity & Accessibility",
                weight=20.0,
                raw_score=raw_sc,
                normalized_score=round(raw_sc * 0.20, 2),
                confidence=90.0,
                explanation=f"{in_count} specific in-scope assets identified; explicit instructions documented.",
                evidence_source="Structured Scope Specification",
            )
        )

        # -------------------------------------------------------------
        # 3. Monetary bounty & reward structure (Weight: 15)
        # -------------------------------------------------------------
        raw_bounty = 40.0
        if program.offers_bounties:
            raw_bounty = 70.0
            if program.max_bounty and program.max_bounty >= 5000:
                raw_bounty = 95.0
            elif program.max_bounty and program.max_bounty >= 2000:
                raw_bounty = 85.0
        criteria.append(
            ScoreCriterion(
                name="Monetary Bounty & Reward Structure",
                weight=15.0,
                raw_score=raw_bounty,
                normalized_score=round(raw_bounty * 0.15, 2),
                confidence=90.0,
                explanation=f"Offers monetary bounties. Max reward: {program.currency} {program.max_bounty or 'TBD'}.",
                evidence_source="HackerOne Program Financial Metadata",
            )
        )

        # -------------------------------------------------------------
        # 4. AI-built & vibe-coded evidence (Weight: 10)
        # -------------------------------------------------------------
        raw_ai = 10.0
        conf_ai = 50.0
        ai_exp = "No evidence of AI-assisted or AI-generated development methodology."
        if program.ai_classification == AIClassification.CONFIRMED_AI_BUILT:
            raw_ai = 100.0
            conf_ai = 95.0
            ai_exp = "Confirmed AI-built application via primary engineering source."
        elif program.ai_classification == AIClassification.PROBABLE_AI_BUILT:
            raw_ai = 75.0
            conf_ai = 70.0
            ai_exp = "Probable AI-built architecture supported by program documentation."
        elif program.ai_classification == AIClassification.AI_PRODUCT:
            raw_ai = 45.0
            conf_ai = 80.0
            ai_exp = "AI-powered product features present; underlying development method traditional or unconfirmed."
        criteria.append(
            ScoreCriterion(
                name="AI-Built / Vibe-Coded Development",
                weight=10.0,
                raw_score=raw_ai,
                normalized_score=round(raw_ai * 0.10, 2),
                confidence=conf_ai,
                explanation=ai_exp,
                evidence_source="Public Engineering Documentation & Profile Analysis",
            )
        )

        # -------------------------------------------------------------
        # 5. Program responsiveness & triage quality (Weight: 10)
        # -------------------------------------------------------------
        raw_resp = 75.0
        if program.raw_attributes.get("triage_active"):
            raw_resp = 90.0
        criteria.append(
            ScoreCriterion(
                name="Program Responsiveness & Triage Quality",
                weight=10.0,
                raw_score=raw_resp,
                normalized_score=round(raw_resp * 0.10, 2),
                confidence=85.0,
                explanation="HackerOne triage active with consistent responsiveness.",
                evidence_source="HackerOne Platform SLA & Activity Indicators",
            )
        )

        # -------------------------------------------------------------
        # 6. Research opportunity & competition indicators (Weight: 10)
        # -------------------------------------------------------------
        raw_opp = 70.0
        if len(program.research_opportunities) >= 3:
            raw_opp = 90.0
        criteria.append(
            ScoreCriterion(
                name="Research Opportunity & Target Complexity",
                weight=10.0,
                raw_score=raw_opp,
                normalized_score=round(raw_opp * 0.10, 2),
                confidence=80.0,
                explanation=f"{len(program.research_opportunities)} distinct vulnerability research hypotheses mapped.",
                evidence_source="Attack Surface & Weakness Mapping",
            )
        )

        # -------------------------------------------------------------
        # 7. Compatibility with existing Bounty Hunter engines (Weight: 10)
        # -------------------------------------------------------------
        raw_eng = 70.0
        matched_engines = set(o.matching_engine for o in program.research_opportunities)
        if "bountybot-authz" in matched_engines:
            raw_eng += 15.0
        if "bountybot-scenario" in matched_engines:
            raw_eng += 15.0
        raw_eng = min(100.0, raw_eng)
        criteria.append(
            ScoreCriterion(
                name="Bounty Hunter Engine Compatibility",
                weight=10.0,
                raw_score=raw_eng,
                normalized_score=round(raw_eng * 0.10, 2),
                confidence=95.0,
                explanation=f"Target interfaces directly match operational engines: {', '.join(matched_engines)}.",
                evidence_source="Verified Operational Bounty Hunter Engines",
            )
        )

        # Sum weighted scores
        total_opp = sum(c.normalized_score for c in criteria)
        avg_conf = sum(c.confidence * (c.weight / 100.0) for c in criteria)

        program.opportunity_score = round(total_opp, 1)
        program.evidence_confidence = round(avg_conf, 1)
        program.score_breakdown = criteria

        # Classify Priority Tier
        if total_opp >= 80.0:
            program.priority_tier = PriorityTier.HIGH_PRIORITY
        elif total_opp >= 65.0:
            program.priority_tier = PriorityTier.GOOD_CANDIDATE
        elif total_opp >= 50.0:
            program.priority_tier = PriorityTier.MODERATE
        else:
            program.priority_tier = PriorityTier.LOW_PRIORITY

        return program.opportunity_score, program.evidence_confidence, criteria
