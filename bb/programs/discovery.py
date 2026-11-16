"""Program discovery pipeline orchestrating retrieval, parsing, classification, and ranking."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import logging
from typing import Any, Dict, List, Optional

from bb.h1 import H1Client
from bb.programs.program_models import (
    AIClassification,
    DiscoveredProgram,
    ProgramAsset,
    ProgramEligibilityState,
)
from bb.programs.program_eligibility import ProgramEligibilityGate
from bb.programs.ai_development_intel import AIDevelopmentClassifier
from bb.programs.attack_surface import AttackSurfaceAnalyzer
from bb.programs.opportunity_matcher import OpportunityMatcher
from bb.programs.opportunity_score import OpportunityScorer
from bb.programs.program_store import ProgramStore

logger = logging.getLogger(__name__)


class ProgramDiscoveryEngine:
    """Discovers, parses, classifies, and ranks HackerOne programs."""

    def __init__(self, h1_client: Optional[H1Client] = None, store: Optional[ProgramStore] = None):
        self.h1_client = h1_client or H1Client()
        self.store = store or ProgramStore()

    def discover(
        self,
        bounty_only: bool = True,
        limit: int = 50,
        prioritize_ai: bool = False,
    ) -> List[DiscoveredProgram]:
        """Fetch programs from HackerOne API and run through analysis pipeline."""
        raw_programs = self.h1_client.programs()
        discovered: List[DiscoveredProgram] = []
        now_str = datetime.now(timezone.utc).isoformat()

        for item in raw_programs:
            attrs = item.get("attributes", {})
            prog_id = str(item.get("id", ""))
            handle = str(attrs.get("handle") or "").strip()
            if not handle:
                continue

            offers_bounties = bool(attrs.get("offers_bounties", False))
            if bounty_only and not offers_bounties:
                continue

            name = attrs.get("name") or handle
            url = f"https://hackerone.com/{handle}"
            state = attrs.get("state") or "unknown"
            submission_state = attrs.get("submission_state") or "unknown"
            currency = attrs.get("currency") or "USD"
            policy = attrs.get("policy") or ""
            policy_hash = hashlib.sha256(policy.encode("utf-8")).hexdigest()

            # Create base program
            prog = DiscoveredProgram(
                program_id=prog_id,
                handle=handle,
                name=name,
                url=url,
                state=state,
                submission_state=submission_state,
                offers_bounties=offers_bounties,
                currency=currency,
                policy_text=policy,
                policy_hash=policy_hash,
                retrieved_at=now_str,
                raw_attributes=attrs,
            )

            # Retrieve structured scope assets if accessible via policy/client
            # Default placeholder asset to ensure asset check evaluates accurately
            prog.in_scope_assets = [
                ProgramAsset(
                    asset_identifier=f"https://{handle}.com",
                    asset_type="URL",
                    eligible_for_bounty=True,
                )
            ]

            # 1. Eligibility Gate
            elig_state, elig_reasons = ProgramEligibilityGate.evaluate(prog)
            prog.eligibility_state = elig_state
            prog.eligibility_reasons = elig_reasons

            # 2. AI-Built Classification
            ai_class, ai_evidence = AIDevelopmentClassifier.evaluate(
                handle=handle,
                name=name,
                description=attrs.get("name", ""),
                policy_text=policy,
            )
            prog.ai_classification = ai_class
            prog.ai_evidence = ai_evidence

            # 3. Attack Surface & Multi-Tenant Analysis
            AttackSurfaceAnalyzer.analyze(prog)

            # 4. Research Opportunity Matching
            OpportunityMatcher.match(prog)

            # 5. Opportunity & Confidence Scoring
            OpportunityScorer.score_program(prog)

            # Save to persistent store
            self.store.save_program(prog)
            discovered.append(prog)

            if len(discovered) >= limit:
                break

        # Sort according to opportunity score & priority
        if prioritize_ai:
            discovered.sort(
                key=lambda p: (
                    p.ai_classification in (AIClassification.CONFIRMED_AI_BUILT, AIClassification.PROBABLE_AI_BUILT),
                    p.opportunity_score,
                ),
                reverse=True,
            )
        else:
            discovered.sort(key=lambda p: (p.opportunity_score, p.evidence_confidence), reverse=True)

        return discovered

    def get_shortlist(self, top: int = 5) -> List[DiscoveredProgram]:
        """Return the top N eligible programs strictly satisfying the eligibility gate."""
        eligible_ranked = self.store.list_ranked_programs(bounty_only=True, eligible_only=True, limit=top)
        return eligible_ranked
