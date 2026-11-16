"""Mapping application attack surface to actionable Bounty Hunter research hypotheses."""
from __future__ import annotations

from typing import List
from bb.programs.program_models import DiscoveredProgram, ResearchOpportunity


class OpportunityMatcher:
    """Generates security research hypotheses matching Bounty Hunter's operational engines."""

    @classmethod
    def match(cls, program: DiscoveredProgram) -> List[ResearchOpportunity]:
        opps: List[ResearchOpportunity] = []

        # 1. Broken Access Control / IDOR (bountybot-authz)
        if program.is_multi_tenant or program.has_rest_api:
            opps.append(
                ResearchOpportunity(
                    category="Authorization / IDOR",
                    cwe_id="CWE-639",
                    supporting_observation="Application features multi-tenant team/workspace boundaries and parameterized REST APIs.",
                    matching_engine="bountybot-authz",
                    confidence=0.85,
                    expected_access="Two standard test accounts in separate organizations",
                    why_relevant="Bounty Hunter's authz engine excels at automated differential session analysis on path/UUID identifiers.",
                )
            )

        # 2. Stateful Business Logic / Workflow Invariants (bountybot-scenario)
        if program.has_auth_workflows or "billing" in program.policy_text.lower():
            opps.append(
                ResearchOpportunity(
                    category="Business Logic / Workflow Transition",
                    cwe_id="CWE-840",
                    supporting_observation="Application enforces invitation, role upgrade, or checkout state transitions.",
                    matching_engine="bountybot-scenario",
                    confidence=0.80,
                    expected_access="Standard authenticated user with invite/billing permissions",
                    why_relevant="Scenario runner tests state machine invariants and coupon/token stacking conditions.",
                )
            )

        # 3. AI / LLM Boundary & Data Isolation
        if program.has_ai_features:
            opps.append(
                ResearchOpportunity(
                    category="AI Data Isolation / Cross-Tenant Prompt Leakage",
                    cwe_id="CWE-200",
                    supporting_observation="Application incorporates conversational AI assistants or document RAG retrieval.",
                    matching_engine="bountybot-ai-auditor",
                    confidence=0.75,
                    expected_access="Standard user with uploaded workspace documents",
                    why_relevant="Evaluates whether AI agents can be coerced into retrieving documents belonging to another tenant.",
                )
            )

        # 4. Injection & API Parameter Handling (sqlmap / dalfox)
        if program.has_rest_api or program.has_graphql:
            opps.append(
                ResearchOpportunity(
                    category="API Injection & Reflection",
                    cwe_id="CWE-89",
                    supporting_observation="High-volume query parameters and search filters exposed on public endpoints.",
                    matching_engine="sqlmap / dalfox",
                    confidence=0.70,
                    expected_access="Anonymous or standard API key",
                    why_relevant="Specialist engines verify backend query parameterization and contextual response escaping.",
                )
            )

        program.research_opportunities = opps
        return opps
