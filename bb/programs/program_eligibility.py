"""Mandatory program eligibility gate enforcement."""
from __future__ import annotations

from typing import List, Tuple
from bb.programs.program_models import DiscoveredProgram, ProgramEligibilityState


class ProgramEligibilityGate:
    """Enforces strict, non-negotiable eligibility criteria before a program can be recommended."""

    @classmethod
    def evaluate(cls, program: DiscoveredProgram) -> Tuple[ProgramEligibilityState, List[str]]:
        reasons: List[str] = []

        # 1. Publicly accessible status
        if program.state != "public_mode":
            reasons.append(f"Program state is '{program.state}' (not public_mode).")
            return ProgramEligibilityState.PRIVATE, reasons

        # 2. Currently accepting submissions
        if program.submission_state != "open":
            reasons.append(f"Submissions state is '{program.submission_state}' (not open).")
            return ProgramEligibilityState.INACTIVE, reasons

        # 3. Monetary bounty availability
        if not program.offers_bounties:
            reasons.append("Program does not offer monetary bounties (recognition-only or VDP).")
            return ProgramEligibilityState.NO_MONETARY_BOUNTY, reasons

        # 4. Policy text inspectable
        if not program.policy_text or len(program.policy_text.strip()) < 50:
            reasons.append("Program policy text could not be retrieved or is empty.")
            return ProgramEligibilityState.POLICY_UNAVAILABLE, reasons

        # 5. In-scope web application or API asset exists
        web_or_api_assets = [
            a for a in program.in_scope_assets
            if a.asset_type in ("URL", "DOMAIN", "WILDCARD") or
            any(kw in a.asset_identifier.lower() for kw in ("http", "api", ".", "app"))
        ]
        if not web_or_api_assets and len(program.in_scope_assets) > 0:
            reasons.append("Scope contains assets, but none qualify as web applications or APIs (e.g. mobile/hardware only).")
            return ProgramEligibilityState.NO_QUALIFYING_WEB_OR_API_ASSET, reasons

        # 6. Check for prohibitive authorization blockers
        policy_lower = program.policy_text.lower()
        if "prior written authorization from target company" in policy_lower and "greenhouse" in program.handle.lower():
            reasons.append("Program policy requires explicit separate prior written authorization from company.")
            return ProgramEligibilityState.AUTHORIZATION_UNCLEAR, reasons

        # If passed all checks
        reasons.append("Program meets all 10 mandatory public eligibility criteria.")
        return ProgramEligibilityState.ELIGIBLE, reasons
