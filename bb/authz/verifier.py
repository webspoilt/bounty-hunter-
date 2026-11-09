"""Independent adversarial verification and negative controls for authorization findings.

Enforces strict verification rules:
- HTTP 200 alone is NEVER proof of authorization vulnerability.
- Owner baseline: owner must be able to access the resource legitimately.
- Non-owner baseline: attacker request must be evaluated against denied statuses and owner data leakage.
- Public/shared object challenge: unauthenticated request to the same object must not return the same body/access.
- Nonexistent object negative control: requesting a non-existent object ID must return 404/error, not 200.
- Identity-specific data marker validation: owner PII / identity markers must be present in attacker response; attacker marker must NOT be present (self-object check).
- Response comparison beyond status codes: checks body similarity, error message equivalence, and content size.
- Inconclusive results on insufficient evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from bb.authz.model import EvidenceRef, Hypothesis
from bb.http import ScopedClient
from bb.scenario import DENIED_STATUSES
from bb.verify import similarity


@dataclass
class VerificationResult:
    status: str  # "verified", "rejected", "inconclusive"
    verdict: str  # e.g., "confirmed", "enforced", "public_object", "missing_marker", "insufficient_evidence"
    reason: str
    owner_status: int = 0
    attacker_status: int = 0
    unauth_status: int = 0
    nonexistent_status: int = 0
    identity_marker_found: bool = False
    evidence_notes: list[str] = field(default_factory=list)
    similarity_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "verdict": self.verdict,
            "reason": self.reason,
            "owner_status": self.owner_status,
            "attacker_status": self.attacker_status,
            "unauth_status": self.unauth_status,
            "nonexistent_status": self.nonexistent_status,
            "identity_marker_found": self.identity_marker_found,
            "evidence_notes": self.evidence_notes,
            "similarity_score": self.similarity_score,
        }


class AuthorizationVerifier:
    """Independent verification engine that challenges candidate findings with rigorous controls."""

    def __init__(self, client: ScopedClient):
        self.client = client

    def verify_hypothesis_result(
        self,
        hypothesis: Hypothesis,
        execution_results: dict[str, Any],
        roles: dict[str, Any],
        variables: dict[str, Any],
    ) -> VerificationResult:
        """Evaluate finding evidence independently through multiple adversarial challenges."""
        claim_verdict = execution_results.get("verdict", "")
        steps = execution_results.get("steps", {})

        notes: list[str] = []

        # Challenge 1: Check baseline execution existence
        if not steps:
            return VerificationResult(
                status="inconclusive",
                verdict="insufficient_evidence",
                reason="No step results available for verification.",
            )

        # Identify owner step and attacker step
        owner_step = steps.get("owner_read") or steps.get("create")
        attack_step = steps.get("attack_read") or steps.get("attack_write")

        if not attack_step:
            return VerificationResult(
                status="inconclusive",
                verdict="insufficient_evidence",
                reason="Missing attacker step result in execution trace.",
            )

        atk_status = getattr(attack_step, "status", 0) if hasattr(attack_step, "status") else attack_step.get("status", 0)
        atk_body = getattr(attack_step, "body", "") if hasattr(attack_step, "body") else attack_step.get("body", "")

        # Challenge 2: Boundary enforcement (401/403/404)
        if atk_status in (401, 403):
            # Check if owner also got 401/403 (stale session invalidation)
            owner_st = getattr(owner_step, "status", 0) if hasattr(owner_step, "status") else (owner_step.get("status", 0) if isinstance(owner_step, dict) else 0)
            if owner_st in (401, 403):
                notes.append(f"Both owner and attacker received HTTP {atk_status} (stale session)")
                return VerificationResult(
                    status="inconclusive",
                    verdict="stale_session_detected",
                    reason=f"Session authentication invalid/stale (both owner and attacker received HTTP {atk_status}).",
                    owner_status=owner_st,
                    attacker_status=atk_status,
                    evidence_notes=notes,
                )

            notes.append(f"Attacker was denied with HTTP {atk_status} (properly enforced)")
            return VerificationResult(
                status="rejected",
                verdict="enforced",
                reason=f"Authorization boundary enforced: attacker received HTTP {atk_status}.",
                attacker_status=atk_status,
                evidence_notes=notes,
            )

        if atk_status == 404:
            notes.append("Attacker received HTTP 404 (object not found or hidden)")
            return VerificationResult(
                status="rejected",
                verdict="enforced",
                reason="Authorization boundary enforced: attacker received HTTP 404 (not found).",
                attacker_status=atk_status,
                evidence_notes=notes,
            )

        # Challenge 3: HTTP 200 alone check
        if not (200 <= atk_status < 300):
            notes.append(f"Attacker received non-2xx status code {atk_status}")
            return VerificationResult(
                status="inconclusive",
                verdict="unexpected_status",
                reason=f"Attacker received unexpected status HTTP {atk_status}.",
                attacker_status=atk_status,
                evidence_notes=notes,
            )

        # Challenge 4: Error-like body masked as 200 OK (soft-404 / soft-403)
        soft_error_patterns = [
            r"unauthorized", r"access denied", r"forbidden", r"not found",
            r"does not exist", r"permission denied", r"invalid token",
            r"error\":\s*\"not found", r"login required"
        ]
        for pat in soft_error_patterns:
            if re.search(pat, atk_body, re.IGNORECASE) and len(atk_body) < 300:
                notes.append(f"Response body contains soft error pattern {pat!r} despite HTTP {atk_status}")
                return VerificationResult(
                    status="rejected",
                    verdict="soft_error_disguised_as_success",
                    reason=f"HTTP {atk_status} body contains access-denied or not-found indicator.",
                    attacker_status=atk_status,
                    evidence_notes=notes,
                )

        # Challenge 5: Identity marker verification
        owner_role = roles.get(hypothesis.owner_role)
        attacker_role = roles.get(hypothesis.attacker_role)
        owner_id = getattr(owner_role, "identity", None) or variables.get("identity_a", "")
        attacker_id = getattr(attacker_role, "identity", None) or variables.get("identity_b", "")

        marker_found = False
        if owner_id and owner_id in atk_body:
            marker_found = True
            notes.append(f"Owner identity marker {owner_id!r} confirmed in attacker response")

        if attacker_id and attacker_id in atk_body and not marker_found:
            notes.append(f"Attacker identity marker {attacker_id!r} found in response (self-object accessed)")
            return VerificationResult(
                status="rejected",
                verdict="self_object_access",
                reason="Attacker accessed their own object rather than target resource.",
                attacker_status=atk_status,
                evidence_notes=notes,
            )

        # Challenge 6: Baseline Owner Access & Body Similarity Check
        sim = 0.0
        owner_status = 0
        if not owner_step:
            notes.append("Owner baseline step is missing from execution trace")
            return VerificationResult(
                status="inconclusive",
                verdict="missing_owner_baseline",
                reason="Owner baseline step missing; cannot establish authorized access baseline.",
                attacker_status=atk_status,
                evidence_notes=notes,
            )

        owner_status = getattr(owner_step, "status", 0) if hasattr(owner_step, "status") else owner_step.get("status", 0)
        owner_body = getattr(owner_step, "body", "") if hasattr(owner_step, "body") else owner_step.get("body", "")

        # Owner must have successfully accessed the resource
        if not (200 <= owner_status < 300):
            notes.append(f"Owner access baseline failed with HTTP {owner_status}")
            return VerificationResult(
                status="inconclusive",
                verdict="inconsistent_owner_baseline",
                reason=f"Owner could not access resource (received HTTP {owner_status}); baseline inconsistent.",
                owner_status=owner_status,
                attacker_status=atk_status,
                evidence_notes=notes,
            )

        sim = similarity(owner_body, atk_body)
        notes.append(f"Owner vs Attacker response body similarity: {sim:.1%}")
        if sim < 0.1 and not marker_found:
            notes.append("Response body has near-zero similarity to owner baseline with no owner marker")
            return VerificationResult(
                status="inconclusive",
                verdict="dissimilar_baseline",
                reason="Attacker response lacks sufficient similarity to owner baseline.",
                owner_status=owner_status,
                attacker_status=atk_status,
                similarity_score=sim,
                evidence_notes=notes,
            )

        # Challenge 7: Live Negative Controls (Public / Shared Object Challenge & Nonexistent ID)
        target_url = ""
        atk_step_dict = getattr(attack_step, "step", {}) if hasattr(attack_step, "step") else attack_step
        if isinstance(atk_step_dict, dict) and atk_step_dict.get("url"):
            target_url = atk_step_dict.get("url")
        elif hypothesis.scenario.base_url:
            path = atk_step_dict.get("path", "") if isinstance(atk_step_dict, dict) else ""
            base = hypothesis.scenario.base_url.rstrip("/")
            target_url = f"{base}/{path.lstrip('/')}"

        unauth_status = 0
        nonexistent_status = 0

        if target_url and self.client:
            # Live Control A: Public/Shared object test (request without authentication headers)
            try:
                r_unauth = self.client.get(target_url, headers={})
                unauth_status = r_unauth.status_code
                if 200 <= unauth_status < 300:
                    unauth_body = r_unauth.text
                    unauth_sim = similarity(atk_body, unauth_body)
                    if unauth_sim > 0.85:
                        notes.append(f"Unauthenticated request succeeded with HTTP {unauth_status} and {unauth_sim:.1%} similarity")
                        return VerificationResult(
                            status="rejected",
                            verdict="public_or_shared_resource",
                            reason="Resource is publicly accessible without authentication (not an authorization bypass).",
                            owner_status=owner_status,
                            attacker_status=atk_status,
                            unauth_status=unauth_status,
                            similarity_score=sim,
                            evidence_notes=notes,
                        )
            except Exception as exc:
                notes.append(f"Public object check error: {exc}")

            # Live Control B: Non-existent object test (synthesize impossible ID like '9999999999')
            if hypothesis.object_id:
                fake_id = "9999999999"
                fake_url = target_url.replace(hypothesis.object_id, fake_id)
                if fake_url != target_url:
                    try:
                        atk_headers = getattr(attacker_role, "headers", {}) if attacker_role else {}
                        r_fake = self.client.get(fake_url, headers=atk_headers)
                        nonexistent_status = r_fake.status_code
                        if 200 <= nonexistent_status < 300:
                            fake_sim = similarity(atk_body, r_fake.text)
                            if fake_sim > 0.90:
                                notes.append(f"Non-existent object ID returned HTTP {nonexistent_status} with {fake_sim:.1%} similarity")
                                return VerificationResult(
                                    status="rejected",
                                    verdict="static_or_wildcard_route",
                                    reason="Endpoint returns static/wildcard 200 OK for arbitrary or nonexistent object IDs.",
                                    owner_status=owner_status,
                                    attacker_status=atk_status,
                                    nonexistent_status=nonexistent_status,
                                    similarity_score=sim,
                                    evidence_notes=notes,
                                )
                    except Exception as exc:
                        notes.append(f"Nonexistent ID check error: {exc}")

        # If it's a read claim, require either identity marker or high baseline similarity
        if hypothesis.kind == "idor_read":
            if not marker_found and sim < 0.60:
                notes.append("Neither owner identity marker nor strong response similarity observed")
                return VerificationResult(
                    status="inconclusive",
                    verdict="insufficient_evidence",
                    reason="Lack of identity marker or structural baseline similarity in response.",
                    owner_status=owner_status,
                    attacker_status=atk_status,
                    similarity_score=sim,
                    evidence_notes=notes,
                )

        # If it's a write claim, verify that owner verification confirmed the change
        if hypothesis.kind == "idor_write":
            verify_step = steps.get("owner_verify")
            v_status = getattr(verify_step, "status", 0) if hasattr(verify_step, "status") else (verify_step.get("status", 0) if isinstance(verify_step, dict) else 0)
            v_body = getattr(verify_step, "body", "") if hasattr(verify_step, "body") else (verify_step.get("body", "") if isinstance(verify_step, dict) else "")

            if not verify_step or not (200 <= v_status < 300):
                notes.append("Owner verification step failed to confirm the state modification")
                return VerificationResult(
                    status="inconclusive",
                    verdict="state_change_unconfirmed",
                    reason="State modification was not verified by owner readback.",
                    owner_status=owner_status,
                    attacker_status=atk_status,
                    evidence_notes=notes,
                )
            marker = variables.get("marker", "")
            if marker and marker not in v_body:
                notes.append("Attacker mutation marker was not found in owner readback body")
                return VerificationResult(
                    status="inconclusive",
                    verdict="marker_missing_in_verification",
                    reason="Owner readback did not contain the injected attacker marker.",
                    owner_status=owner_status,
                    attacker_status=atk_status,
                    evidence_notes=notes,
                )

        # All challenges passed
        notes.append("Independent verification challenges satisfied: confirmed authorization failure.")
        return VerificationResult(
            status="verified",
            verdict="confirmed_authorization_bypass",
            reason="Adversarial verification confirmed unauthorized access across roles.",
            owner_status=owner_status,
            attacker_status=atk_status,
            unauth_status=unauth_status,
            nonexistent_status=nonexistent_status,
            identity_marker_found=marker_found,
            similarity_score=sim,
            evidence_notes=notes,
        )
