"""HackerOne Platform Policy Knowledge Base and Compliance Engine.

Defines the formalized rules and automated compliance checks derived from:
1. Vulnerability Disclosure Guidelines (VDG, v1.3 July 27, 2026)
   URL: https://www.hackerone.com/terms/disclosure-guidelines
   SHA-256: 711f7747ead5622e1346887f1979e85b3a726393fc0a8f4759b5a8bec0b8df10
2. Code of Conduct (CoC)
   URL: https://www.hackerone.com/policies/code-of-conduct
   SHA-256: f4c38dbbb6eb5527c251a3a550db388e697dcaca33169352cd5be26d562f33e1

Key Requirements & Classifications:
- RFC 2119 Classifications: MUST, MUST_NOT, SHOULD, SHOULD_NOT, MAY,
  REQUIRES_EXPLICIT_AUTHORIZATION, REQUIRES_HUMAN_REVIEW.
- Precedence Order:
  1. Universal Platform Floor: Code of Conduct rules (DoS prohibition, extortion ban,
     single account, ethical working practices, AI accountability) cannot be waived by any program.
  2. Program-Specific Policy: Explicit program terms supersede standard Vulnerability
     Disclosure Guidelines in event of conflict (e.g. customized disclosure timeframes,
     specific authorization for certain testing types, specific prohibited weaknesses).
  3. Default Platform Guidelines: Vulnerability Disclosure Guidelines govern unless
     program policy provides otherwise.
- AI & Hackbot Compliance (CoC Lines 53-116):
  * Human-in-the-Loop mandatory (no fully autonomous reporting to H1).
  * Operator accountability (due diligence, responsible for traffic and findings).
  * Rejection of unverified claims, fabricated findings, hallucinated endpoints.
  * Quality over quantity: ban on mass low-signal / non-actionable reports.
  * Strict prohibition on service degradation, DoS/DDoS, spam, social engineering.
"""
from __future__ import annotations

import enum
import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

from bb.config import DATA, now_iso
from bb.models import Finding

log = logging.getLogger(__name__)

# Document metadata anchoring the official policy versions
VDG_URL = "https://www.hackerone.com/terms/disclosure-guidelines"
VDG_FINAL_URL = "https://www.hackerone.com/terms/disclosure-guidelines"
VDG_VERSION = "1.3 (July 27, 2026)"
VDG_SHA256 = "711f7747ead5622e1346887f1979e85b3a726393fc0a8f4759b5a8bec0b8df10"
VDG_RETRIEVED_AT = "2026-11-11T12:09:00Z"

COC_URL = "https://www.hackerone.com/policies/code-of-conduct"
COC_FINAL_URL = "https://www.hackerone.com/policies/code-of-conduct"
COC_VERSION = "Standing Terms"
COC_SHA256 = "f4c38dbbb6eb5527c251a3a550db388e697dcaca33169352cd5be26d562f33e1"
COC_RETRIEVED_AT = "2026-11-11T12:09:00Z"


@dataclass(frozen=True)
class PolicyDocumentMetadata:
    name: str
    original_url: str
    final_url: str
    version: str
    sha256: str
    retrieved_at: str
    headings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


VDG_METADATA = PolicyDocumentMetadata(
    name="Vulnerability Disclosure Guidelines",
    original_url=VDG_URL,
    final_url=VDG_FINAL_URL,
    version=VDG_VERSION,
    sha256=VDG_SHA256,
    retrieved_at=VDG_RETRIEVED_AT,
    headings=(
        "Vulnerability Disclosure Standards",
        "Program Participation & Submission Process",
        "Vulnerability Disclosure Process",
        "Disclosure Setting - Default",
        "Disclosure Setting - Mutual Agreement",
        "Last Resort",
        "Disclosure Setting - Disabled",
        "Private Program",
        "Public Recognition",
        "Bug Bounty",
        "Definitions",
        "Contact",
        "Changes to These Guidelines",
    ),
)

COC_METADATA = PolicyDocumentMetadata(
    name="Code of Conduct",
    original_url=COC_URL,
    final_url=COC_FINAL_URL,
    version=COC_VERSION,
    sha256=COC_SHA256,
    retrieved_at=COC_RETRIEVED_AT,
    headings=(
        "Code of Conduct",
        "Unprofessional Behavior",
        "Abusive Conduct/Harassment",
        "Ethical Working Practices",
        "Unlawful or obscene content",
        "Service Degradation/Unsafe Testing",
        "Hackbots: By the Rules, Human-in-the-Loop, Bounty Eligible, Accountable",
        "AI-assisted Research & Submission Standards",
        "High-quality submissions",
        "Submissions closed as Not Applicable",
        "Uncoordinated Vulnerability Disclosure",
        "Private Programs",
        "Third-Party Assets",
        "Contacting Program Team Out-of-Band",
        "Reputation Farming/Duplicate Account Abuse",
        "Misuse of Intellectual Property",
        "Social Engineering",
        "Use of tools",
        "Extortion/Blackmail",
        "Circumventing a Ban",
        "Enforcement Actions",
    ),
)


@dataclass
class GlobalH1PolicyProfile:
    """Consolidated Global HackerOne Policy Compliance Profile."""
    vdg: PolicyDocumentMetadata = field(default_factory=lambda: VDG_METADATA)
    coc: PolicyDocumentMetadata = field(default_factory=lambda: COC_METADATA)
    active_rules: list[PolicyRule] = field(default_factory=lambda: list(H1_RULES.values()))
    max_platform_rate_rps: float = 10.0
    require_human_in_the_loop: bool = True
    prohibit_full_autonomy: bool = True
    prohibit_extortion: bool = True
    prohibit_dos_ddos: bool = True
    prohibit_spam: bool = True
    prohibit_social_engineering: bool = True

    def get_summary(self) -> dict[str, Any]:
        return {
            "documents": [self.vdg.to_dict(), self.coc.to_dict()],
            "rules_count": len(self.active_rules),
            "max_rate_rps": self.max_platform_rate_rps,
            "human_in_the_loop": self.require_human_in_the_loop,
            "prohibit_full_autonomy": self.prohibit_full_autonomy,
        }


class RuleClassification(str, enum.Enum):
    MUST = "MUST"
    MUST_NOT = "MUST_NOT"
    SHOULD = "SHOULD"
    SHOULD_NOT = "SHOULD_NOT"
    MAY = "MAY"
    REQUIRES_EXPLICIT_AUTHORIZATION = "REQUIRES_EXPLICIT_AUTHORIZATION"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"


class PolicyDocument(str, enum.Enum):
    COC = "Code of Conduct"
    VDG = "Vulnerability Disclosure Guidelines"
    PROGRAM = "Program Policy"


class RuleCategory(str, enum.Enum):
    UNSAFE_TESTING = "unsafe_testing"
    AI_HACKBOT_STANDARDS = "ai_hackbot_standards"
    REPORT_QUALITY = "report_quality"
    COORDINATED_DISCLOSURE = "coordinated_disclosure"
    CONFIDENTIALITY_PRIVACY = "confidentiality_privacy"
    ETHICAL_CONDUCT = "ethical_conduct"
    ACCOUNT_INTEGRITY = "account_integrity"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    document: PolicyDocument
    category: RuleCategory
    classification: RuleClassification
    section_heading: str
    summary: str
    verbatim_text: str
    rationale: str
    applies_to: tuple[str, ...] = ("researcher", "hackbot", "ai_agent", "pipeline")
    can_program_override: bool = False  # If False, platform CoC floor prevents program waiver
    sanction_floor: str = "Warning / Temporary Ban / Permanent Platform Ban"


# ---------------------------------------------------------------------------
# PLATFORM RULES KNOWLEDGE BASE (VDG & COC)
# ---------------------------------------------------------------------------

H1_RULES: dict[str, PolicyRule] = {
    # 1. Unsafe testing & service degradation
    "COC-UNSAFE-001": PolicyRule(
        rule_id="COC-UNSAFE-001",
        document=PolicyDocument.COC,
        category=RuleCategory.UNSAFE_TESTING,
        classification=RuleClassification.MUST_NOT,
        section_heading="Service Degradation/Unsafe Testing",
        summary="Never perform testing deemed unsafe or causing service degradation without prior authorization.",
        verbatim_text="Community Members must not perform testing which might be deemed 'unsafe' without prior authorization from the Customer. If there is any uncertainty always ask for clarification from the Customer before engaging in the testing.",
        rationale="Protects availability and integrity of target systems.",
        can_program_override=False,
        sanction_floor="Educational -> Warnings -> Temporary Ban -> Permanent Platform Ban",
    ),
    "COC-UNSAFE-002": PolicyRule(
        rule_id="COC-UNSAFE-002",
        document=PolicyDocument.COC,
        category=RuleCategory.UNSAFE_TESTING,
        classification=RuleClassification.MUST_NOT,
        section_heading="Service Degradation/Unsafe Testing",
        summary="Prohibition on excessive traffic generation (DoS/DDoS) and availability disruption.",
        verbatim_text="Hazardous testing—as outlined in HackerOne's Core Ineligible Findings—must never be attempted unless explicitly authorized by the program. This includes but is not limited to: Excessive traffic or request generation (e.g., DoS, DDoS), Testing that affects system availability.",
        rationale="Denial of service degrades customer operations and violates ethical research standards.",
        can_program_override=False,
    ),
    "COC-UNSAFE-003": PolicyRule(
        rule_id="COC-UNSAFE-003",
        document=PolicyDocument.COC,
        category=RuleCategory.UNSAFE_TESTING,
        classification=RuleClassification.MUST_NOT,
        section_heading="Service Degradation/Unsafe Testing",
        summary="Prohibition on social engineering and physical security testing.",
        verbatim_text="Social engineering (e.g., phishing, opening support tickets)... Physical security testing.",
        rationale="Out of scope for software bug bounty and abusive to support personnel.",
        can_program_override=True,  # Only if explicitly authorized in program policy
    ),
    "COC-UNSAFE-004": PolicyRule(
        rule_id="COC-UNSAFE-004",
        document=PolicyDocument.COC,
        category=RuleCategory.UNSAFE_TESTING,
        classification=RuleClassification.MUST_NOT,
        section_heading="Service Degradation/Unsafe Testing",
        summary="Prohibition on noisy attacks that disrupt users or admins (form or notification spam).",
        verbatim_text="Noisy attacks that disrupt users or admins (e.g., notification or form spam).",
        rationale="Prevents mail flooding, notification exhaustion, and end-user disruption.",
        can_program_override=False,
    ),
    "COC-UNSAFE-005": PolicyRule(
        rule_id="COC-UNSAFE-005",
        document=PolicyDocument.COC,
        category=RuleCategory.UNSAFE_TESTING,
        classification=RuleClassification.MUST_NOT,
        section_heading="Service Degradation/Unsafe Testing",
        summary="Never exploit a vulnerability beyond what is strictly necessary to show impact (e.g. database dumping).",
        verbatim_text="This includes (but is not limited to): exploiting a vulnerability beyond what is necessary to show impact (i.e. accessing excessive amounts of customer internal information, dumping a database, etc.), gaining access to and using accounts or production credentials not approved per the program's policy, altering production or database information.",
        rationale="Exfiltrating excess customer data or modifying production databases turns authorized research into a data breach.",
        can_program_override=False,
    ),

    # 2. Hackbot & AI-assisted research standards
    "COC-AI-001": PolicyRule(
        rule_id="COC-AI-001",
        document=PolicyDocument.COC,
        category=RuleCategory.AI_HACKBOT_STANDARDS,
        classification=RuleClassification.MUST_NOT,
        section_heading="Hackbot Principles: Human-in-the-Loop",
        summary="Hackbots and AI agents must not operate in a fully autonomous manner; human-in-the-loop validation is required.",
        verbatim_text="Human-in-the-Loop: Hackbots must not operate in a fully autonomous manner. We employ a 'hacker-in-the-loop' model, requiring human experts to investigate, validate, and confirm all potential vulnerabilities before submitting to a Vulnerability Disclosure (VDP) or Bug Bounty Program (BBP).",
        rationale="Eliminates automated submission noise and ensures expert review before platform reporting.",
        can_program_override=False,
    ),
    "COC-AI-002": PolicyRule(
        rule_id="COC-AI-002",
        document=PolicyDocument.COC,
        category=RuleCategory.AI_HACKBOT_STANDARDS,
        classification=RuleClassification.MUST,
        section_heading="Hackbot Principles: Accountable",
        summary="Operators are strictly accountable for their Hackbots and AI tools and must ensure compliance with platform rules.",
        verbatim_text="Accountable: Hackbot operators are responsible for their Hackbots and must exercise due diligence to ensure compliance with platform rules and program policies. Misuse of hackbots will result in potential sanctions against their hackbot operator.",
        rationale="Assigns legal and operational accountability to the human researcher.",
        can_program_override=False,
    ),
    "COC-AI-003": PolicyRule(
        rule_id="COC-AI-003",
        document=PolicyDocument.COC,
        category=RuleCategory.AI_HACKBOT_STANDARDS,
        classification=RuleClassification.MUST_NOT,
        section_heading="AI-assisted Research & Submission Standards",
        summary="Generating large volumes of low-signal or non-actionable reports is strictly prohibited.",
        verbatim_text="The following behaviors are not permitted: Generating large volumes of low-signal or non-actionable reports.",
        rationale="Protects security triagers from automated spam.",
        can_program_override=False,
        sanction_floor="Final Warning -> Temporary Ban (12 months) -> Permanent Platform Ban",
    ),
    "COC-AI-004": PolicyRule(
        rule_id="COC-AI-004",
        document=PolicyDocument.COC,
        category=RuleCategory.AI_HACKBOT_STANDARDS,
        classification=RuleClassification.MUST_NOT,
        section_heading="AI-assisted Research & Submission Standards",
        summary="Submitting unverified or fabricated claims or relying on AI outputs with hallucinated technical details is prohibited.",
        verbatim_text="Submitting unverified or fabricated vulnerability claims, including those without a proof of concept. Relying on AI outputs that contain hallucinated or misleading technical details (e.g., invented endpoints or unsupported impact claims).",
        rationale="Maintains factual integrity and technical veracity.",
        can_program_override=False,
    ),
    "COC-AI-005": PolicyRule(
        rule_id="COC-AI-005",
        document=PolicyDocument.COC,
        category=RuleCategory.AI_HACKBOT_STANDARDS,
        classification=RuleClassification.MUST,
        section_heading="AI-assisted Research & Submission Standards",
        summary="Community members remain fully responsible for validating all AI-assisted outputs and providing clear, reproducible PoCs.",
        verbatim_text="The use of AI does not change the requirement to validate findings, connect all steps in an attack chain, and provide a clear, reproducible proof-of-concept demonstrating a real vulnerability and its impact.",
        rationale="Validates real-world security impact before reporting.",
        can_program_override=False,
    ),

    # 3. Report Quality Standards
    "COC-REP-001": PolicyRule(
        rule_id="COC-REP-001",
        document=PolicyDocument.COC,
        category=RuleCategory.REPORT_QUALITY,
        classification=RuleClassification.MUST,
        section_heading="High-quality submissions",
        summary="Reports must demonstrate clear, reproducible impact with step-by-step reproduction and a strong proof of concept.",
        verbatim_text="High-quality submissions: Demonstrate clear, reproducible impact with step-by-step reproduction. Include a strong proof of concept. Account for real-world mitigations and context.",
        rationale="Ensures triagers can independently confirm the bug.",
        can_program_override=False,
    ),
    "COC-REP-002": PolicyRule(
        rule_id="COC-REP-002",
        document=PolicyDocument.COC,
        category=RuleCategory.REPORT_QUALITY,
        classification=RuleClassification.MUST,
        section_heading="High-quality submissions",
        summary="Accurate severity rating at point of submission; repeated inflated severity constitutes a CoC violation.",
        verbatim_text="Assign accurate severity at the point of submission - a repeated pattern of inflated severity constitutes a Code of Conduct violation.",
        rationale="Eliminates artificial inflation of CVSS / severity scores.",
        can_program_override=False,
    ),
    "COC-REP-003": PolicyRule(
        rule_id="COC-REP-003",
        document=PolicyDocument.COC,
        category=RuleCategory.REPORT_QUALITY,
        classification=RuleClassification.MUST_NOT,
        section_heading="Submissions closed as Not Applicable",
        summary="Do not submit speculative findings, findings missing PoCs, or findings that do not account for mitigations.",
        verbatim_text="Submissions will be closed as Not Applicable (N/A) if they are: Speculative or misleading, Missing a proof of concept, Not reproducible, Based solely on a video attachment, Lacking demonstrated impact. Findings that do not account for existing mitigations or defense-in-depth controls are not valid unless a practical exploit path is clearly demonstrated.",
        rationale="Prevents rejected noise and protects researcher reputation.",
        can_program_override=False,
    ),

    # 4. Coordinated Vulnerability Disclosure & Confidentiality
    "COC-DISC-001": PolicyRule(
        rule_id="COC-DISC-001",
        document=PolicyDocument.COC,
        category=RuleCategory.COORDINATED_DISCLOSURE,
        classification=RuleClassification.MUST,
        section_heading="Uncoordinated Vulnerability Disclosure",
        summary="Explicit customer approval required before any vulnerability details are made public across all closure statuses.",
        verbatim_text="Obtain explicit approval from the program team before any vulnerability details are made public. This applies to all closure statuses (including Informative, Duplicate, and Not Applicable).",
        rationale="Enforces coordinated disclosure and protects customer systems during remediation.",
        can_program_override=False,
    ),
    "COC-DISC-002": PolicyRule(
        rule_id="COC-DISC-002",
        document=PolicyDocument.COC,
        category=RuleCategory.COORDINATED_DISCLOSURE,
        classification=RuleClassification.MUST_NOT,
        section_heading="Uncoordinated Vulnerability Disclosure",
        summary="Never use disclosure as leverage, threat, extortion or blackmail to pressure a bounty award or payout increase.",
        verbatim_text="Never use disclosure as leverage. Threatening to disclose in order to pressure a bounty award or payout increase is a serious violation of the HackerOne Code of Conduct and will result in enforcement action, including potential permanent platform removal.",
        rationale="Zero tolerance for extortion / coercion.",
        can_program_override=False,
        sanction_floor="Permanent Platform Ban",
    ),
    "COC-DISC-003": PolicyRule(
        rule_id="COC-DISC-003",
        document=PolicyDocument.COC,
        category=RuleCategory.CONFIDENTIALITY_PRIVACY,
        classification=RuleClassification.MUST_NOT,
        section_heading="Private Programs",
        summary="Strict non-disclosure on private programs: existence, handle, scope, vulnerabilities, communications.",
        verbatim_text="Do not disclose publicly the existence of any private program on the H1 Platform. These programs are designated private by the customer for a reason and must be treated as confidential. This includes program name, scope, vulnerability information, bounty structure, account information, communications with program personnel, or any other detail that could identify the program.",
        rationale="Protects confidentiality of private programs and their customers.",
        can_program_override=False,
    ),
    "COC-DISC-004": PolicyRule(
        rule_id="COC-DISC-004",
        document=PolicyDocument.COC,
        category=RuleCategory.COORDINATED_DISCLOSURE,
        classification=RuleClassification.MUST_NOT,
        section_heading="Contacting Program Team Out-of-Band",
        summary="Never contact security teams out-of-band about HackerOne reports unless explicitly permitted in program policy.",
        verbatim_text="Only use approved communication channels to discuss vulnerabilities submitted to HackerOne. Unless the program has explicitly provided an alternative contact method to you in their program policy, contacting security teams 'out-of-band' about reports submitted on HackerOne is a violation of this CoC.",
        rationale="Centralizes triage communication and prevents researcher harassment of engineers.",
        can_program_override=True,  # If program policy provides alternate channel
    ),
    "COC-PRIV-001": PolicyRule(
        rule_id="COC-PRIV-001",
        document=PolicyDocument.COC,
        category=RuleCategory.CONFIDENTIALITY_PRIVACY,
        classification=RuleClassification.MUST_NOT,
        section_heading="Confidential communications and Personal Data",
        summary="Never publish or expose third-party personal data (PII) or confidential customer communications.",
        verbatim_text="Personal data that may identify or be capable of identifying an individual must never be published or otherwise disclosed without explicit consent from the individual. Reports should not include third-party PII.",
        rationale="Protects individual privacy under GDPR, CCPA, and global data privacy standards.",
        can_program_override=False,
    ),

    # 5. Account integrity
    "COC-ACCT-001": PolicyRule(
        rule_id="COC-ACCT-001",
        document=PolicyDocument.COC,
        category=RuleCategory.ACCOUNT_INTEGRITY,
        classification=RuleClassification.MUST,
        section_heading="Reputation Farming/Duplicate Account Abuse",
        summary="Community members are permitted to have and use one sole account for submitting reports; no account sharing or evasion.",
        verbatim_text="Community Members are permitted to have and use one sole account for the purpose of submitting vulnerability reports... Community Members are prohibited from sharing, selling, trading, or giving away their account.",
        rationale="Guarantees researcher identity and prevents sanction evasion.",
        can_program_override=False,
    ),

    # 6. VDG Standards
    "VDG-PREC-001": PolicyRule(
        rule_id="VDG-PREC-001",
        document=PolicyDocument.VDG,
        category=RuleCategory.COORDINATED_DISCLOSURE,
        classification=RuleClassification.MUST,
        section_heading="Program Participation & Submission Process",
        summary="Program policy supersedes Vulnerability Disclosure Guidelines in event of conflict.",
        verbatim_text="You should always carefully review this program policy prior to participating in a program, as they may supersede these guidelines in the event of a conflict.",
        rationale="Honors specific customer rules of engagement.",
        can_program_override=True,
    ),
    "VDG-DISC-001": PolicyRule(
        rule_id="VDG-DISC-001",
        document=PolicyDocument.VDG,
        category=RuleCategory.COORDINATED_DISCLOSURE,
        classification=RuleClassification.MUST,
        section_heading="Vulnerability Disclosure Process",
        summary="Report contents remain non-public initially to allow security team sufficient time to remediate.",
        verbatim_text="The contents of the Report will be made available to the Security Team immediately, and will initially remain non-public to allow the Security Team sufficient time to publish a remediation.",
        rationale="Ensures vulnerabilities are fixed before exposure.",
        can_program_override=False,
    ),
    "VDG-DISC-002": PolicyRule(
        rule_id="VDG-DISC-002",
        document=PolicyDocument.VDG,
        category=RuleCategory.COORDINATED_DISCLOSURE,
        classification=RuleClassification.MAY,
        section_heading="Vulnerability Disclosure Process: Last Resort",
        summary="Last resort disclosure permitted after 180 days unresponsive if followed up monthly, unless prohibited by program.",
        verbatim_text="Last Resort: If a Security Team has not responded to a formal request for disclosure for 180 days despite reasonable follow up from the Community Member (at least once every 30 days), the contents of the Report may be publicly disclosed by the Community Member, unless otherwise prohibited by the program's policy. Any disclosure must adhere to the HackerOne Code of Conduct and cannot include third-party confidential or personal information.",
        rationale="Provides structured pathway if program completely abandons coordination.",
        can_program_override=True,
    ),
}


# ---------------------------------------------------------------------------
# POLICY COMPLIANCE CHECKER AND VALIDATORS
# ---------------------------------------------------------------------------

@dataclass
class ComplianceViolation:
    rule_id: str
    rule_classification: RuleClassification
    category: RuleCategory
    message: str
    blocking: bool = True
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceResult:
    compliant: bool
    violations: list[ComplianceViolation] = field(default_factory=list)
    warnings: list[ComplianceViolation] = field(default_factory=list)
    human_review_required: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "compliant": self.compliant,
            "violations": [asdict(v) for v in self.violations],
            "warnings": [asdict(w) for w in self.warnings],
            "human_review_required": self.human_review_required,
            "notes": self.notes,
        }


class PolicyComplianceEngine:
    """Deterministic validation of proposed actions, scanning rates, and findings
    against HackerOne platform rules (VDG, CoC) and target program policy.
    
    Precedence Order:
      1. Platform CoC (Universal Floor: DoS, extortion, account abuse, AI accountability)
      2. Program-Specific Policy (Supersedes standard VDG on scope, rate limits, custom headers)
      3. Vulnerability Disclosure Guidelines (Default disclosure baseline)
    """

    @classmethod
    def get_rule(cls, rule_id: str) -> Optional[PolicyRule]:
        return H1_RULES.get(rule_id)

    @classmethod
    def all_rules(cls) -> list[PolicyRule]:
        return list(H1_RULES.values())

    @classmethod
    def validate_testing_action(cls,
                                method: str,
                                url: str,
                                program_handle: str,
                                rate_rps: float = 2.0,
                                max_program_rate: float = 3.0,
                                is_state_changing: bool = False,
                                writes_approved: bool = False,
                                test_type: str = "http_request",
                                is_private_program: bool = False) -> ComplianceResult:
        """Validate an outbound testing operation before sending.

        Note on Rate Limiting:
        The 10.0 req/sec limit is Bounty Hunter's internal defensive ceiling designed
        to prevent accidental denial of service (DoS) under HackerOne Code of Conduct
        prohibitions against service degradation. HackerOne's official Code of Conduct
        forbids DoS and excessive traffic qualitatively, without specifying a global
        numerical rate limit.
        """
        violations: list[ComplianceViolation] = []
        warnings: list[ComplianceViolation] = []
        notes: list[str] = []

        # 1. Traffic & Rate Limit Checks (COC-UNSAFE-002)
        # Note: 10 req/s is Bounty Hunter's internal defensive safety ceiling, not an official H1 numerical rule.
        if rate_rps > 10.0:
            violations.append(ComplianceViolation(
                rule_id="COC-UNSAFE-002",
                rule_classification=RuleClassification.MUST_NOT,
                category=RuleCategory.UNSAFE_TESTING,
                message=f"Proposed rate of {rate_rps} req/sec exceeds safe platform ceiling (10 req/sec internal defensive ceiling) and constitutes excessive traffic.",
                blocking=True,
            ))
        elif rate_rps > max_program_rate:
            violations.append(ComplianceViolation(
                rule_id="COC-UNSAFE-001",
                rule_classification=RuleClassification.MUST_NOT,
                category=RuleCategory.UNSAFE_TESTING,
                message=f"Proposed rate {rate_rps} req/sec exceeds target program policy limit of {max_program_rate} req/sec.",
                blocking=True,
            ))

        # 2. Prohibited attack types (COC-UNSAFE-002, COC-UNSAFE-003, COC-UNSAFE-004)
        prohibited_types = {
            "dos": ("COC-UNSAFE-002", "Denial of service testing is strictly prohibited."),
            "ddos": ("COC-UNSAFE-002", "DDoS attacks are strictly prohibited."),
            "social_engineering": ("COC-UNSAFE-003", "Social engineering/phishing is prohibited unless explicitly authorized."),
            "spam": ("COC-UNSAFE-004", "Notification and form spam is prohibited."),
            "physical": ("COC-UNSAFE-003", "Physical security testing is prohibited."),
        }
        if test_type.lower() in prohibited_types:
            rid, msg = prohibited_types[test_type.lower()]
            violations.append(ComplianceViolation(
                rule_id=rid,
                rule_classification=RuleClassification.MUST_NOT,
                category=RuleCategory.UNSAFE_TESTING,
                message=msg,
                blocking=True,
            ))

        # 3. State changing operations check (COC-UNSAFE-005)
        method_upper = method.upper()
        # Parse path to exempt standard authentication and read-only introspection endpoints
        path_lower = urlsplit(url).path.lower()
        is_auth_or_read_endpoint = any(
            p in path_lower for p in ("/login", "/logout", "/token", "/session", "/auth", "/register", "/graphql")
        )

        if is_auth_or_read_endpoint:
            is_state_changing = False

        if method_upper in ("POST", "PUT", "PATCH", "DELETE"):
            if not is_auth_or_read_endpoint:
                is_state_changing = True
            if is_state_changing and not writes_approved:
                violations.append(ComplianceViolation(
                    rule_id="COC-UNSAFE-005",
                    rule_classification=RuleClassification.REQUIRES_EXPLICIT_AUTHORIZATION,
                    category=RuleCategory.UNSAFE_TESTING,
                    message=f"State-changing method {method_upper} on {url} requires explicit operator authorization to avoid production data destruction.",
                    blocking=True,
                ))

        # 4. Private program protection check (COC-DISC-003)
        if is_private_program:
            notes.append(f"Private program '{program_handle}' is subject to strict confidentiality. No telemetry or findings may be logged out-of-band.")

        compliant = len(violations) == 0
        human_review = not compliant or len(warnings) > 0

        return ComplianceResult(
            compliant=compliant,
            violations=violations,
            warnings=warnings,
            human_review_required=human_review,
            notes=notes,
        )

    @classmethod
    def validate_finding_for_submission(cls, finding: Finding,
                                        program_handle: str,
                                        is_private: bool = False,
                                        ai_generated: bool = False) -> ComplianceResult:
        """Validate a discovered finding against HackerOne quality & policy standards before report drafting."""
        violations: list[ComplianceViolation] = []
        warnings: list[ComplianceViolation] = []
        notes: list[str] = []

        # 1. Proof of concept & reproducibility (COC-REP-001, COC-REP-003, COC-AI-005)
        if not finding.evidence or len(finding.evidence) == 0:
            violations.append(ComplianceViolation(
                rule_id="COC-REP-003",
                rule_classification=RuleClassification.MUST_NOT,
                category=RuleCategory.REPORT_QUALITY,
                message="Finding lacks concrete HTTP evidence exchanges (missing proof of concept). Will be closed as N/A under CoC.",
                blocking=True,
            ))

        if not finding.steps or len(finding.steps) == 0:
            violations.append(ComplianceViolation(
                rule_id="COC-REP-001",
                rule_classification=RuleClassification.MUST,
                category=RuleCategory.REPORT_QUALITY,
                message="Finding lacks step-by-step reproduction instructions.",
                blocking=True,
            ))

        # 2. Demonstrated impact (COC-REP-001, COC-REP-003)
        impact = (finding.impact or "").strip()
        if len(impact) < 30 or "TODO" in impact.upper() or "PLACEHOLDER" in impact.upper():
            violations.append(ComplianceViolation(
                rule_id="COC-REP-001",
                rule_classification=RuleClassification.MUST,
                category=RuleCategory.REPORT_QUALITY,
                message="Finding lacks demonstrated real-world security impact or contains placeholders.",
                blocking=True,
            ))

        # 3. Independent verification requirement (COC-AI-001, COC-AI-004)
        is_verified = bool(finding.meta.get("verified")) or finding.status == "confirmed"
        if not is_verified:
            violations.append(ComplianceViolation(
                rule_id="COC-AI-001",
                rule_classification=RuleClassification.MUST_NOT,
                category=RuleCategory.AI_HACKBOT_STANDARDS,
                message="Human/Independent verification not recorded. Unverified automated claims violate Hackbot Human-in-the-Loop policy.",
                blocking=True,
            ))

        # 4. Severity inflation check (COC-REP-002)
        sev = (finding.severity or "medium").lower()
        if sev == "critical":
            # Check if critical is actually justified (e.g. RCE, full auth bypass, SQLi, IDOR with sensitive PII)
            bug_class = (finding.bug_class or "").lower()
            allowed_crit_classes = ("idor", "broken authentication", "rce", "sql_injection", "ssrf")
            if not any(ac in bug_class for ac in allowed_crit_classes):
                warnings.append(ComplianceViolation(
                    rule_id="COC-REP-002",
                    rule_classification=RuleClassification.SHOULD,
                    category=RuleCategory.REPORT_QUALITY,
                    message=f"Severity marked 'Critical' for bug class '{finding.bug_class}'. Ensure severity is not inflated to avoid CoC review.",
                    blocking=False,
                ))

        # 5. PII / Confidentiality leak prevention (COC-PRIV-001)
        # Note: Regular expressions provide heuristic defense-in-depth for common patterns (tokens, credit cards, credentials)
        # and do not constitute exhaustive PII detection. Operators must conduct human review before final report submission.
        evidence_texts = []
        for ex in (finding.evidence or []):
            if hasattr(ex, "request"):
                evidence_texts.append(str(getattr(ex.request, "headers", "")))
                evidence_texts.append(str(getattr(ex.request, "body", "")))
            if hasattr(ex, "response"):
                evidence_texts.append(str(getattr(ex.response, "headers", "")))
                evidence_texts.append(str(getattr(ex.response, "body", "")))
            if isinstance(ex, dict):
                evidence_texts.append(str(ex.get("request", "")))
                evidence_texts.append(str(ex.get("response", "")))

        full_text = f"{finding.title} {finding.summary} {' '.join(finding.steps)} {finding.impact} {' '.join(evidence_texts)}"

        # Heuristic regex for real credit cards, social security numbers, unredacted tokens/passwords
        if re.search(r"\b(?:\d{4}[ -]?){3}\d{4}\b", full_text):
            violations.append(ComplianceViolation(
                rule_id="COC-PRIV-001",
                rule_classification=RuleClassification.MUST_NOT,
                category=RuleCategory.CONFIDENTIALITY_PRIVACY,
                message="Report or attached evidence contains potential unredacted credit card or financial data. Must redact before submission.",
                blocking=True,
            ))
        if re.search(r"\b(password|passwd|api[_-]?key|bearer\s+[a-zA-Z0-9_\-\.]{20,})\b", full_text, re.I):
            warnings.append(ComplianceViolation(
                rule_id="COC-PRIV-001",
                rule_classification=RuleClassification.SHOULD_NOT,
                category=RuleCategory.CONFIDENTIALITY_PRIVACY,
                message="Report or attached evidence contains potential unredacted credential or API key tokens (heuristic scan; manual review required).",
                blocking=False,
            ))

        # 6. AI assistance disclosure & accountability (COC-AI-002, COC-AI-005)
        if ai_generated:
            notes.append("Finding generated with AI assistance: Human operator retains exclusive responsibility for verifying all details.")

        compliant = len(violations) == 0
        return ComplianceResult(
            compliant=compliant,
            violations=violations,
            warnings=warnings,
            human_review_required=True,  # HackerOne always requires human review before submission
            notes=notes,
        )


def format_compliance_report(result: ComplianceResult) -> str:
    """Format human-readable compliance audit report."""
    lines = []
    status_icon = "✅ COMPLIANT" if result.compliant else "❌ NON-COMPLIANT (POLICY VIOLATIONS)"
    lines.append(f"HACKERONE POLICY COMPLIANCE AUDIT: {status_icon}")
    lines.append("=" * 65)

    if result.violations:
        lines.append(f"\n[!] VIOLATIONS ({len(result.violations)} blocking issues):")
        for v in result.violations:
            lines.append(f"  * [{v.rule_id}] ({v.rule_classification.value}): {v.message}")

    if result.warnings:
        lines.append(f"\n[?] WARNINGS ({len(result.warnings)} non-blocking issues):")
        for w in result.warnings:
            lines.append(f"  * [{w.rule_id}] ({w.rule_classification.value}): {w.message}")

    if result.notes:
        lines.append("\n[i] POLICY NOTES:")
        for n in result.notes:
            lines.append(f"  * {n}")

    lines.append(f"\nHuman Review Required: {'YES (Mandatory)' if result.human_review_required else 'NO'}")
    return "\n".join(lines)
