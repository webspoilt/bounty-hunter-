"""Comprehensive validation tests for HackerOne Scope, Policy, and Integrity Invariants."""
import pytest
from bb.h1 import (
    AssetEligibility,
    BriefGenerator,
    PolicyParser,
    ProgramAuthorizationBrief,
    ProgramDiscoveryRanker,
    RankedProgram,
    ScopeRetrievalStatus,
    StructuredAssetEntry,
    sanitize_handle,
)
from bb.h1_policy import (
    COC_METADATA,
    GlobalH1PolicyProfile,
    H1_RULES,
    PolicyComplianceEngine,
    RuleClassification,
    VDG_METADATA,
)
from bb.models import Evidence, Exchange, Finding
from bb.scope import Scope, parse_rule, parse_target


def test_missing_eligibility_and_severity_defaults_to_unknown():
    """Rule 1: Missing eligibility must be UNKNOWN, never True; missing severity UNKNOWN, never Medium."""
    scopes = [
        {
            "attributes": {
                "asset_identifier": "api.example.com",
                "asset_type": "URL",
                # Omit eligible_for_bounty, eligible_for_submission, max_severity
            }
        }
    ]
    policy = PolicyParser.parse_policy("example", "Standard policy")
    brief = BriefGenerator.generate_brief(
        prog={"id": "example", "attributes": {"handle": "example", "offers_bounties": True}},
        policy=policy,
        scopes=scopes,
        exclusions=[],
    )

    entry = brief.structured_asset_entries[0]
    assert entry["eligible_for_bounty"] == AssetEligibility.UNKNOWN.value
    assert entry["eligible_for_submission"] == AssetEligibility.UNKNOWN.value
    assert entry["max_severity"] == "UNKNOWN"

    # Unknown eligibility must NOT be placed in in_scope or used to recommend target
    assert "api.example.com" not in brief.in_scope_assets
    assert brief.recommended_first_target == ""
    # Incomplete scope must require human review
    assert any("UNKNOWN submission eligibility" in n for n in brief.human_review_notes)


def test_separate_submission_and_bounty_eligibility():
    """Rule 1: Submission eligibility and bounty eligibility are separate properties."""
    scopes = [
        {
            "attributes": {
                "asset_identifier": "https://vdp.example.com",
                "asset_type": "URL",
                "eligible_for_submission": True,
                "eligible_for_bounty": False,  # VDP asset in a bounty program
                "max_severity": "high",
            }
        },
        {
            "attributes": {
                "asset_identifier": "https://paid.example.com",
                "asset_type": "URL",
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
                "max_severity": "critical",
            }
        }
    ]
    policy = PolicyParser.parse_policy("example", "Standard policy")
    brief = BriefGenerator.generate_brief(
        prog={"id": "example", "attributes": {"handle": "example", "offers_bounties": True}},
        policy=policy,
        scopes=scopes,
        exclusions=[],
    )

    vdp_entry = [e for e in brief.structured_asset_entries if "vdp.example.com" in e["identifier"]][0]
    paid_entry = [e for e in brief.structured_asset_entries if "paid.example.com" in e["identifier"]][0]

    assert vdp_entry["eligible_for_submission"] == AssetEligibility.ELIGIBLE.value
    assert vdp_entry["eligible_for_bounty"] == AssetEligibility.INELIGIBLE.value

    assert paid_entry["eligible_for_submission"] == AssetEligibility.ELIGIBLE.value
    assert paid_entry["eligible_for_bounty"] == AssetEligibility.ELIGIBLE.value


def test_wildcard_scope_does_not_automatically_authorize_apex():
    """Rule 2: Wildcard *.example.com must NOT automatically authorize apex example.com."""
    # Scope containing ONLY wildcard *.example.com
    scope = Scope.from_h1_structured(
        "testprog",
        [
            {
                "asset_identifier": "*.example.com",
                "asset_type": "WILDCARD",
                "eligible_for_submission": True,
            }
        ]
    )

    # Subdomains are allowed
    assert scope.is_in_scope("https://api.example.com") is True
    assert scope.is_in_scope("https://sub.portal.example.com") is True

    # Apex is NOT allowed!
    assert scope.is_in_scope("https://example.com") is False
    assert scope.is_in_scope("http://example.com") is False

    # Unrelated domains refused
    assert scope.is_in_scope("https://evil.com") is False
    assert scope.is_in_scope("https://notexample.com") is False


def test_wildcard_target_recommendation_never_invents_apex():
    """Rule 2: BriefGenerator must not recommend apex from a wildcard without explicit apex scope."""
    scopes = [
        {
            "attributes": {
                "asset_identifier": "*.example.com",
                "asset_type": "WILDCARD",
                "eligible_for_submission": True,
            }
        }
    ]
    policy = PolicyParser.parse_policy("example", "Standard policy")
    brief = BriefGenerator.generate_brief(
        prog={"id": "example", "attributes": {"handle": "example", "offers_bounties": True}},
        policy=policy,
        scopes=scopes,
        exclusions=[],
    )

    # Brief must NOT recommend https://example.com because it violates Scope.is_in_scope()
    assert brief.recommended_first_target != "https://example.com"
    assert brief.recommended_first_target == ""
    assert any("wildcard" in n.lower() for n in brief.human_review_notes)


def test_scope_exclusion_overrides_inclusion():
    """Rule 2: Explicit exclusion strictly overrides wildcard or URL inclusion."""
    scope = Scope.from_h1_structured(
        "testprog",
        [
            {
                "asset_identifier": "*.example.com",
                "asset_type": "WILDCARD",
                "eligible_for_submission": True,
            },
            {
                "asset_identifier": "admin.example.com",
                "asset_type": "DOMAIN",
                "eligible_for_submission": False,  # Explicitly out-of-scope!
            }
        ]
    )

    assert scope.is_in_scope("https://api.example.com") is True
    assert scope.is_in_scope("https://admin.example.com") is False  # Refused by out-of-scope rule!


def test_global_h1_policy_profile_integrity():
    """Rule 3: Global policy profile metadata, SHA-256 fingerprints, and headings."""
    profile = GlobalH1PolicyProfile()
    assert profile.max_platform_rate_rps == 10.0
    assert profile.require_human_in_the_loop is True
    assert profile.prohibit_full_autonomy is True

    # Verify VDG metadata
    assert profile.vdg.name == "Vulnerability Disclosure Guidelines"
    assert profile.vdg.sha256 == "711f7747ead5622e1346887f1979e85b3a726393fc0a8f4759b5a8bec0b8df10"
    assert "Last Resort" in profile.vdg.headings

    # Verify CoC metadata
    assert profile.coc.name == "Code of Conduct"
    assert profile.coc.sha256 == "f4c38dbbb6eb5527c251a3a550db388e697dcaca33169352cd5be26d562f33e1"
    assert any("Hackbots" in h for h in profile.coc.headings)
    assert any("Service Degradation" in h for h in profile.coc.headings)


def test_separate_display_of_bounty_eligibility_rewards_and_scores():
    """Rule 4: CLI summary must separate monetary eligibility, reward range, and score."""
    sample_unloaded = {
        "attributes": {
            "handle": "demo-prog",
            "name": "Demo Program",
            "offers_bounties": True,
            "submission_state": "open",
        }
    }
    rp_unloaded = ProgramDiscoveryRanker.score_program(sample_unloaded)
    sum_unloaded = rp_unloaded.summary()

    # Must contain separate elements
    assert "💰 BOUNTY" in sum_unloaded
    assert "Reward: NOT RETRIEVED" in sum_unloaded
    assert "[INSUFFICIENT DATA]" in sum_unloaded
    assert "Scope: NOT LOADED | Assets: UNKNOWN" in sum_unloaded

    # Never format score as dollar amount ($)
    assert "$" not in sum_unloaded


def test_fail_closed_authorization_unknown_eligibility():
    """Rule 5: Fail-closed authorization when eligibility is absent."""
    scope_unknown = Scope.from_h1_structured(
        "unknown_prog",
        [
            {
                "asset_identifier": "api.example.com",
                "asset_type": "URL",
                # missing eligible_for_submission
            }
        ],
        strict=True,
    )

    # In-rules should be empty because unknown eligibility is excluded (fail-closed)
    assert len(scope_unknown.in_rules) == 0
    decision = scope_unknown.check("https://api.example.com/test")
    assert not decision.allowed
    assert "deny by default" in decision.reason
