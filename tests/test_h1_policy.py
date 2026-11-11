"""Unit tests for HackerOne Policy Compliance Engine & Scope/Reward Data Repair."""
import pytest
from bb.h1 import (
    ProgramDiscoveryRanker,
    RankedProgram,
    ScopeRetrievalStatus,
    sanitize_handle,
)
from bb.h1_policy import (
    H1_RULES,
    PolicyComplianceEngine,
    RuleClassification,
    RuleCategory,
    PolicyDocument,
    format_compliance_report,
)
from bb.http import RequestBudget, ScopedClient
from bb.models import Evidence, Exchange, Finding
from bb.scope import Scope


def test_h1_policy_rules_integrity():
    """Verify official rules loaded with correct classifications and document sources."""
    assert len(H1_RULES) >= 20
    assert "COC-UNSAFE-001" in H1_RULES
    assert "COC-AI-001" in H1_RULES
    assert "COC-AI-003" in H1_RULES
    assert "VDG-PREC-001" in H1_RULES

    ai_rule = H1_RULES["COC-AI-001"]
    assert ai_rule.classification == RuleClassification.MUST_NOT
    assert "Human-in-the-Loop" in ai_rule.section_heading
    assert not ai_rule.can_program_override  # Universal floor

    vdg_prec = H1_RULES["VDG-PREC-001"]
    assert vdg_prec.document == PolicyDocument.VDG
    assert vdg_prec.can_program_override  # Program supersedes VDG


def test_rate_limit_and_excessive_traffic_enforcement():
    """Verify PolicyComplianceEngine blocks excessive request rates and ScopedClient enforces ceiling."""
    # Test rate check
    res_excessive = PolicyComplianceEngine.validate_testing_action(
        method="GET",
        url="https://api.example.com/v1/users",
        program_handle="example",
        rate_rps=15.0,  # Exceeds 10 req/s platform ceiling
    )
    assert not res_excessive.compliant
    assert any(v.rule_id == "COC-UNSAFE-002" for v in res_excessive.violations)

    # ScopedClient and RequestBudget automatically cap at 10.0
    budget = RequestBudget(rate=20.0)
    assert budget.rate == 10.0

    scope = Scope.from_entries(program="test", in_scope=["example.com"])
    client = ScopedClient(scope, rate=25.0, dry_run=True)
    assert client.rate == 10.0


def test_unsafe_testing_types_blocked():
    """Verify DoS, spam, and social engineering are blocked deterministically."""
    for bad_type in ["dos", "ddos", "social_engineering", "spam", "physical"]:
        res = PolicyComplianceEngine.validate_testing_action(
            method="POST",
            url="https://example.com/submit",
            program_handle="test",
            test_type=bad_type,
        )
        assert not res.compliant
        assert len(res.violations) >= 1


def test_state_changing_operation_requires_approval():
    """Verify POST/PUT/DELETE requires explicit authorization to prevent destructive writes."""
    res_unapproved = PolicyComplianceEngine.validate_testing_action(
        method="DELETE",
        url="https://example.com/api/user/123",
        program_handle="test",
        writes_approved=False,
    )
    assert not res_unapproved.compliant
    assert any(v.rule_id == "COC-UNSAFE-005" for v in res_unapproved.violations)

    res_approved = PolicyComplianceEngine.validate_testing_action(
        method="DELETE",
        url="https://example.com/api/user/123",
        program_handle="test",
        writes_approved=True,
    )
    assert res_approved.compliant


def test_finding_submission_gate_rejection_of_unverified_and_missing_poc():
    """Verify AI/Hackbot rules reject findings without evidence, repro steps, or verification."""
    finding_empty = Finding(
        id="f1",
        title="Potential IDOR on users endpoint",
        bug_class="IDOR",
        url="https://example.com/api/users/2",
        host="example.com",
        severity="high",
        summary="Speculative claim without evidence",
        impact="Could access other user accounts",
        evidence=[],  # Missing PoC!
        steps=[],     # Missing reproduction steps!
    )
    res = PolicyComplianceEngine.validate_finding_for_submission(
        finding=finding_empty,
        program_handle="test",
    )
    assert not res.compliant
    rule_ids = [v.rule_id for v in res.violations]
    assert "COC-REP-003" in rule_ids  # Missing proof of concept
    assert "COC-REP-001" in rule_ids  # Missing steps
    assert "COC-AI-001" in rule_ids   # Unverified automated claim


def test_finding_submission_gate_accepts_verified_finding():
    """Verify fully reproducible, independently verified finding passes policy compliance."""
    ex = Exchange(
        url="https://example.com/api/users/2",
        method="GET",
        status=200,
        request_headers={"Authorization": "Bearer token_attacker"},
        response_headers={"Content-Type": "application/json"},
        response_body='{"user_id": 2, "name": "Victim Alice", "email": "alice@example.com"}',
    )
    finding_valid = Finding(
        id="f2",
        title="IDOR Accessing Other User Profiles via ID parameter",
        bug_class="IDOR",
        url="https://example.com/api/users/2",
        host="example.com",
        severity="high",
        summary="User B is able to retrieve User A profile by altering user_id.",
        impact="Allows an authenticated attacker to read sensitive profile information belonging to arbitrary users.",
        steps=[
            "Authenticate as User B.",
            "Send GET request to /api/users/2 with User B's token.",
            "Observe 200 OK containing Alice's personal details."
        ],
        evidence=[Evidence(summary="User B reading User A profile", exchange=ex)],
        status="confirmed",
        meta={"verified": True, "program": "example"},
    )
    res = PolicyComplianceEngine.validate_finding_for_submission(
        finding=finding_valid,
        program_handle="example",
    )
    assert res.compliant
    assert len(res.violations) == 0
    assert res.human_review_required  # Mandatory human review prior to H1 submission


def test_pii_credit_card_leak_detection():
    """Verify finding containing raw payment card data is blocked under privacy policy."""
    ex = Exchange(url="https://example.com", method="GET", status=200)
    finding_pii = Finding(
        id="f3",
        title="Exposed Credit Card",
        bug_class="Sensitive Data Exposure",
        url="https://example.com/cards",
        host="example.com",
        severity="high",
        summary="Exposed raw card 4111 1111 1111 1111 on endpoint",
        impact="Cardholder data exposure",
        steps=["Visit /cards"],
        evidence=[Evidence(summary="Cards", exchange=ex)],
        status="confirmed",
        meta={"verified": True},
    )
    res = PolicyComplianceEngine.validate_finding_for_submission(finding_pii, "test")
    assert not res.compliant
    assert any(v.rule_id == "COC-PRIV-001" for v in res.violations)


def test_program_discovery_ranker_honest_unloaded_state():
    """Verify unpopulated scope in list view does not default to 0 assets or arbitrary 55.0 score."""
    raw_prog = {
        "attributes": {
            "handle": "greenhouse",
            "name": "Greenhouse",
            "offers_bounties": True,
            "submission_state": "open",
            "rating": 4.5,
        }
        # No relationships.structured_scopes provided (typical list view)
    }
    ranked = ProgramDiscoveryRanker.score_program(raw_prog)
    assert ranked.scope_status == ScopeRetrievalStatus.NOT_LOADED
    assert ranked.asset_count is None
    assert ranked.bounty_score is None  # INSUFFICIENT DATA
    assert ranked.reward_range == "NOT RETRIEVED"

    summary = ranked.summary()
    assert "[INSUFFICIENT DATA]" in summary
    assert "Reward: NOT RETRIEVED" in summary
    assert "Scope: NOT LOADED | Assets: UNKNOWN" in summary
    assert any("INSUFFICIENT DATA" in r for r in ranked.reasons)


def test_program_discovery_ranker_loaded_scope_scoring():
    """Verify program with fetched structured scopes gets transparent, breakdown score."""
    raw_prog = {
        "attributes": {
            "handle": "greenhouse",
            "name": "Greenhouse",
            "offers_bounties": True,
            "submission_state": "open",
            "rating": 4.0,
        },
        "relationships": {
            "structured_scopes": {
                "data": [
                    {"attributes": {"asset_identifier": "app.greenhouse.io", "asset_type": "URL", "max_severity": "critical"}},
                    {"attributes": {"asset_identifier": "*.greenhouse.io", "asset_type": "WILDCARD", "max_severity": "high"}},
                ]
            }
        }
    }
    ranked = ProgramDiscoveryRanker.score_program(raw_prog)
    assert ranked.scope_status == ScopeRetrievalStatus.LOADED_WITH_ASSETS
    assert ranked.asset_count == 2
    assert ranked.web_asset_count == 2
    assert ranked.wildcard_count == 1
    assert ranked.bounty_score is not None
    # 40 (bounties) + 15 (open) + 10 (2*4 + 1*6 = 14 surface, but min(web*4 + wild*6, 30) = 14) + 10 (critical) + 8 (rating 4*2) = 87.0
    assert ranked.bounty_score == 87.0
    assert any("40.0" in r for r in ranked.reasons)
    assert any("critical" in r for r in ranked.reasons)


def test_program_discovery_ranker_loaded_empty_scope():
    """Verify program with loaded but empty structured scope shows 0 assets."""
    raw_prog = {
        "attributes": {
            "handle": "smallprog",
            "name": "Small Prog",
            "offers_bounties": False,
            "submission_state": "open",
        },
        "relationships": {
            "structured_scopes": {
                "data": []
            }
        }
    }
    ranked = ProgramDiscoveryRanker.score_program(raw_prog)
    assert ranked.scope_status == ScopeRetrievalStatus.LOADED_EMPTY
    assert ranked.asset_count == 0
    assert ranked.bounty_score is not None
    assert "Assets: 0" in ranked.summary()
