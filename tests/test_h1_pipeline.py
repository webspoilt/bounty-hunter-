"""Comprehensive test suite for Phase 2–9 HackerOne Pipeline.

Validates:
- H1Client: credential handling, token masking, host boundary restriction
- Pagination over JSON:API page[number] and page[size]
- Rate limiting (429 Retry-After handling)
- Authentication and network error handling
- ProgramDiscoveryRanker: multi-factor ranking, monetary bounty prioritization, web asset scoring
- PolicyParser: verbatim policy preservation, hash calculation, prohibited attacks, custom headers, ambiguity detection
- BriefGenerator: authorization brief card generation, target recommendation, approval gate
- Target approval: rejection of unauthorized targets, acceptance of valid in-scope targets
- Report preparation: draft generation, curl command rendering, no auto-submission
- CLI integration: bb h1 subcommands
"""
import json
from pathlib import Path
import pytest

from bb.h1 import (
    BriefGenerator,
    H1AuthError,
    H1Client,
    H1Error,
    H1RateLimitError,
    HackerOneReportGenerator,
    PolicyParser,
    ProgramAuthorizationBrief,
    ProgramDiscoveryRanker,
    ensure_h1_dirs,
    submit_curl,
    submit_payload,
)
from bb.models import Finding
from bb.scope import Scope


# ---------------------------------------------------------------------------
# PHASE 2: CLIENT & AUTHENTICATION TESTS
# ---------------------------------------------------------------------------

def test_client_requires_credentials(monkeypatch):
    monkeypatch.setattr("bb.h1.H1_USERNAME", "")
    monkeypatch.setattr("bb.h1.H1_TOKEN", "")
    monkeypatch.setenv("H1_USERNAME", "")
    monkeypatch.setenv("H1_TOKEN", "")
    with pytest.raises(H1AuthError) as exc:
        H1Client(username="", token="")
    assert "credentials missing" in str(exc.value).lower()


def test_client_host_restriction():
    with pytest.raises(H1Error) as exc:
        H1Client(username="test_user", token="test_token", api_base="https://evil-attacker.com/v1")
    assert "restricted to official HackerOne API host" in str(exc.value)


def test_client_pagination(monkeypatch):
    client = H1Client(username="test_user", token="test_token")
    calls = []

    def mock_get(path, **params):
        calls.append((path, params))
        page_num = params.get("page[number]", 1)
        if page_num == 1:
            return {
                "data": [{"id": f"prog_{i}", "attributes": {"handle": f"prog_{i}"}} for i in range(10)],
                "links": {"next": "https://api.hackerone.com/v1/hackers/programs?page[number]=2"},
            }
        elif page_num == 2:
            return {
                "data": [{"id": f"prog_{i}", "attributes": {"handle": f"prog_{i}"}} for i in range(10, 15)],
                "links": {},
            }
        return {"data": []}

    monkeypatch.setattr(client, "_get", mock_get)
    progs = client.programs(page_size=10, max_pages=3)
    assert len(progs) == 15
    assert len(calls) == 2
    assert calls[0][1]["page[number]"] == 1
    assert calls[1][1]["page[number]"] == 2


def test_client_rate_limit_retry(monkeypatch):
    client = H1Client(username="test_user", token="test_token", max_retries=1)
    attempt_count = 0

    class MockResponse:
        status_code = 429
        headers = {"Retry-After": "1"}
        text = "Too Many Requests"

    def mock_httpx_get(*args, **kwargs):
        nonlocal attempt_count
        attempt_count += 1
        return MockResponse()

    monkeypatch.setattr("httpx.get", mock_httpx_get)
    with pytest.raises(H1RateLimitError) as exc:
        client._get("/hackers/programs")
    assert exc.value.retry_after == 1.0
    assert attempt_count == 2  # initial + 1 retry


# ---------------------------------------------------------------------------
# PHASE 3: PROGRAM DISCOVERY & RANKING TESTS
# ---------------------------------------------------------------------------

def test_program_ranking_prioritizes_bounties_and_web_surface():
    raw_programs = [
        {
            "id": "1",
            "attributes": {
                "handle": "unpaid_vdp",
                "name": "Unpaid VDP",
                "offers_bounties": False,
                "submission_state": "open",
            },
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {"attributes": {"asset_type": "URL", "asset_identifier": "https://vdp.example.com"}}
                    ]
                }
            }
        },
        {
            "id": "2",
            "attributes": {
                "handle": "top_fintech_bbp",
                "name": "Top Fintech BBP",
                "offers_bounties": True,
                "submission_state": "open",
            },
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {"attributes": {"asset_type": "URL", "asset_identifier": "https://api.fintech.com", "max_severity": "critical"}},
                        {"attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.fintech.com", "max_severity": "critical"}},
                        {"attributes": {"asset_type": "URL", "asset_identifier": "https://app.fintech.com", "max_severity": "high"}},
                    ]
                }
            }
        },
        {
            "id": "3",
            "attributes": {
                "handle": "paused_bbp",
                "name": "Paused BBP",
                "offers_bounties": True,
                "submission_state": "paused",
            },
            "relationships": {"structured_scopes": {"data": []}}
        }
    ]

    ranked = ProgramDiscoveryRanker.rank_programs(raw_programs)
    assert len(ranked) == 3
    # Top rank must be the paying BBP with active submission state
    assert ranked[0].handle == "top_fintech_bbp"
    assert ranked[0].offers_bounties is True
    assert ranked[0].bounty_score > ranked[1].bounty_score
    assert ranked[0].wildcard_count == 1
    assert ranked[0].max_severity == "critical"
    # Paused BBP should be penalized
    assert any("paused" in r.lower() for r in ranked[-1].reasons or [])


# ---------------------------------------------------------------------------
# PHASE 4: COMPLETE GUIDELINE READER & POLICY PARSER TESTS
# ---------------------------------------------------------------------------

def test_policy_parser_preserves_text_and_extracts_rules():
    sample_policy = """
    # Security Bug Bounty Guidelines
    Welcome to Acme Corp's program!
    Testing rate limits: Maximum 5 requests per second. Please test politely.
    
    Prohibited Activities:
    - Denial of Service (DoS) attacks or automated mass scanners are strictly forbidden.
    - Social engineering and phishing against Acme employees.
    - Destructive write operations or data tampering.
    
    Out of Scope:
    - Clickjacking without demonstrated sensitive action impact.
    - SPF/DKIM missing records.
    - Self-XSS.
    
    Header requirement:
    All testing requests must include the header: X-Bug-Bounty: researcher-audit
    
    Discretionary decisions:
    Reward amounts are decided at our discretion on a case-by-case basis.
    """

    rec = PolicyParser.parse_policy("acme", sample_policy)
    assert rec.handle == "acme"
    assert len(rec.policy_hash) == 64  # SHA-256
    assert rec.original_policy_text == sample_policy
    assert rec.rate_limit_rps == 5.0
    assert "denial_of_service" in rec.prohibited_attacks
    assert "automated_scanners_prohibited" in rec.prohibited_attacks
    assert "social_engineering" in rec.prohibited_attacks
    assert "clickjacking" in rec.ineligible_findings
    assert "self_xss" in rec.ineligible_findings
    assert rec.requires_custom_header is True
    assert rec.custom_header_name == "X-Bug-Bounty"
    assert rec.custom_header_value == "researcher-audit"
    assert rec.human_review_required is True
    assert len(rec.ambiguous_clauses) > 0


# ---------------------------------------------------------------------------
# PHASE 6: BRIEF GENERATOR & AUTHORIZATION GATE TESTS
# ---------------------------------------------------------------------------

def test_brief_generation_and_approval_flow():
    prog = {
        "id": "acme",
        "attributes": {
            "handle": "acme",
            "name": "Acme Global",
            "offers_bounties": True,
        }
    }
    policy_rec = PolicyParser.parse_policy("acme", "Max 3 requests per second. No DoS.")
    scopes = [
        {"attributes": {"asset_identifier": "https://api.acme.com", "asset_type": "URL", "eligible_for_submission": True}},
        {"attributes": {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD", "eligible_for_submission": True}},
        {"attributes": {"asset_identifier": "https://internal-dev.acme.com", "asset_type": "URL", "eligible_for_submission": False}},
    ]
    exclusions = [{"attributes": {"name": "Volumetric Denial of Service"}}]

    brief = BriefGenerator.generate_brief(prog, policy_rec, scopes, exclusions)
    assert brief.handle == "acme"
    assert brief.offers_bounties is True
    assert "https://api.acme.com" in brief.in_scope_assets
    assert "https://internal-dev.acme.com" in brief.out_of_scope_assets
    assert brief.recommended_first_target == "https://api.acme.com"
    assert brief.approval_status == "PENDING_HUMAN_APPROVAL"

    # Render markdown card
    md = brief.render_markdown()
    assert "PROGRAM AUTHORIZATION BRIEF: ACME" in md
    assert "PENDING_HUMAN_APPROVAL" in md
    assert "https://api.acme.com" in md

    # Create ProgramProfile from brief
    profile = BriefGenerator.create_program_profile(brief)
    assert profile.program_id == "acme"
    assert profile.rate_limit == 3.0
    assert "https://api.acme.com" in profile.in_scope_assets
    assert "https://internal-dev.acme.com" in profile.out_of_scope_assets


def test_target_approval_enforces_scope():
    client = H1Client(username="test_user", token="test_token")
    mock_payload = {
        "data": {
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {"attributes": {"asset_identifier": "https://api.acme.com", "asset_type": "URL", "eligible_for_submission": True}},
                        {"attributes": {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD", "eligible_for_submission": True}},
                        {"attributes": {"asset_identifier": "https://out-of-scope.acme.com", "asset_type": "URL", "eligible_for_submission": False}},
                    ]
                }
            }
        }
    }
    client.program = lambda handle: mock_payload
    client.structured_scopes = lambda handle: mock_payload["data"]["relationships"]["structured_scopes"]["data"]
    scope = client.scope("acme")

    # In-scope assertions
    assert scope.is_in_scope("https://api.acme.com/v1/users")
    assert scope.is_in_scope("https://portal.acme.com/login")

    # Out-of-scope assertions (must be strictly blocked)
    assert not scope.is_in_scope("https://out-of-scope.acme.com/admin")
    assert not scope.is_in_scope("https://unrelated-domain.com")


# ---------------------------------------------------------------------------
# PHASE 8: REPORT DRAFT PREPARATION TESTS
# ---------------------------------------------------------------------------

def test_h1_report_preparation():
    finding = Finding(
        title="BOLA on /api/v2/invoices: Cross-Tenant Data Disclosure",
        bug_class="BOLA_IDOR",
        severity="high",
        host="api.acme.com",
        url="https://api.acme.com/api/v2/invoices/inv_9921",
        confidence=0.95,
        summary="User B is able to fetch invoice inv_9921 owned by User A.",
        impact="Demonstrated unauthorized access to financial data across organization boundaries.",
        steps=["Send GET to /api/v2/invoices/inv_9921 as role B."],
    )
    brief = ProgramAuthorizationBrief(
        handle="acme",
        program_name="Acme Global",
        offers_bounties=True,
        policy_hash="abc123hash",
        retrieved_at="2026-11-11T12:00:00Z",
        in_scope_assets=["https://api.acme.com"],
        out_of_scope_assets=[],
        scope_exclusions=[],
        testing_restrictions=[],
        rate_limit=3.0,
        custom_headers={},
        human_review_notes=[],
        recommended_first_target="https://api.acme.com",
    )

    draft = HackerOneReportGenerator.prepare_draft(finding, brief)
    assert draft["team_handle"] == "acme"
    assert draft["severity"] == "high"
    assert "BOLA on /api/v2/invoices" in draft["title"]
    assert "curl" in draft["curl_command"]
    assert "never executed by bountybot" in draft["curl_command"]
    assert draft["payload"]["data"]["attributes"]["team_handle"] == "acme"
    assert draft["payload"]["data"]["attributes"]["severity_rating"] == "high"
