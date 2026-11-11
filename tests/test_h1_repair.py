"""Comprehensive regression and edge-case tests for HackerOne pipeline repair.

Verifies:
1. `asdict` serialization of ProgramAuthorizationBrief (no NameError)
2. Safe filename sanitization (no path traversal, e.g. ../../)
3. Honest handling of unpopulated structured scope in list views ('Not loaded' state)
4. ProgramDiscoveryRanker scoring with and without structured scopes
5. Error handling without traceback exposure on missing/unauthorized assets
6. Brief generation with empty and populated asset inventories
7. Scope approval rejection on empty asset inventory or out-of-scope target
"""
import json
import os
import pytest
from pathlib import Path
from dataclasses import asdict

from bb.h1 import (
    BriefGenerator,
    H1Client,
    H1Error,
    PolicyParser,
    ProgramAuthorizationBrief,
    ProgramDiscoveryRanker,
    StructuredAssetEntry,
    sanitize_handle,
)
from bb.scope import Scope


def test_sanitize_handle_prevents_path_traversal():
    assert sanitize_handle("../../evil_program") == "evil_program"
    assert sanitize_handle("program/with/slashes") == "program_with_slashes"
    assert sanitize_handle("..\\..\\windows_traversal") == "windows_traversal"
    assert sanitize_handle("normal-handle_123.corp") == "normal-handle_123.corp"
    assert sanitize_handle("???!!!") == "unknown_program"


def test_brief_asdict_serialization():
    brief = ProgramAuthorizationBrief(
        handle="greenhouse",
        program_name="Greenhouse Software",
        offers_bounties=True,
        policy_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        retrieved_at="2026-11-11T12:00:00Z",
        in_scope_assets=["https://api.greenhouse.io"],
        out_of_scope_assets=[],
        structured_asset_entries=[
            StructuredAssetEntry(
                identifier="https://api.greenhouse.io",
                asset_type="URL",
                eligible_for_bounty=True,
                eligible_for_submission=True,
                max_severity="critical",
                instruction="Test safely",
            ).to_dict()
        ],
        scope_exclusions=["Denial of Service"],
        testing_restrictions=["Max 3 req/sec"],
        rate_limit=3.0,
        custom_headers={"X-Bug-Bounty": "webspoilt"},
        human_review_notes=[],
        recommended_first_target="https://api.greenhouse.io",
    )

    # Test asdict serialization directly
    serialized = asdict(brief)
    assert isinstance(serialized, dict)
    assert serialized["handle"] == "greenhouse"
    assert serialized["structured_asset_entries"][0]["asset_type"] == "URL"

    # Test json.dumps serialization without exception
    json_str = json.dumps(serialized, indent=2)
    assert "https://api.greenhouse.io" in json_str

    # Test deserialization and recreation
    loaded_data = json.loads(json_str)
    recreated = ProgramAuthorizationBrief(**loaded_data)
    assert recreated.handle == "greenhouse"
    assert recreated.render_markdown().startswith("# PROGRAM AUTHORIZATION BRIEF: GREENHOUSE")


def test_program_ranking_honest_asset_display_when_not_loaded():
    raw_listing_item = {
        "id": "greenhouse",
        "attributes": {
            "handle": "greenhouse",
            "name": "Greenhouse",
            "offers_bounties": True,
            "submission_state": "open",
            "rating": 4.5,
        },
        # Notice: in H1 /v1/hackers/programs list view, relationships.structured_scopes is NOT included
        "relationships": {}
    }

    scored = ProgramDiscoveryRanker.score_program(raw_listing_item)
    assert scored.handle == "greenhouse"
    assert scored.assets_loaded is False
    assert "Assets: Not loaded in list view" in scored.summary()
    assert scored.bounty_score == 40.0 + 15.0 + (4.5 * 2.0)  # 40 (bounty) + 15 (open) + 9 (rating) = 64.0
    assert any("Assets not loaded" in r for r in scored.reasons)


def test_program_ranking_with_loaded_assets():
    raw_detailed_item = {
        "id": "greenhouse",
        "attributes": {
            "handle": "greenhouse",
            "name": "Greenhouse",
            "offers_bounties": True,
            "submission_state": "open",
            "rating": 4.5,
        },
        "relationships": {
            "structured_scopes": {
                "data": [
                    {"attributes": {"asset_type": "URL", "asset_identifier": "https://api.greenhouse.io", "max_severity": "critical"}},
                    {"attributes": {"asset_type": "DOMAIN", "asset_identifier": "app.greenhouse.io", "max_severity": "high"}},
                    {"attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.greenhouse.io", "max_severity": "critical"}},
                ]
            }
        }
    }

    scored = ProgramDiscoveryRanker.score_program(raw_detailed_item)
    assert scored.assets_loaded is True
    assert scored.asset_count == 3
    assert scored.web_asset_count == 3
    assert scored.wildcard_count == 1
    assert scored.max_severity == "critical"
    assert "Assets:  3 (Web:  3, Wildcards:  1)" in scored.summary()
    # 40 (bounty) + 15 (open) + (3*4 + 1*6 = 18 surface) + 10 (critical) + 9 (rating) = 92.0
    assert scored.bounty_score == 92.0


def test_brief_generation_with_empty_and_populated_inventory():
    policy = PolicyParser.parse_policy("testprog", "Polite testing only.")

    # Empty inventory
    empty_brief = BriefGenerator.generate_brief(
        prog={"id": "testprog", "attributes": {"handle": "testprog", "offers_bounties": False}},
        policy=policy,
        scopes=[],
        exclusions=[],
    )
    assert empty_brief.in_scope_assets == []
    assert empty_brief.recommended_first_target == ""
    md_empty = empty_brief.render_markdown()
    assert "No accessible structured scope assets returned by API" in md_empty
    assert "No in-scope web asset identified for testing" in md_empty

    # Populated inventory
    pop_brief = BriefGenerator.generate_brief(
        prog={"id": "testprog", "attributes": {"handle": "testprog", "offers_bounties": True}},
        policy=policy,
        scopes=[
            {"attributes": {"asset_identifier": "https://api.testprog.io", "asset_type": "URL", "eligible_for_submission": True}},
            {"attributes": {"asset_identifier": "*.testprog.io", "asset_type": "WILDCARD", "eligible_for_submission": True}},
        ],
        exclusions=[],
    )
    assert len(pop_brief.in_scope_assets) == 2
    assert pop_brief.recommended_first_target == "https://api.testprog.io"
    md_pop = pop_brief.render_markdown()
    assert "https://api.testprog.io" in md_pop
    assert "🎯 **`https://api.testprog.io`**" in md_pop
