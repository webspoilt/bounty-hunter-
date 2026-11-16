"""Comprehensive unit and integration tests for Phase 12 Program Discovery Engine."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from bb.programs.program_models import (
    AIClassification,
    DiscoveredProgram,
    PriorityTier,
    ProgramAsset,
    ProgramEligibilityState,
)
from bb.programs.program_eligibility import ProgramEligibilityGate
from bb.programs.ai_development_intel import AIDevelopmentClassifier
from bb.programs.attack_surface import AttackSurfaceAnalyzer
from bb.programs.opportunity_matcher import OpportunityMatcher
from bb.programs.opportunity_score import OpportunityScorer
from bb.programs.program_store import ProgramStore
from bb.programs.discovery import ProgramDiscoveryEngine


def test_program_models_and_serialization():
    prog = DiscoveredProgram(
        program_id="101",
        handle="test-saas",
        name="Test SaaS Inc",
        url="https://hackerone.com/test-saas",
        state="public_mode",
        submission_state="open",
        offers_bounties=True,
        currency="USD",
        policy_text="Detailed public policy text with scope rules and requirements.",
        policy_hash="abc123hash",
        eligibility_state=ProgramEligibilityState.ELIGIBLE,
        ai_classification=AIClassification.CONFIRMED_AI_BUILT,
        opportunity_score=85.5,
        evidence_confidence=90.0,
        priority_tier=PriorityTier.HIGH_PRIORITY,
    )
    d = prog.to_dict()
    assert d["handle"] == "test-saas"
    assert d["opportunity_score"] == 85.5
    assert d["ai_classification"] == "CONFIRMED_AI_BUILT"


def test_program_eligibility_gate():
    # 1. Private program -> PRIVATE
    p_priv = DiscoveredProgram(
        program_id="1", handle="priv", name="Priv", url="",
        state="soft_launched", submission_state="open", offers_bounties=True,
    )
    st, reasons = ProgramEligibilityGate.evaluate(p_priv)
    assert st == ProgramEligibilityState.PRIVATE

    # 2. Inactive submissions -> INACTIVE
    p_inact = DiscoveredProgram(
        program_id="2", handle="inact", name="Inact", url="",
        state="public_mode", submission_state="paused", offers_bounties=True,
    )
    st2, _ = ProgramEligibilityGate.evaluate(p_inact)
    assert st2 == ProgramEligibilityState.INACTIVE

    # 3. No monetary bounties -> NO_MONETARY_BOUNTY
    p_vdp = DiscoveredProgram(
        program_id="3", handle="vdp", name="VDP", url="",
        state="public_mode", submission_state="open", offers_bounties=False,
    )
    st3, _ = ProgramEligibilityGate.evaluate(p_vdp)
    assert st3 == ProgramEligibilityState.NO_MONETARY_BOUNTY

    # 4. Valid public monetary program -> ELIGIBLE
    p_ok = DiscoveredProgram(
        program_id="4", handle="valid-bounty", name="Valid Bounty", url="",
        state="public_mode", submission_state="open", offers_bounties=True,
        policy_text="This is a comprehensive bug bounty policy with clear testing rules.",
        in_scope_assets=[ProgramAsset(asset_identifier="https://app.valid.com", asset_type="URL")],
    )
    st4, _ = ProgramEligibilityGate.evaluate(p_ok)
    assert st4 == ProgramEligibilityState.ELIGIBLE


def test_ai_development_classifier():
    # Primary evidence lookup for Cursor
    c_cursor, ev_cursor = AIDevelopmentClassifier.evaluate(
        handle="cursor", name="Cursor", description="AI code editor", policy_text=""
    )
    assert c_cursor == AIClassification.CONFIRMED_AI_BUILT
    assert len(ev_cursor) == 1
    assert ev_cursor[0].evidence_confidence >= 0.90

    # Textual heuristic for AI product feature (not AI built)
    c_copilot, ev_copilot = AIDevelopmentClassifier.evaluate(
        handle="sample-tool", name="Sample Tool", description="Includes an AI assistant copilot", policy_text=""
    )
    assert c_copilot == AIClassification.AI_PRODUCT

    # Unknown
    c_unk, ev_unk = AIDevelopmentClassifier.evaluate(
        handle="legacy-corp", name="Legacy Corp", description="Traditional retail store", policy_text=""
    )
    assert c_unk == AIClassification.UNKNOWN
    assert len(ev_unk) == 0


def test_attack_surface_and_scoring():
    prog = DiscoveredProgram(
        program_id="50", handle="multi-saas", name="Multi SaaS", url="",
        state="public_mode", submission_state="open", offers_bounties=True,
        policy_text="Application features organization team workspaces, OAuth logins, and public REST API endpoints.",
        in_scope_assets=[ProgramAsset(asset_identifier="https://api.saas.com", asset_type="URL")],
        ai_classification=AIClassification.CONFIRMED_AI_BUILT,
        raw_attributes={"triage_active": True},
    )
    AttackSurfaceAnalyzer.analyze(prog)
    assert prog.is_multi_tenant is True
    assert prog.has_rest_api is True
    assert prog.has_auth_workflows is True

    opps = OpportunityMatcher.match(prog)
    assert len(opps) >= 2
    cwe_set = set(o.cwe_id for o in opps)
    assert "CWE-639" in cwe_set

    score, conf, criteria = OpportunityScorer.score_program(prog)
    assert score >= 80.0  # High priority
    assert conf >= 80.0
    assert prog.priority_tier == PriorityTier.HIGH_PRIORITY
    assert len(criteria) == 7


def test_program_store_persistence(tmp_path: Path):
    db_file = tmp_path / "test_h1_prog.db"
    store = ProgramStore(db_path=db_file)

    p = DiscoveredProgram(
        program_id="99", handle="persisted-target", name="Persisted Target",
        url="https://hackerone.com/persisted-target", state="public_mode",
        submission_state="open", offers_bounties=True, policy_text="Policy text here",
        eligibility_state=ProgramEligibilityState.ELIGIBLE,
        opportunity_score=82.0, evidence_confidence=88.0,
        priority_tier=PriorityTier.HIGH_PRIORITY,
    )
    store.save_program(p)

    counts = store.count_programs()
    assert counts["total"] == 1
    assert counts["eligible"] == 1

    fetched = store.get_program("persisted-target")
    assert fetched is not None
    assert fetched.opportunity_score == 82.0
    assert fetched.priority_tier == PriorityTier.HIGH_PRIORITY

    # Select target
    fetched.is_selected = True
    store.save_program(fetched)
    counts2 = store.count_programs()
    assert counts2["selected"] == 1
