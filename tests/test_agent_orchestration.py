"""Unit tests for Autonomous Pentesting Agent Orchestration (Phase 6)."""
import pytest
from bb.engines import EngineRegistry
from bb.engines.base import EngineCategory, ExecutionContext, FindingLifecycle
from bb.engines.claude_bughunter import ClaudeBugHunterEngine
from bb.engines.shannon import ShannonEngine


def test_agent_registration():
    reg = EngineRegistry.get_instance()
    agents = reg.list_engines(category=EngineCategory.AUTONOMOUS)
    agent_names = [ag.name for ag in agents]
    assert "shannon" in agent_names
    assert "claude-bughunter" in agent_names


def test_shannon_prerequisite_reporting():
    shannon = ShannonEngine()
    avail = shannon.check_availability()
    # Docker Desktop daemon is stopped on host; shannon must report BLOCKED_DEPENDENCY
    assert avail.state.value == "BLOCKED_DEPENDENCY"
    assert avail.available is False


def test_claude_bughunter_availability_and_skills():
    cbh = ClaudeBugHunterEngine()
    avail = cbh.check_availability()
    assert avail.state.value in ("VERIFIED_OPERATIONAL", "READY")
    assert avail.available is True
    assert "83 specialized hunting skills" in avail.remediation_hint


def test_claude_bughunter_live_classification_and_hypotheses():
    cbh = ClaudeBugHunterEngine()
    ctx = ExecutionContext(
        program="owasp-lab",
        target="http://127.0.0.1:8000/api/vulnerable/cart/apply-coupon",
        rate_limit=3.0,
        timeout_sec=30,
    )
    res = cbh.execute(ctx)
    assert res.success is True
    assert res.exit_code == 0
    assert len(res.findings) >= 3

    # Ensure findings enter as DISCOVERED and not auto-verified
    for f in res.findings:
        assert f.status == FindingLifecycle.DISCOVERED.value
        assert f.confidence == "hypothesized"
        assert f.meta.get("active_discovery") is True

    # Check for coupon-relevant patterns
    bug_classes = [f.bug_class for f in res.findings]
    assert "business-logic" in bug_classes or "race-condition" in bug_classes
