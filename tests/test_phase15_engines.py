"""
Tests for Phase 15 Advanced Security Engines & Verification Architecture.
"""
import pytest
from bb.engines import EngineRegistry
from bb.engines.trivy import TrivyEngine
from bb.engines.trufflehog import TruffleHogEngine
from bb.engines.strix import StrixEngine
from bb.engines.pyrit import PyRITEngine
from bb.engines.skillspector import SkillSpectorEngine
from bb.engines.source_audit import SourceAuditEngine
from bb.engines.base import EngineCategory, EngineState, ExecutionContext


def test_registry_contains_new_engines():
    """Verify all new Phase 15 adapters are registered in the global engine registry."""
    reg = EngineRegistry.get_instance()
    for name in ["trivy", "trufflehog", "strix", "pyrit", "skillspector", "source-audit"]:
        eng = reg.get(name)
        assert eng is not None, f"Engine {name} missing from registry"
        avail = eng.check_availability()
        assert avail.state in (EngineState.READY, EngineState.VERIFIED_OPERATIONAL)


def test_trivy_engine_metadata_and_capabilities():
    """Verify Trivy engine interface and capabilities."""
    trivy = TrivyEngine()
    assert trivy.name == "trivy"
    assert trivy.category == EngineCategory.SAST
    assert trivy.license == "Apache-2.0"
    assert "sca" in trivy.get_capabilities()
    assert "cve" in trivy.get_capabilities()


def test_trufflehog_engine_metadata_and_capabilities():
    """Verify TruffleHog engine interface and non-verification invariant."""
    th = TruffleHogEngine()
    assert th.name == "trufflehog"
    assert th.category == EngineCategory.SAST
    assert th.license == "AGPL-3.0"
    assert "secrets" in th.get_capabilities()
    assert "api_keys" in th.get_capabilities()


def test_strix_engine_execution_flow():
    """Verify Strix autonomous agent executes within authorized scope bounds."""
    strix = StrixEngine()
    ctx = ExecutionContext(
        target="http://127.0.0.1:8000/api/secure/echo",
        program="local_lab",
        dry_run=True,
    )
    res = strix.execute(ctx)
    assert res.success is True
    assert res.exit_code == 0


def test_pyrit_engine_capabilities():
    """Verify PyRIT generative AI red teaming capabilities."""
    pyrit = PyRITEngine()
    assert "prompt_injection" in pyrit.get_capabilities()
    assert "rag_leakage" in pyrit.get_capabilities()


def test_skillspector_and_source_audit():
    """Verify SkillSpector and SourceAudit adapters."""
    ss = SkillSpectorEngine()
    assert "mcp_poisoning" in ss.get_capabilities()

    sa = SourceAuditEngine()
    assert "boundary_audit" in sa.get_capabilities()
    assert "principal_separation" in sa.get_capabilities()
