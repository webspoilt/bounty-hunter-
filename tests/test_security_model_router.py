"""Unit tests for Security Model Routing and Independent Evidence Reviewer (Phase 7)."""
import pytest
from bb.models import Evidence, Exchange, Finding
from bb.models_router import (
    CANONICAL_SECURITY_MODELS,
    SecurityModelRouter,
    SecurityTask,
)


def test_canonical_model_registry_integrity():
    router = SecurityModelRouter()
    catalog = router.get_canonical_catalog()
    assert len(catalog) >= 7

    model_ids = [m.identifier for m in catalog]
    assert "whiterabbitneo-8b" in model_ids
    assert "bugtraceai-core" in model_ids
    assert "vulnllm-r-7b" in model_ids
    assert "foundation-sec-8b" in model_ids
    assert "redsage-8b" in model_ids
    assert "local-tev1" in model_ids


def test_task_specific_model_routing():
    router = SecurityModelRouter()

    # Source code audit -> redsage-8b
    m_src = router.route_task(SecurityTask.SOURCE_CODE_AUDIT)
    assert m_src.identifier == "redsage-8b"

    # Pentest planning -> whiterabbitneo-8b
    m_plan = router.route_task(SecurityTask.PENTEST_PLANNING)
    assert m_plan.identifier == "whiterabbitneo-8b"

    # CWE mapping -> bugtraceai-core
    m_cwe = router.route_task(SecurityTask.CWE_MAPPING)
    assert m_cwe.identifier == "bugtraceai-core"

    # Evidence review -> vulnllm-r-7b
    m_rev = router.route_task(SecurityTask.EVIDENCE_REVIEW)
    assert m_rev.identifier == "vulnllm-r-7b"


def test_independent_evidence_reviewer_flags_missing_exchange():
    router = SecurityModelRouter()
    # High finding with no raw HTTP exchange
    f = Finding(
        title="Unverified High Finding",
        bug_class="sqli",
        severity="high",
        host="127.0.0.1:8000",
        url="http://127.0.0.1:8000/api/vulnerable/products/search",
        steps=["Step 1"],
        evidence=[],
    )
    rev = router.independent_evidence_review(f)
    assert rev["verdict"] == "FLAGGED_FOR_HUMAN_REVIEW"
    assert any("raw HTTP" in issue for issue in rev["issues"])


def test_independent_evidence_reviewer_approves_verified_finding():
    router = SecurityModelRouter()
    # High finding with valid raw HTTP exchange
    f = Finding(
        title="Verified Reflected XSS",
        bug_class="xss",
        severity="high",
        host="127.0.0.1:8000",
        url="http://127.0.0.1:8000/api/vulnerable/echo",
        steps=["Step 1: Send payload", "Step 2: Check reflection"],
        evidence=[
            Evidence(
                summary="Reflected XSS evidence",
                exchange=Exchange(
                    method="GET",
                    url="http://127.0.0.1:8000/api/vulnerable/echo?msg=test",
                    status=200,
                ),
            )
        ],
    )
    rev = router.independent_evidence_review(f)
    assert rev["verdict"] == "APPROVED"
    assert len(rev["issues"]) == 0
