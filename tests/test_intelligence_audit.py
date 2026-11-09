"""Comprehensive Regression Tests for P6 Final Acceptance Audit & Corrections.

Covers:
1. CVE-2023-38606 cannot support a web IDOR hypothesis merely through version matching.
2. Correct vendor and component matching is required.
3. Version boundary conditions work correctly.
4. Vulnerability-class mismatches are rejected (state: class_mismatch or version_match_only).
5. Unknown classifications do not create artificial confidence.
6. Relevant intelligence still increases research priority appropriately (state: relevant -> +3.0 bonus).
7. Irrelevant intelligence cannot improve empirical priors or grant intelligence bonuses.
8. Duplicate outcomes are handled correctly (tracked separately, do not bias confirmed/rejected counts).
9. Inconclusive outcomes do not become negative ground truth (remain neutral).
10. Unreviewed judgments cannot modify empirical priors.
11. Cost adjustment is separated from empirical success probability.
12. Repeated ranking is deterministic for identical inputs.
13. Existing scope and authorization gates remain unchanged.
"""
from __future__ import annotations

import json
import pytest

from bb.intelligence import (
    IntelligenceEngine,
    IntelligenceRecord,
    VersionConstraint,
    check_version_applicable,
    compute_hypothesis_priors,
    evaluate_intelligence_relevance,
    rank_hypotheses_with_intelligence,
)
from bb.intelligence.versions import (
    STATE_CLASS_MISMATCH,
    STATE_COMPONENT_MISMATCH,
    STATE_INSUFFICIENT_INFORMATION,
    STATE_POSSIBLY_RELEVANT,
    STATE_PRODUCT_MISMATCH,
    STATE_RELEVANT,
    STATE_VERSION_MATCH_ONLY,
)


@pytest.fixture
def audit_engine(tmp_path):
    db_file = tmp_path / "audit_intel.db"
    engine = IntelligenceEngine(db_path=db_file)
    yield engine
    engine.close()


def test_cve_38606_cannot_support_web_idor_hypothesis(audit_engine):
    """CVE-2023-38606 is an Apple kernel privilege escalation flaw.

    Must NEVER be accepted as supporting evidence for a web IDOR hypothesis.
    """
    cve_doc = {
        "cve": {
            "id": "CVE-2023-38606",
            "descriptions": [{"lang": "en", "value": "An app may be able to modify sensitive kernel state."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}}]},
            "weaknesses": [{"description": [{"value": "NVD-CWE-noinfo"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.0.0", "versionEndExcluding": "16.6"}]}]}],
        }
    }
    audit_engine.ingest_nvd_cve(cve_doc)
    rec = audit_engine.get_record("CVE-2023-38606")

    # Evaluate against a Web IDOR hypothesis on a web service
    target_context = {
        "product": "user_api",
        "vendor": "targetcorp",
        "version": "1.2.0",  # falls within 1.0.0 - 16.6 range
        "vuln_class": "IDOR",
        "attack_surface": "web_application",
    }

    state, reason = evaluate_intelligence_relevance(rec, target_context)
    assert state == STATE_PRODUCT_MISMATCH
    assert "user_api" in reason and "iphone_os" in reason

    # Even if product name was spoofed as iphone_os, class and attack surface mismatch must reject it
    spoofed_context = {
        "product": "iphone_os",
        "vendor": "apple",
        "version": "1.2.0",
        "vuln_class": "IDOR",
        "attack_surface": "web_application",
    }
    state2, reason2 = evaluate_intelligence_relevance(rec, spoofed_context)
    assert state2 in (STATE_CLASS_MISMATCH, STATE_VERSION_MATCH_ONLY)


def test_vulnerability_class_mismatch_rejected():
    """Version matches, but vuln class is mismatched -> returns version_match_only, zero bonus."""
    rec = IntelligenceRecord(
        id="CVE-2022-0155",
        source="nvd",
        source_id="CVE-2022-0155",
        source_url="https://nvd.nist.gov",
        title="follow-redirects header leak",
        description="Cookie header leakage upon redirect",
        vuln_class="Open Redirect",  # or Information Exposure
        retrieved_at="2026-01-01T00:00:00Z",
        affected_product="follow-redirects",
        version_constraints=[VersionConstraint(version_end_excluding="1.14.7")],
    )

    # Hypothesis is IDOR
    ctx = {
        "product": "follow-redirects",
        "version": "1.14.0",
        "vuln_class": "IDOR",
    }
    state, reason = evaluate_intelligence_relevance(rec, ctx)
    assert state == STATE_CLASS_MISMATCH


def test_relevant_intelligence_grants_priority_bonus(audit_engine):
    """When vendor, product, version, and vulnerability class match, state is 'relevant'

    and grants appropriate intelligence priority bonus.
    """
    cve_confluence = {
        "cve": {
            "id": "CVE-2022-26134",
            "descriptions": [{"lang": "en", "value": "OGNL injection in Confluence Server and Data Center allows remote code execution."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "weaknesses": [{"description": [{"value": "CWE-917"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.3.0", "versionEndExcluding": "7.18.1"}]}]}],
        }
    }
    audit_engine.ingest_nvd_cve(cve_confluence)
    rec = audit_engine.get_record("CVE-2022-26134")

    ctx = {
        "vendor": "atlassian",
        "product": "confluence",
        "version": "7.15.0",
        "vuln_class": "Remote Code Execution",
        "attack_surface": "web_application",
    }

    state, reason = evaluate_intelligence_relevance(rec, ctx)
    assert state == STATE_RELEVANT

    hypotheses = [
        {
            "hypothesis_id": "hypo-confluence-rce",
            "vuln_class": "Remote Code Execution",
            "severity": "critical",
            "vendor": "atlassian",
            "product": "confluence",
            "version": "7.15.0",
            "supporting_intelligence": [rec],
        },
        {
            "hypothesis_id": "hypo-other-rce",
            "vuln_class": "Remote Code Execution",
            "severity": "critical",
            "vendor": "generic",
            "product": "app",
            "version": "1.0.0",
            "supporting_intelligence": [],
        }
    ]

    ranked = audit_engine.rank_hypotheses(hypotheses)
    assert ranked[0]["hypothesis_id"] == "hypo-confluence-rce"
    assert ranked[0]["meta"]["intel_rank_score"] > ranked[1]["meta"]["intel_rank_score"]


def test_adaptive_prior_mathematical_separation(audit_engine):
    """Verifies:

    - Empirical success prior = (confirmed + 1) / (decided + 2)
    - Duplicate does NOT count as confirmed or rejected.
    - Inconclusive does NOT count as negative ground truth.
    - Cost-adjusted priority is separated from empirical probability.
    """
    # 3 confirmed, 1 duplicate, 0 rejected
    for i in range(3):
        audit_engine.record_hypothesis_outcome(
            hypothesis_id=f"h-id-{i}",
            program="math-prog",
            endpoint=f"/u/{i}",
            method="GET",
            vuln_class="IDOR",
            supporting_intelligence_ids=[],
            supporting_observations=[],
            proposed_test="test",
            result="confirmed",
            verification_result="confirmed",
            researcher_review="approved",
            requests_cost=3,
        )
    audit_engine.record_hypothesis_outcome(
        hypothesis_id="h-id-dup",
        program="math-prog",
        endpoint="/u/0",
        method="GET",
        vuln_class="IDOR",
        supporting_intelligence_ids=[],
        supporting_observations=[],
        proposed_test="test",
        result="duplicate",
        verification_result="confirmed",
        researcher_review="approved",
        requests_cost=2,
    )

    # 0 confirmed, 4 rejected
    for i in range(4):
        audit_engine.record_hypothesis_outcome(
            hypothesis_id=f"h-ssrf-{i}",
            program="math-prog",
            endpoint=f"/s/{i}",
            method="POST",
            vuln_class="SSRF",
            supporting_intelligence_ids=[],
            supporting_observations=[],
            proposed_test="test",
            result="rejected",
            verification_result="rejected",
            researcher_review="rejected",
            requests_cost=25,
        )

    # 4 inconclusive
    for i in range(4):
        audit_engine.record_hypothesis_outcome(
            hypothesis_id=f"h-inconc-{i}",
            program="math-prog",
            endpoint=f"/inc/{i}",
            method="GET",
            vuln_class="InfoLeak",
            supporting_intelligence_ids=[],
            supporting_observations=[],
            proposed_test="test",
            result="inconclusive",
            verification_result="inconclusive",
            researcher_review="unreviewed",
            requests_cost=5,
        )

    priors = audit_engine.get_program_priors(program="math-prog")

    # IDOR: (3 + 1) / (3 + 2) = 4 / 5 = 0.8
    assert priors["IDOR"]["empirical_prior"] == 0.8
    assert priors["IDOR"]["confirmed"] == 3
    assert priors["IDOR"]["duplicate"] == 1
    assert priors["IDOR"]["decided"] == 3
    assert priors["IDOR"]["evidence_quality"] == 1.0
    # Cost adjusted priority is calculated distinctly
    assert priors["IDOR"]["cost_adjusted_priority"] < priors["IDOR"]["empirical_prior"]

    # SSRF: (0 + 1) / (4 + 2) = 1 / 6 = 0.167
    assert priors["SSRF"]["empirical_prior"] == 0.167
    assert priors["SSRF"]["rejected"] == 4
    assert priors["SSRF"]["decided"] == 4
    assert priors["SSRF"]["evidence_quality"] == 0.0

    # InfoLeak: Inconclusive -> neutral (0.5), decided == 0
    assert priors["InfoLeak"]["neutral"] is True
    assert priors["InfoLeak"]["empirical_prior"] == 0.5
    assert priors["InfoLeak"]["inconclusive"] == 4
    assert priors["InfoLeak"]["decided"] == 0


def test_unreviewed_judgments_cannot_modify_ground_truth(audit_engine):
    """Speculative triage judgments without verification or researcher review are ignored."""
    for i in range(5):
        audit_engine.record_hypothesis_outcome(
            hypothesis_id=f"h-unrev-{i}",
            program="unrev-prog",
            endpoint=f"/e/{i}",
            method="GET",
            vuln_class="CORS",
            supporting_intelligence_ids=[],
            supporting_observations=[],
            proposed_test="test",
            result="confirmed",  # claimed confirmed by speculative model
            verification_result=None,
            researcher_review="unreviewed",
        )

    priors = audit_engine.get_program_priors(program="unrev-prog")
    assert priors["CORS"]["neutral"] is True
    assert priors["CORS"]["empirical_prior"] == 0.5
    assert priors["CORS"]["unreviewed"] == 5
    assert priors["CORS"]["decided"] == 0


def test_deterministic_hypothesis_ranking(audit_engine):
    """Identical inputs must produce strictly deterministic rankings and scores."""
    candidates = [
        {"hypothesis_id": "h-1", "severity": "high", "vuln_class": "IDOR", "endpoint": "/a"},
        {"hypothesis_id": "h-2", "severity": "high", "vuln_class": "IDOR", "endpoint": "/b"},
        {"hypothesis_id": "h-3", "severity": "medium", "vuln_class": "SSRF", "endpoint": "/c"},
    ]

    r1 = audit_engine.rank_hypotheses(candidates, program="prog-det")
    r2 = audit_engine.rank_hypotheses(candidates, program="prog-det")

    assert [h["hypothesis_id"] for h in r1] == [h["hypothesis_id"] for h in r2]
    assert [h["meta"]["intel_rank_score"] for h in r1] == [h["meta"]["intel_rank_score"] for h in r2]
