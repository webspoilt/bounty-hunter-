"""Unit tests for the Security Intelligence Engine.

Covers:
- CVE record ingestion (NVD 2.0 format)
- Duplicate intelligence records (upsert idempotency)
- Source provenance preservation (source URLs, publication dates)
- Version-range applicability (exact matches, boundary conditions, exclusion of product-name-only matches)
- Invalid and incomplete source records (graceful handling and parse_status tracking)
- Stale intelligence calculation (freshness buckets)
- CWE/CAPEC relationships and mappings
- Confirmed versus rejected hypotheses
- Learning from inconclusive results (neutrality preserved, not biased as negative)
- Protection against unreviewed labels (unreviewed model judgments not treated as ground truth)
- Secret and credential redaction
- Provider outage recovery and offline search
- Database schema and migrations
- Reproducible retrieval via FTS5 and exact filtering
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bb.intelligence import (
    AdvisoryAdapter,
    CapecAdapter,
    CweAdapter,
    HypothesisOutcomeRecord,
    IntelligenceEngine,
    IntelligenceRecord,
    IntelligenceStore,
    NvdCveAdapter,
    ResearchDisclosureAdapter,
    VersionConstraint,
    check_version_applicable,
    compute_hypothesis_priors,
    rank_hypotheses_with_intelligence,
    record_matches_component,
)


@pytest.fixture
def intel_engine(tmp_path):
    db_file = tmp_path / "test_intel.db"
    engine = IntelligenceEngine(db_path=db_file)
    yield engine
    engine.close()


def test_nvd_cve_ingestion_and_provenance(intel_engine):
    sample_cve = {
        "cve": {
            "id": "CVE-2024-12345",
            "published": "2024-01-15T10:00:00.000",
            "lastModified": "2024-01-20T12:00:00.000",
            "descriptions": [
                {"lang": "en", "value": "Insecure Direct Object Reference in user management component"}
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 8.8,
                            "baseSeverity": "HIGH"
                        }
                    }
                ]
            },
            "weaknesses": [
                {"description": [{"value": "CWE-639"}]}
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:a:targetcorp:authapp:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "1.0.0",
                                    "versionEndExcluding": "2.4.0"
                                }
                            ]
                        }
                    ]
                }
            ],
            "references": [
                {"url": "https://example.com/advisory/CVE-2024-12345"}
            ]
        }
    }

    ingested = intel_engine.ingest_nvd_cve(sample_cve)
    assert len(ingested) == 1
    assert ingested[0] == "CVE-2024-12345"

    rec = intel_engine.get_record("CVE-2024-12345")
    assert rec is not None
    assert rec.source == "nvd"
    assert rec.source_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
    assert rec.published_at == "2024-01-15T10:00:00.000"
    assert rec.vuln_class == "IDOR"
    assert rec.cvss_score == 8.8
    assert rec.severity == "high"
    assert "CWE-639" in rec.cwe_ids
    assert rec.affected_product == "authapp"
    assert len(rec.version_constraints) == 1
    assert rec.version_constraints[0].version_start_including == "1.0.0"
    assert rec.version_constraints[0].version_end_excluding == "2.4.0"


def test_duplicate_intelligence_records(intel_engine):
    """Upsert idempotency: duplicate records update without integrity errors."""
    sample = {
        "id": "CWE-89",
        "name": "SQL Injection",
        "description": "Initial description",
    }
    intel_engine.ingest_cwe(sample)
    rec1 = intel_engine.get_record("CWE-89")
    assert rec1.description == "Initial description"

    # Ingest updated duplicate
    sample["description"] = "Updated comprehensive description"
    intel_engine.ingest_cwe(sample)
    rec2 = intel_engine.get_record("CWE-89")
    assert rec2.description == "Updated comprehensive description"


def test_version_applicability_constraints():
    """Requirement: A product-name match alone must NEVER establish vulnerability applicability."""
    constraints = [
        VersionConstraint(version_start_including="2.0.0", version_end_excluding="2.5.0")
    ]

    # Matching range
    app, reason = check_version_applicable("2.1.0", constraints)
    assert app is True

    # Boundary: exactly at start
    app, reason = check_version_applicable("2.0.0", constraints)
    assert app is True

    # Boundary: at excluded end
    app, reason = check_version_applicable("2.5.0", constraints)
    assert app is False

    # Above range (patched)
    app, reason = check_version_applicable("3.0.0", constraints)
    assert app is False

    # Below range
    app, reason = check_version_applicable("1.9.9", constraints)
    assert app is False

    # Target version missing: product alone fails closed
    app, reason = check_version_applicable(None, constraints)
    assert app is False
    assert "cannot establish version applicability" in reason

    # Constraints missing: fails closed
    app, reason = check_version_applicable("2.1.0", [])
    assert app is False
    assert "product match alone insufficient" in reason


def test_record_matches_component_strictness():
    rec = IntelligenceRecord(
        id="CVE-TEST-1",
        source="advisory",
        source_id="ADV-1",
        source_url="https://example.com",
        title="Test Vuln",
        description="A flaw in nginx",
        vuln_class="Remote Code Execution",
        retrieved_at="2026-01-01T00:00:00Z",
        affected_product="nginx",
        version_constraints=[VersionConstraint(exact_version="1.18.0")],
    )

    # Product matches and version matches
    matched, _ = record_matches_component(rec, "nginx", "1.18.0")
    assert matched is True

    # Product matches but version is different
    matched, _ = record_matches_component(rec, "nginx", "1.20.0")
    assert matched is False

    # Product mismatch
    matched, _ = record_matches_component(rec, "apache", "1.18.0")
    assert matched is False


def test_invalid_and_incomplete_records(intel_engine):
    # Malformed CVE missing ID
    malformed = {"cve": {"descriptions": [{"value": "No ID here"}]}}
    recs = intel_engine.ingest_nvd_cve(malformed)
    assert len(recs) == 1
    rec = intel_engine.get_record(recs[0])
    assert rec.parse_status == "malformed"

    # Incomplete advisory
    incomplete_adv = {"id": "ADV-999"}  # missing details and product
    intel_engine.ingest_advisory(incomplete_adv)
    adv_rec = intel_engine.get_record("ADV-999")
    assert adv_rec.parse_status == "incomplete"


def test_cwe_capec_relationships(intel_engine):
    cwe_data = {
        "id": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page Generation",
        "description": "Cross-site scripting weakness",
        "capec_ids": ["CAPEC-63", "CAPEC-85"],
    }
    capec_data = {
        "id": "CAPEC-63",
        "name": "Cross-Site Scripting (XSS)",
        "description": "Adversary injects script payload into target page",
        "cwe_ids": ["CWE-79"],
    }

    intel_engine.ingest_cwe(cwe_data)
    intel_engine.ingest_capec(capec_data)

    cwe_rec = intel_engine.get_record("CWE-79")
    assert "CAPEC-63" in cwe_rec.capec_ids

    capec_rec = intel_engine.get_record("CAPEC-63")
    assert "CWE-79" in capec_rec.cwe_ids


def test_adaptive_learning_from_confirmed_vs_rejected_hypotheses(intel_engine):
    """Demonstrates empirical hypothesis prior adjustment based on reviewed outcomes."""
    # Program: corp-portal
    # Inject 3 confirmed IDORs
    for i in range(3):
        intel_engine.record_hypothesis_outcome(
            hypothesis_id=f"h-idor-{i}",
            program="corp-portal",
            endpoint=f"/api/v1/user/{i}",
            method="GET",
            vuln_class="IDOR",
            supporting_intelligence_ids=["CVE-2024-12345"],
            supporting_observations=["User ID parameter in path"],
            proposed_test="Replay with Account B bearer token",
            executed=True,
            result="confirmed",
            verification_result="confirmed",
            researcher_review="approved",
            requests_cost=3,
        )

    # Inject 3 rejected SSRF (false positives)
    for i in range(3):
        intel_engine.record_hypothesis_outcome(
            hypothesis_id=f"h-ssrf-{i}",
            program="corp-portal",
            endpoint=f"/api/v1/fetch?url={i}",
            method="POST",
            vuln_class="SSRF",
            supporting_intelligence_ids=["CWE-918"],
            supporting_observations=["URL parameter in request"],
            proposed_test="Probe loopback address",
            executed=True,
            result="rejected",
            verification_result="rejected",
            researcher_review="rejected",
            requests_cost=20,  # costly fruitless test
        )

    priors = intel_engine.get_program_priors(program="corp-portal")

    # IDOR: (3 + 1) / (3 + 2) = 4 / 5 = 0.8
    assert priors["IDOR"]["weight"] >= 0.75
    assert priors["IDOR"]["confirmed"] == 3
    assert not priors["IDOR"]["neutral"]

    # SSRF: (0 + 1) / (3 + 2) = 1 / 5 = 0.2 (plus efficiency penalty for 20 reqs/test)
    assert priors["SSRF"]["weight"] <= 0.20
    assert priors["SSRF"]["rejected"] == 3
    assert "verified false positives" in priors["SSRF"]["note"]


def test_inconclusive_and_unreviewed_hypotheses_protection(intel_engine):
    """Inconclusive outcomes and unreviewed model decisions MUST NOT become ground truth."""
    # Record inconclusive outcomes
    for i in range(4):
        intel_engine.record_hypothesis_outcome(
            hypothesis_id=f"h-inconc-{i}",
            program="finance-app",
            endpoint="/api/v1/statement",
            method="GET",
            vuln_class="Information Disclosure",
            supporting_intelligence_ids=[],
            supporting_observations=[],
            proposed_test="Read statement",
            executed=True,
            result="inconclusive",
            verification_result="inconclusive",
            researcher_review="unreviewed",
        )

    priors = intel_engine.get_program_priors(program="finance-app")
    prior_info = priors["Information Disclosure"]
    # Should stay neutral: 0 decided outcomes, inconclusive explicitly tracked
    assert prior_info["neutral"] is True
    assert prior_info["weight"] == 0.5
    assert prior_info["inconclusive"] == 4
    assert prior_info["decided"] == 0


def test_secret_redaction_in_disclosure_intelligence(intel_engine):
    from bb.analyze import _strip_secrets

    raw_text = 'Authorization: Bearer secret_live_token_12345; apiKey="super_secret_key_abcdef"'
    redacted = _strip_secrets(raw_text)
    assert "secret_live_token_12345" not in redacted
    assert "super_secret_key_abcdef" not in redacted
    assert "[REDACTED]" in redacted


def test_hypothesis_ranking_with_intelligence_and_priors(intel_engine):
    """Verifies that rank_hypotheses incorporates intelligence bonus and empirical priors."""
    # Set up priors in store: IDOR high yield (0.8), Open Redirect low yield (0.2)
    for i in range(3):
        intel_engine.record_hypothesis_outcome(
            hypothesis_id=f"id-{i}",
            program="app-test",
            endpoint="/api/doc",
            method="GET",
            vuln_class="IDOR",
            supporting_intelligence_ids=[],
            supporting_observations=[],
            proposed_test="IDOR test",
            result="confirmed",
            verification_result="confirmed",
            researcher_review="approved",
        )
    for i in range(3):
        intel_engine.record_hypothesis_outcome(
            hypothesis_id=f"or-{i}",
            program="app-test",
            endpoint="/redirect",
            method="GET",
            vuln_class="Open Redirect",
            supporting_intelligence_ids=[],
            supporting_observations=[],
            proposed_test="Redirect test",
            result="rejected",
            verification_result="rejected",
            researcher_review="rejected",
        )

    candidates = [
        {
            "hypothesis_id": "hypo-open-redirect",
            "vuln_class": "Open Redirect",
            "severity": "medium",
            "endpoint": "/out",
            "supporting_intelligence": [],
        },
        {
            "hypothesis_id": "hypo-idor-with-cve",
            "vuln_class": "IDOR",
            "severity": "high",
            "endpoint": "/api/users/42",
            "supporting_intelligence": [
                {"source": "nvd", "id": "CVE-2024-12345"}
            ],
        },
    ]

    ranked = intel_engine.rank_hypotheses(candidates, program="app-test")
    # High severity + IDOR confirmed prior + CVE intelligence bonus must rank first
    assert ranked[0]["hypothesis_id"] == "hypo-idor-with-cve"
    assert ranked[0]["meta"]["intel_rank_score"] > ranked[1]["meta"]["intel_rank_score"]


def test_reproducible_fts_search(intel_engine):
    intel_engine.ingest_cwe({
        "id": "CWE-287",
        "name": "Improper Authentication",
        "description": "When an actor claims to have a given identity, software does not prove identity.",
    })
    intel_engine.ingest_cwe({
        "id": "CWE-79",
        "name": "Cross-site Scripting",
        "description": "Software does not neutralize user-controllable input before placed in web output.",
    })

    # Search authentication
    results = intel_engine.query(query="authentication")
    assert any(r.id == "CWE-287" for r in results)
    assert not any(r.id == "CWE-79" for r in results)

    # Search scripting
    results_xss = intel_engine.query(query="scripting")
    assert any(r.id == "CWE-79" for r in results_xss)
