"""
Unit and integration tests for Phase 14 Startup Intelligence & Obscura Browser Integration.
"""
import pytest
import os
from unittest.mock import MagicMock, patch
from bb.startup_intel.models import (
    SourceAccessMode,
    HiringCategory,
    AIClassification,
    ResearchSaturation,
    JobListing,
    StartupProfile
)
from bb.startup_intel.browser_provider import ObscuraBrowserProvider
from bb.startup_intel.sources import (
    classify_role_category,
    YCombinatorConnector,
    HackerNewsConnector,
    WellfoundConnector,
    LinkedInConnector
)
from bb.startup_intel.engine import StartupIntelligenceEngine


def test_obscura_binary_installed():
    """Verify that Obscura v0.2.7 is downloaded and executable on Windows."""
    provider = ObscuraBrowserProvider()
    assert provider.is_available() is True
    version = provider.get_version()
    assert "obscura" in version.lower()


def test_role_category_classification():
    """Test classification of engineering hiring titles into normalized categories."""
    assert classify_role_category("Senior Application Security Engineer") == HiringCategory.SECURITY
    assert classify_role_category("Product Security Specialist") == HiringCategory.SECURITY
    assert classify_role_category("Staff Backend Engineer - APIs") == HiringCategory.BACKEND
    assert classify_role_category("Distributed Systems Core Engineer") == HiringCategory.BACKEND
    assert classify_role_category("DevOps / Cloud Platform Engineer") == HiringCategory.INFRASTRUCTURE
    assert classify_role_category("Site Reliability Engineer") == HiringCategory.INFRASTRUCTURE
    assert classify_role_category("LLM Alignment & Agent Engineer") == HiringCategory.AI_ML
    assert classify_role_category("Senior React Frontend Engineer") == HiringCategory.FRONTEND


def test_source_access_modes():
    """Verify compliance policies for external sources."""
    wf = WellfoundConnector()
    li = LinkedInConnector()
    assert wf.ACCESS_MODE == SourceAccessMode.RESEARCHER_ASSISTED
    assert li.ACCESS_MODE == SourceAccessMode.RESEARCHER_ASSISTED


def test_yc_startup_discovery():
    """Verify YC startup discovery returns valid profiles with hiring data."""
    yc = YCombinatorConnector()
    startups = yc.discover_recent_startups(top=5)
    assert len(startups) == 5
    first = startups[0]
    assert first.canonical_domain != ""
    assert first.is_currently_hiring is True
    assert len(first.job_listings) > 0


def test_hn_who_is_hiring_parser():
    """Test parsing of Hacker News Who is Hiring signals."""
    hn = HackerNewsConnector()
    # Mocking HN Algolia response
    sample_response = {
        "hits": [{"objectID": "12345", "title": "Ask HN: Who is hiring? (Nov 2026)"}]
    }
    sample_item = {
        "title": "Ask HN: Who is hiring? (Nov 2026)",
        "children": [
            {
                "id": 999,
                "text": "Acme SaaS | Senior AppSec Engineer | San Francisco, CA | Full-time<p>Building secure APIs",
                "created_at": "2026-11-01T12:00:00Z"
            }
        ]
    }
    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.read.side_effect = [
            b'{"hits": [{"objectID": "12345", "title": "Ask HN: Who is hiring?"}]}',
            b'{"title": "Ask HN", "children": [{"id": 999, "text": "Acme SaaS | Senior AppSec Engineer | Remote"}]}'
        ]
        mock_resp.__enter__.return_value = mock_resp
        mock_url.return_value = mock_resp

        jobs = hn.fetch_who_is_hiring_signals(limit=1)
        assert len(jobs) == 1
        assert jobs[0].company_name == "Acme SaaS"
        assert jobs[0].hiring_category == HiringCategory.SECURITY


def test_opportunity_scoring_and_saturation():
    """Test calculation of research saturation and 100-point opportunity score."""
    engine = StartupIntelligenceEngine()
    profile = StartupProfile(
        company_name="TestCorp",
        canonical_domain="testcorp.com",
        website="https://testcorp.com",
        yc_batch="W24",
        is_multi_tenant=True,
        has_apis=True,
        ai_classification=AIClassification.AI_PRODUCT,
        bounty_status="ACTIVE_MONETARY_BOUNTY",
        hexbrain_report_count=12
    )
    profile.hiring_categories = [HiringCategory.BACKEND, HiringCategory.SECURITY]
    profile.research_saturation = engine.calculate_research_saturation(profile)
    assert profile.research_saturation == ResearchSaturation.LOW

    score = engine.score_startup_opportunity(profile)
    assert 70.0 <= score <= 100.0
    assert profile.score_breakdown["authorized_bounty"] == 15.0


def test_unauthorized_startup_bounty_gate():
    """Verify that startups without authorized bounty program receive 0 pts for bounty gate."""
    engine = StartupIntelligenceEngine()
    profile = StartupProfile(
        company_name="NoBountyCo",
        canonical_domain="nobounty.com",
        website="https://nobounty.com",
        bounty_status="NO_ACTIVE_AUTHORIZED_PROGRAM"
    )
    score = engine.score_startup_opportunity(profile)
    assert profile.score_breakdown["authorized_bounty"] == 0.0
