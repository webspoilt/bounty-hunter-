"""Regression tests verifying ScopeWeaver-inspired asset normalization,
wildcard segregation, CIDR evaluation, exclusion precedence, and fingerprinting in bb.scope.
"""
import pytest

from bb.scope import Scope, ScopeWeaverNormalizer


def test_scopeweaver_wildcard_vs_apex():
    """Verify that wildcard *.example.com matches subdomains but does NOT authorize the apex domain."""
    norm = ScopeWeaverNormalizer.normalize_asset("*.example.com")
    assert norm["type"] == "WILDCARD"
    assert norm["wildcard"] is True
    assert norm["apex"] == "example.com"

    # Build Scope
    scope = ScopeWeaverNormalizer.build_scope(
        program="test-prog",
        in_scope=["*.example.com"],
        out_of_scope=[],
    )

    # Subdomain is permitted
    assert scope.is_in_scope("https://api.example.com/v1") is True
    assert scope.is_in_scope("https://sub.portal.example.com/dashboard") is True

    # Apex is NOT permitted unless explicitly listed
    assert scope.is_in_scope("https://example.com/") is False


def test_scopeweaver_apex_handling():
    """Verify that an apex domain matches only the apex, not subdomains."""
    scope = ScopeWeaverNormalizer.build_scope(
        program="test-prog",
        in_scope=["example.com"],
        out_of_scope=[],
    )
    assert scope.is_in_scope("https://example.com/login") is True
    assert scope.is_in_scope("https://api.example.com/login") is False


def test_scopeweaver_exclusion_precedence():
    """Verify that explicit out-of-scope rules strictly override wildcard in-scope rules."""
    scope = ScopeWeaverNormalizer.build_scope(
        program="test-prog",
        in_scope=["*.greenhouse.io"],
        out_of_scope=["community.greenhouse.io", "resources.greenhouse.io"],
    )
    # Permitted in-scope target
    assert scope.is_in_scope("https://app.greenhouse.io/") is True
    assert scope.is_in_scope("https://boards.greenhouse.io/") is True

    # Excluded targets are rejected
    assert scope.is_in_scope("https://community.greenhouse.io/") is False
    assert scope.is_in_scope("https://resources.greenhouse.io/") is False


def test_scopeweaver_cidr_handling():
    """Verify IPv4 CIDR matching."""
    norm = ScopeWeaverNormalizer.normalize_asset("10.50.0.0/16")
    assert norm["type"] == "CIDR"
    assert norm["valid"] is True

    scope = ScopeWeaverNormalizer.build_scope(
        program="test-prog",
        in_scope=["10.50.0.0/16"],
        out_of_scope=[],
    )
    assert scope.is_in_scope("http://10.50.1.25:8080/api") is True
    assert scope.is_in_scope("http://10.51.1.25:8080/api") is False


def test_scopeweaver_ipv4_and_ipv6():
    """Verify IP address normalization for loopback and public addresses."""
    norm_v4 = ScopeWeaverNormalizer.normalize_asset("127.0.0.1")
    assert norm_v4["type"] == "IP_ADDRESS"
    assert norm_v4["identifier"] == "127.0.0.1"

    norm_v6 = ScopeWeaverNormalizer.normalize_asset("::1")
    assert norm_v6["type"] == "IP_ADDRESS"
    assert norm_v6["identifier"] == "::1"


def test_scopeweaver_url_normalization():
    """Verify URL asset normalization decomposes scheme, host, port, and path prefix."""
    norm = ScopeWeaverNormalizer.normalize_asset("https://api.greenhouse.io:8443/harvest")
    assert norm["type"] == "URL"
    assert norm["host"] == "api.greenhouse.io"
    assert norm["port"] == 8443
    assert norm["path"] == "/harvest"


def test_scopeweaver_fingerprint_stability():
    """Verify SHA-256 fingerprint is stable across rule order."""
    scope1 = ScopeWeaverNormalizer.build_scope(
        program="test-prog",
        in_scope=["b.example.com", "a.example.com"],
        out_of_scope=["c.example.com"],
    )
    scope2 = ScopeWeaverNormalizer.build_scope(
        program="test-prog",
        in_scope=["a.example.com", "b.example.com"],
        out_of_scope=["c.example.com"],
    )
    assert scope1.fingerprint == scope2.fingerprint
    assert len(scope1.fingerprint) == 16


def test_scopeweaver_policy_change_invalidates_fingerprint():
    """Verify modifying in-scope or out-of-scope targets changes fingerprint digest."""
    scope1 = ScopeWeaverNormalizer.build_scope(
        program="test-prog",
        in_scope=["a.example.com"],
        out_of_scope=[],
    )
    scope2 = ScopeWeaverNormalizer.build_scope(
        program="test-prog",
        in_scope=["a.example.com", "b.example.com"],
        out_of_scope=[],
    )
    assert scope1.fingerprint != scope2.fingerprint
