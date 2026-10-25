import json

import pytest

from bb.scope import Scope, parse_rule, parse_target


def test_exact_and_wildcard(scope):
    assert scope.is_in_scope("https://app.example.com/login")
    assert scope.is_in_scope("https://deep.sub.example.com/x")
    assert not scope.is_in_scope("https://example.com/")      # apex not implied by *.
    assert not scope.is_in_scope("https://notexample.com/")
    assert not scope.is_in_scope("https://example.com.evil.dev/")


def test_out_of_scope_wins(scope):
    assert not scope.is_in_scope("https://staging.example.com/")
    assert not scope.is_in_scope("https://a.internal.example.com/")


def test_wildcard_does_not_match_lookalike(scope):
    assert not scope.is_in_scope("https://evilexample.com/")


def test_ip_and_cidr(scope):
    assert scope.is_in_scope("10.0.0.5")
    assert scope.is_in_scope("http://10.0.0.5:8080/x")
    assert not scope.is_in_scope("10.0.1.5")
    assert scope.is_in_scope("203.0.113.7")
    assert not scope.is_in_scope("203.0.113.8")


def test_deny_all_rule(scope):
    s = Scope.from_entries("p", ["*.example.com"], out_of_scope=["*"])
    assert not s.is_in_scope("https://app.example.com/")
    assert s.check("https://app.example.com/").allowed is False


def test_empty_scope_denies_everything():
    s = Scope.from_entries("p", [], [])
    assert not s.is_in_scope("https://anything.test/")


def test_malformed_targets(scope):
    for bad in ["", "javascript:alert(1)", "ftp://app.example.com/x",
                "http://app.example.com\\@evil.com/", "http://[::1]:3000/",
                "http://user:pass@app.example.com/"]:
        decision = scope.check(bad)
        assert not decision.allowed or bad.startswith("http://user:pass"), bad


def test_userinfo_cannot_spoof_host(scope):
    # host is evil.com, userinfo says example.com
    assert not scope.is_in_scope("http://app.example.com@evil.com/")


def test_port_rule():
    s = Scope.from_entries("p", ["api.example.com:8443"])
    assert s.is_in_scope("https://api.example.com:8443/x")
    assert not s.is_in_scope("https://api.example.com/x")
    assert not s.is_in_scope("https://api.example.com:9443/x")


def test_url_path_rule():
    s = Scope.from_entries("p", ["https://api.example.com/v2"])
    assert s.is_in_scope("https://api.example.com/v2/users")
    assert not s.is_in_scope("https://api.example.com/v3/users")
    assert not s.is_in_scope("https://other.example.com/v2/users")


def test_parse_target_forms():
    assert parse_target("https://app.example.com/x")[0] == "app.example.com"
    assert parse_target("app.example.com:8443/x")[1] == 8443
    assert parse_target("app.example.com/x")[2] == "/x"


def test_h1_structured_scope_mapping():
    s = Scope.from_h1_structured("acme", [
        {"asset_type": "WILDCARD", "asset_identifier": "*.acme.io",
         "eligible_for_submission": True, "eligible_for_bounty": True},
        {"asset_type": "DOMAIN", "asset_identifier": "acme.io",
         "eligible_for_submission": True},
        {"asset_type": "URL", "asset_identifier": "https://api.acme.io/v1",
         "eligible_for_submission": True},
        {"asset_type": "IP_ADDRESS", "asset_identifier": "198.51.100.9"},
        {"asset_type": "APPLE_STORE_APP_ID", "asset_identifier": "123456"},
        {"asset_type": "DOMAIN", "asset_identifier": "legacy.acme.io",
         "eligible_for_submission": False},
    ])
    assert s.is_in_scope("https://app.acme.io/")
    assert s.is_in_scope("https://acme.io/")
    assert s.is_in_scope("https://api.acme.io/v1/users")
    assert s.is_in_scope("198.51.100.9")
    assert not s.is_in_scope("https://legacy.acme.io/")
    assert not s.is_in_scope("https://apps.apple.com/x")
    assert any("APPLE_STORE_APP_ID" in w for w in s.warnings)


def test_scope_roundtrip(tmp_path):
    s = Scope.from_entries("acme", ["*.acme.io"], ["old.acme.io"])
    path = s.save(tmp_path / "scope.json")
    loaded = Scope.load(path)
    assert loaded.program == "acme"
    assert loaded.is_in_scope("https://x.acme.io/")
    assert not loaded.is_in_scope("https://old.acme.io/")
    assert loaded.fingerprint == s.fingerprint


def test_scope_load_accepts_utf8_bom(tmp_path):
    path = tmp_path / "scope.json"
    payload = json.dumps({"program": "p", "in_scope": ["lab.test"]}).encode()
    path.write_bytes(b"\xef\xbb\xbf" + payload)
    loaded = Scope.load(path)
    assert loaded.is_in_scope("https://lab.test/")


def test_rule_parsing_edge_cases():
    assert parse_rule("*.a.test").wildcard
    assert parse_rule("10.0.0.0/24").kind == "cidr"
    assert parse_rule("https://a.test/x*").path.startswith("/x")
    with pytest.raises(ValueError):
        parse_rule("ftp://a.test/x")
