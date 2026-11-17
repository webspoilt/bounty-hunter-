"""Regression and unit tests for HackerOne program target approval workflow.

Validates:
1. `now_iso()` generates valid UTC ISO-8601 timestamps.
2. `ProgramAuthorizationBrief.from_dict` deserializes without `TypeError` when extra brief keys are present.
3. Approval requires concrete target.
4. Approval verifies target against scope and rejects out-of-scope targets.
5. Approval rejects stale scope fingerprints.
6. Approval rejects unresolved scope conflicts.
7. Approval rejects excluded paths.
8. Approval rejects ineligible/unknown submission assets.
9. Successful approval persists approved metadata and generates research profile.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bb.config import now_iso
from bb.h1 import (
    AssetEligibility,
    H1_BRIEFS_DIR,
    H1_PROGRAMS_DIR,
    ProgramAuthorizationBrief,
    ProgramVisibility,
)
from bb.scope import Scope


def test_now_iso_generates_valid_utc_timestamp():
    """Verify now_iso produces a valid ISO-8601 parseable timestamp with timezone."""
    ts = now_iso()
    assert isinstance(ts, str)
    dt = datetime.fromisoformat(ts)
    assert dt.tzinfo is not None


def test_brief_from_dict_handles_extra_fields():
    """Regression test: ProgramAuthorizationBrief.from_dict must safely ignore extra fields."""
    sample_data = {
        "handle": "testprog",
        "program_name": "Test Program",
        "offers_bounties": True,
        "policy_hash": "a1b2c3d4",
        "retrieved_at": now_iso(),
        "in_scope_assets": ["testprog.com"],
        "out_of_scope_assets": ["internal.testprog.com"],
        "scope_exclusions": [],
        "testing_restrictions": [],
        "rate_limit": 1.0,
        # Extra fields present in real brief files:
        "path_exclusions": ["/web-security"],
        "scope_conflicts": [{"asset": "sub.testprog.com", "issue": "forbidden"}],
        "rate_limit_source": "program_policy",
        "human_review_notes": ["Note 1"],
        "custom_extra_key_42": "should_not_crash",
    }
    brief = ProgramAuthorizationBrief.from_dict(sample_data)
    assert brief.handle == "testprog"
    assert brief.rate_limit == 1.0
    assert brief.offers_bounties is True
    assert brief.policy_hash == "a1b2c3d4"


def test_approval_rejects_missing_target(capsys):
    """Verify approval command rejects missing or empty target."""
    from bb.cli import cmd_h1

    args = argparse.Namespace(action="approve", program="testprog", target="")
    res = cmd_h1(args)
    assert res == 1
    out = capsys.readouterr().out
    assert "Concrete in-scope target is mandatory" in out


def test_approval_rejects_missing_brief(tmp_path, capsys):
    """Verify approval command fails if brief has not been generated."""
    from bb.cli import cmd_h1

    with patch("bb.h1.H1_BRIEFS_DIR", tmp_path):
        args = argparse.Namespace(action="approve", program="nonexistent", target="https://target.com")
        res = cmd_h1(args)
        assert res == 1
        out = capsys.readouterr().out
        assert "Brief not found" in out


def test_approval_rejects_out_of_scope_target(tmp_path, capsys):
    """Verify approval rejects target not permitted by the program's scope."""
    from bb.cli import cmd_h1

    brief_file = tmp_path / "testprog_brief.json"
    brief_data = {
        "handle": "testprog",
        "program_name": "Test Program",
        "offers_bounties": True,
        "policy_hash": "abc",
        "retrieved_at": now_iso(),
        "in_scope_assets": ["allowed.testprog.com"],
        "out_of_scope_assets": [],
        "scope_exclusions": [],
        "testing_restrictions": [],
        "rate_limit": 1.0,
    }
    brief_file.write_text(json.dumps(brief_data), encoding="utf-8")

    fake_scope = Scope.from_entries(
        program="testprog",
        in_scope=["allowed.testprog.com"],
        out_of_scope=[],
    )

    with patch("bb.h1.H1_BRIEFS_DIR", tmp_path), \
         patch("bb.cli.H1Client") as mock_client:
        mock_client.return_value.scope.return_value = fake_scope
        args = argparse.Namespace(action="approve", program="testprog", target="https://evil.notallowed.com")
        res = cmd_h1(args)
        assert res == 1
        out = capsys.readouterr().out
        assert "is NOT in-scope" in out


def test_approval_rejects_stale_scope_fingerprint(tmp_path, capsys):
    """Verify approval rejects if brief was generated against a different scope fingerprint."""
    from bb.cli import cmd_h1

    brief_file = tmp_path / "testprog_brief.json"
    brief_data = {
        "handle": "testprog",
        "program_name": "Test Program",
        "offers_bounties": True,
        "policy_hash": "abc",
        "scope_fingerprint": "old_fingerprint_1111",
        "retrieved_at": now_iso(),
        "in_scope_assets": ["testprog.com"],
        "out_of_scope_assets": [],
        "scope_exclusions": [],
        "testing_restrictions": [],
        "rate_limit": 1.0,
    }
    brief_file.write_text(json.dumps(brief_data), encoding="utf-8")

    fake_scope = Scope.from_entries(
        program="testprog",
        in_scope=["testprog.com"],
        out_of_scope=[],
    )

    with patch("bb.h1.H1_BRIEFS_DIR", tmp_path), \
         patch("bb.cli.H1Client") as mock_client:
        mock_client.return_value.scope.return_value = fake_scope
        args = argparse.Namespace(action="approve", program="testprog", target="https://testprog.com")
        res = cmd_h1(args)
        assert res == 1
        out = capsys.readouterr().out
        assert "Scope fingerprint mismatch" in out


def test_approval_rejects_scope_conflicts(tmp_path, capsys):
    """Verify approval rejects target if it is recorded in unresolved scope conflicts."""
    from bb.cli import cmd_h1

    fake_scope = Scope.from_entries(
        program="testprog",
        in_scope=["*.testprog.net"],
        out_of_scope=[],
    )

    brief_file = tmp_path / "testprog_brief.json"
    brief_data = {
        "handle": "testprog",
        "program_name": "Test Program",
        "offers_bounties": True,
        "policy_hash": "abc",
        "scope_fingerprint": fake_scope.fingerprint,
        "retrieved_at": now_iso(),
        "in_scope_assets": ["*.testprog.net"],
        "out_of_scope_assets": [],
        "scope_exclusions": [],
        "testing_restrictions": [],
        "scope_conflicts": [{"asset": "ai.testprog.net", "issue": "Prohibited by policy text"}],
        "rate_limit": 1.0,
    }
    brief_file.write_text(json.dumps(brief_data), encoding="utf-8")

    with patch("bb.h1.H1_BRIEFS_DIR", tmp_path), \
         patch("bb.cli.H1Client") as mock_client:
        mock_client.return_value.scope.return_value = fake_scope
        args = argparse.Namespace(action="approve", program="testprog", target="https://ai.testprog.net/chat")
        res = cmd_h1(args)
        assert res == 1
        out = capsys.readouterr().out
        assert "unresolved scope conflict" in out


def test_approval_rejects_path_exclusions(tmp_path, capsys):
    """Verify approval rejects target if path matches excluded subpaths."""
    from bb.cli import cmd_h1

    fake_scope = Scope.from_entries(
        program="testprog",
        in_scope=["testprog.net"],
        out_of_scope=[],
    )

    brief_file = tmp_path / "testprog_brief.json"
    brief_data = {
        "handle": "testprog",
        "program_name": "Test Program",
        "offers_bounties": True,
        "policy_hash": "abc",
        "scope_fingerprint": fake_scope.fingerprint,
        "retrieved_at": now_iso(),
        "in_scope_assets": ["testprog.net"],
        "out_of_scope_assets": [],
        "scope_exclusions": [],
        "testing_restrictions": [],
        "path_exclusions": ["/web-security"],
        "rate_limit": 1.0,
    }
    brief_file.write_text(json.dumps(brief_data), encoding="utf-8")

    with patch("bb.h1.H1_BRIEFS_DIR", tmp_path), \
         patch("bb.cli.H1Client") as mock_client:
        mock_client.return_value.scope.return_value = fake_scope
        args = argparse.Namespace(action="approve", program="testprog", target="https://testprog.net/web-security/learning-path")
        res = cmd_h1(args)
        assert res == 1
        out = capsys.readouterr().out
        assert "matches excluded path '/web-security'" in out


def test_approval_rejects_ineligible_asset(tmp_path, capsys):
    """Verify approval rejects target if asset is explicitly marked INELIGIBLE."""
    from bb.cli import cmd_h1

    fake_scope = Scope.from_entries(
        program="testprog",
        in_scope=["testprog.net"],
        out_of_scope=[],
    )

    brief_file = tmp_path / "testprog_brief.json"
    brief_data = {
        "handle": "testprog",
        "program_name": "Test Program",
        "offers_bounties": True,
        "policy_hash": "abc",
        "scope_fingerprint": fake_scope.fingerprint,
        "retrieved_at": now_iso(),
        "in_scope_assets": ["testprog.net"],
        "out_of_scope_assets": [],
        "scope_exclusions": [],
        "testing_restrictions": [],
        "structured_asset_entries": [
            {"identifier": "testprog.net", "eligible_for_submission": "ineligible"}
        ],
        "rate_limit": 1.0,
    }
    brief_file.write_text(json.dumps(brief_data), encoding="utf-8")

    with patch("bb.h1.H1_BRIEFS_DIR", tmp_path), \
         patch("bb.cli.H1Client") as mock_client:
        mock_client.return_value.scope.return_value = fake_scope
        args = argparse.Namespace(action="approve", program="testprog", target="https://testprog.net")
        res = cmd_h1(args)
        assert res == 1
        out = capsys.readouterr().out
        assert "explicitly marked INELIGIBLE" in out


def test_successful_approval_workflow(tmp_path, monkeypatch, capsys):
    """Verify successful approval writes APPROVED status, approved_at, and saves scope."""
    from bb.cli import cmd_h1

    briefs_dir = tmp_path / "briefs"
    briefs_dir.mkdir()
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir()
    scopes_dir = tmp_path / "scopes"
    scopes_dir.mkdir()

    fake_scope = Scope.from_entries(
        program="testprog",
        in_scope=["testprog.com"],
        out_of_scope=[],
    )

    brief_file = briefs_dir / "testprog_brief.json"
    brief_data = {
        "handle": "testprog",
        "program_name": "Test Program",
        "offers_bounties": True,
        "policy_hash": "hash_12345",
        "scope_fingerprint": fake_scope.fingerprint,
        "retrieved_at": now_iso(),
        "in_scope_assets": ["testprog.com"],
        "out_of_scope_assets": [],
        "scope_exclusions": [],
        "testing_restrictions": [],
        "rate_limit": 2.0,
        "structured_asset_entries": [
            {"identifier": "testprog.com", "eligible_for_submission": "eligible"}
        ],
    }
    brief_file.write_text(json.dumps(brief_data), encoding="utf-8")

    monkeypatch.setenv("USERNAME", "audit_tester")

    with patch("bb.h1.H1_BRIEFS_DIR", briefs_dir), \
         patch("bb.h1.H1_PROGRAMS_DIR", programs_dir), \
         patch("bb.cli.scope_path", lambda p: scopes_dir / f"{p}.json"), \
         patch("bb.cli.H1Client") as mock_client:
        mock_client.return_value.scope.return_value = fake_scope
        args = argparse.Namespace(action="approve", program="testprog", target="https://testprog.com/api")
        res = cmd_h1(args)
        assert res == 0

        # Verify saved brief
        saved_data = json.loads(brief_file.read_text(encoding="utf-8"))
        assert saved_data["approval_status"] == "APPROVED"
        assert saved_data["approved_by"] == "audit_tester"
        assert saved_data["approved_target"] == "https://testprog.com/api"
        assert saved_data["approved_policy_hash"] == "hash_12345"
        assert saved_data["approved_scope_fingerprint"] == fake_scope.fingerprint
        assert datetime.fromisoformat(saved_data["approved_at"]) is not None

        # Verify program profile created
        profile_file = programs_dir / "testprog_profile.json"
        assert profile_file.exists()

        out = capsys.readouterr().out
        assert "APPROVED for investigation" in out
        assert "verified and authorized for testing" in out


def test_approved_apex_target_cannot_authorize_excluded_path_or_disputed_subdomains(tmp_path, capsys):
    """Verify that an approved apex target cannot authorize /web-security, disputed subdomains, or unrelated hosts."""
    from bb.cli import cmd_h1
    from bb.scope import parse_rule

    briefs_dir = tmp_path / "briefs"
    briefs_dir.mkdir()
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir()
    scopes_dir = tmp_path / "scopes"
    scopes_dir.mkdir()

    disputed_hosts = [
        "ai.portswigger.net",
        "collections.portswigger.net",
        "share.portswigger.net",
        "links.portswigger.net",
        "id.portswigger.net",
    ]
    fake_scope = Scope.from_entries(
        program="portswigger",
        in_scope=["portswigger.net", *disputed_hosts],
        out_of_scope=[
            "*.web-security-academy.net",
            "*.portswigger.net",
        ],
    )

    brief_file = briefs_dir / "portswigger_brief.json"
    brief_data = {
        "handle": "portswigger",
        "program_name": "PortSwigger Web Security",
        "offers_bounties": True,
        "policy_hash": "hash_pw_123",
        "scope_fingerprint": fake_scope.fingerprint,
        "retrieved_at": now_iso(),
        "in_scope_assets": ["portswigger.net", *disputed_hosts],
        "out_of_scope_assets": ["*.web-security-academy.net", "*.portswigger.net"],
        "path_exclusions": ["https://portswigger.net/web-security"],
        "scope_conflicts": [
            {
                "asset": host,
                "issue": "Prohibited by policy text",
            }
            for host in disputed_hosts
        ],
        "testing_restrictions": [],
        "rate_limit": 1.0,
        "structured_asset_entries": [
            {"identifier": "portswigger.net", "eligible_for_submission": "eligible"},
            *[{"identifier": host, "eligible_for_submission": "eligible"} for host in disputed_hosts],
        ],
    }
    brief_file.write_text(json.dumps(brief_data), encoding="utf-8")

    with patch("bb.h1.H1_BRIEFS_DIR", briefs_dir), \
         patch("bb.h1.H1_PROGRAMS_DIR", programs_dir), \
         patch("bb.cli.scope_path", lambda p: scopes_dir / f"{p}.json"), \
         patch("bb.cli.H1Client") as mock_client:
        mock_client.return_value.scope.return_value = fake_scope

        # 1. Approval of apex domain succeeds
        args_apex = argparse.Namespace(action="approve", program="portswigger", target="https://portswigger.net")
        res = cmd_h1(args_apex)
        assert res == 0

        # Load saved scope
        saved_scope = Scope.load(scopes_dir / "portswigger.json")

        # 2. Apex is permitted
        assert saved_scope.is_in_scope("https://portswigger.net") is True
        assert saved_scope.is_in_scope("https://portswigger.net/burp") is True

        # 3. /web-security is strictly BLOCKED by path exclusion
        assert saved_scope.is_in_scope("https://portswigger.net/web-security") is False
        assert saved_scope.is_in_scope("https://portswigger.net/web-security/learning-path") is False

        # 4. Disputed subdomains are strictly BLOCKED
        for host in disputed_hosts:
            assert saved_scope.is_in_scope(f"https://{host}") is False
        assert saved_scope.is_in_scope("https://other.portswigger.net") is False

        # 5. Unrelated hosts are strictly BLOCKED
        assert saved_scope.is_in_scope("https://google.com") is False
        assert saved_scope.is_in_scope("https://evil-attacker.com") is False

        # 6. Direct approval attempt for /web-security path must be rejected by approval gate
        args_path = argparse.Namespace(action="approve", program="portswigger", target="https://portswigger.net/web-security")
        res_path = cmd_h1(args_path)
        assert res_path == 1

        # 7. Direct approval attempt for disputed subdomain must be rejected by approval gate
        for host in disputed_hosts:
            args_sub = argparse.Namespace(action="approve", program="portswigger", target=f"https://{host}")
            res_sub = cmd_h1(args_sub)
            assert res_sub == 1


def test_def03_finding_program_mapping_and_run_id_integrity(tmp_path):
    """Verify DEF-03: Finding correctly preserves program in meta and maintains valid run_id relationships."""
    from bb.models import Finding
    from bb.store import Store

    db_path = tmp_path / "test_store.db"
    store = Store(db_path)

    # Case 1: save_finding with program name does not corrupt run_id in findings table
    finding1 = Finding(title="Test Finding 1", bug_class="idor", severity="high")
    f_id1 = store.save_finding("portswigger", finding1)
    assert finding1.meta.get("program") == "portswigger"
    saved1 = store.get_finding(f_id1)
    assert saved1 is not None
    assert saved1.meta.get("program") == "portswigger"
    # findings.run_id should be None (not the string "portswigger" which has no corresponding run)
    assert store.finding_run(f_id1) is None

    # Case 2: save_finding with a real run_id preserves both the run association and meta
    real_run_id = store.start_run(program="portswigger", target="https://portswigger.net")
    finding2 = Finding(title="Test Finding 2", bug_class="sqli", severity="critical")
    f_id2 = store.save_finding(real_run_id, finding2)
    assert store.finding_run(f_id2) == real_run_id
    run_record = store.run(real_run_id)
    assert run_record is not None
    assert run_record["program"] == "portswigger"


def test_def06_authz_run_fails_fast_on_missing_accounts(tmp_path, capsys):
    """Verify DEF-06: bb authz run fails fast when account configuration is missing."""
    from bb.cli import cmd_authz

    fake_scope = Scope.from_entries(program="testprog", in_scope=["testprog.com"])
    missing_accounts_file = tmp_path / "missing_accounts.json"

    with patch("bb.cli._scope_or_die", return_value=fake_scope), \
         patch("bb.cli._require_not_stopped"):
        args = argparse.Namespace(
            action="run",
            program="testprog",
            accounts=str(missing_accounts_file),
            har="test.har",
            rate=1.0,
            max_requests=10,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_authz(args)
        assert "Missing account configuration" in str(exc_info.value)


