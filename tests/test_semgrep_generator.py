"""Tests for Semgrep rule generation, validation, and registry."""
from __future__ import annotations

import pytest
import yaml

from bb.intel.semgrep_generator import SemgrepRuleGenerator
from bb.intel.rule_validation import RuleValidator
from bb.intel.rule_registry import RuleRegistry


def test_semgrep_generator_python_sqli():
    rule_yaml = SemgrepRuleGenerator.generate_python_sqli_rule("test-sqli-fstring")
    data = yaml.safe_load(rule_yaml)
    assert "rules" in data
    assert data["rules"][0]["id"] == "test-sqli-fstring"
    assert data["rules"][0]["metadata"]["cwe"] == "CWE-89"


def test_rule_validator_syntax():
    valid_yaml = SemgrepRuleGenerator.generate_python_sqli_rule()
    ok, err = RuleValidator.validate_syntax(valid_yaml)
    assert ok is True
    assert err is None

    # Invalid syntax
    bad_yaml = "invalid: [yaml: string"
    bad_ok, bad_err = RuleValidator.validate_syntax(bad_yaml)
    assert bad_ok is False
    assert bad_err is not None


def test_rule_fixture_testing():
    rule_yaml = SemgrepRuleGenerator.generate_python_sqli_rule()
    vuln_code = """
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    sec_code = """
def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
    res = RuleValidator.test_rule_against_fixtures(rule_yaml, vuln_code, sec_code)
    assert res["syntax_ok"] is True
    assert res["valid"] is True


def test_rule_registry_lifecycle():
    reg = RuleRegistry()
    draft = reg.register_draft("rule-1", "rules: []", "CWE-89")
    assert draft.status == "DRAFT"

    # Approve
    approved = reg.approve_rule("rule-1", reviewer="security-lead", notes="Verified no false positives")
    assert approved is not None
    assert approved.status == "APPROVED"
    assert approved.reviewer == "security-lead"
    assert len(reg.list_approved_rules()) == 1
