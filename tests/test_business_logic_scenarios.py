"""Unit tests for the stateful business logic scenario engine."""
import pytest
from bb.scenarios import (
    InvariantOperator,
    InvariantSeverity,
    InvariantValidator,
    ScenarioDefinition,
    ScenarioRunner,
    ScenarioStep,
    ScenarioVerdict,
    SecurityInvariant,
    get_scenario,
    list_scenarios,
)


def test_validator_basic_operators():
    # EQUALS
    inv = SecurityInvariant(
        name="test_equals",
        description="status_code must be 200",
        field_path="status_code",
        operator=InvariantOperator.EQUALS,
        expected_value=200,
    )
    violated, _ = InvariantValidator.evaluate(inv, {"status_code": 200}, {})
    assert not violated

    violated, _ = InvariantValidator.evaluate(inv, {"status_code": 400}, {})
    assert violated

    # NOT_EQUALS
    inv_ne = SecurityInvariant(
        name="test_ne",
        description="role must not be admin",
        field_path="body.role",
        operator=InvariantOperator.NOT_EQUALS,
        expected_value="admin",
    )
    violated, _ = InvariantValidator.evaluate(inv_ne, {"body": {"role": "admin"}}, {})
    assert violated

    violated, _ = InvariantValidator.evaluate(inv_ne, {"body": {"role": "customer"}}, {})
    assert not violated


def test_validator_numeric_bounds():
    inv_gt = SecurityInvariant(
        name="test_gt",
        description="qty > 0",
        field_path="body.quantity",
        operator=InvariantOperator.GREATER_THAN,
        expected_value=0,
    )
    assert not InvariantValidator.evaluate(inv_gt, {"body": {"quantity": 5}}, {})[0]
    assert InvariantValidator.evaluate(inv_gt, {"body": {"quantity": -1}}, {})[0]


def test_scenario_library_loading():
    scenarios = list_scenarios()
    assert len(scenarios) >= 5

    sc = get_scenario("BL-COUPON-01")
    assert sc.id == "BL-COUPON-01"
    assert len(sc.steps) == 2


def test_live_coupon_scenario_reproduction():
    runner = ScenarioRunner(base_url="http://127.0.0.1:8000")
    sc = get_scenario("BL-COUPON-01")

    # 1. Run against vulnerable endpoint
    res_vuln = runner.execute_scenario(sc, target_mode="vulnerable")
    assert res_vuln.verdict == ScenarioVerdict.VULNERABLE
    assert len(res_vuln.violations) > 0

    # 2. Run against secure reference endpoint
    res_sec = runner.execute_scenario(sc, target_mode="secure")
    assert res_sec.verdict == ScenarioVerdict.ENFORCED
    assert len(res_sec.violations) == 0


def test_live_all_scenarios_differentiation():
    runner = ScenarioRunner(base_url="http://127.0.0.1:8000")
    for sc in list_scenarios():
        res_v = runner.execute_scenario(sc, target_mode="vulnerable")
        assert res_v.verdict == ScenarioVerdict.VULNERABLE, f"Failed on {sc.id} vuln"

        res_s = runner.execute_scenario(sc, target_mode="secure")
        assert res_s.verdict == ScenarioVerdict.ENFORCED, f"Failed on {sc.id} secure"
