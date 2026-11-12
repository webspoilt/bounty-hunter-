"""Comprehensive repository of stateful business-logic scenarios."""
from __future__ import annotations

from typing import Dict, List
from bb.scenarios.models import (
    InvariantOperator,
    InvariantSeverity,
    ScenarioDefinition,
    ScenarioStep,
    SecurityInvariant,
)

SCENARIOS: Dict[str, ScenarioDefinition] = {
    # =========================================================================
    # A. COUPON AND DISCOUNT ABUSE
    # =========================================================================
    "BL-COUPON-01": ScenarioDefinition(
        id="BL-COUPON-01",
        title="Repeated Coupon Application & Unlimited Reuse",
        description="Tests whether a one-time promotional discount code (WELCOME10) can be applied multiple times in the same session without exhaustion.",
        category="coupon_abuse",
        cwe="CWE-840",
        owasp_category="A06:2025 - Insecure Design",
        severity=InvariantSeverity.HIGH,
        required_roles=["alice"],
        steps=[
            ScenarioStep(
                name="apply_coupon_first_time",
                method="POST",
                path="/cart/apply-coupon",
                role="alice",
                body={"code": "WELCOME10"},
                expected_status=[200],
            ),
            ScenarioStep(
                name="apply_coupon_second_time_abuse",
                method="POST",
                path="/cart/apply-coupon",
                role="alice",
                body={"code": "WELCOME10"},
                # Invariant: Secure application MUST reject second redemption (status != 200)
                invariants=[
                    SecurityInvariant(
                        name="single_use_enforcement",
                        description="Coupons must enforce single-use policy and reject repeated redemption",
                        field_path="status_code",
                        operator=InvariantOperator.NOT_EQUALS,
                        expected_value=200,
                    ),
                ],
            ),
        ],
        vulnerable_target_path="/api/vulnerable",
        secure_target_path="/api/secure",
    ),

    # =========================================================================
    # B. CHECKOUT AND PAYMENT WORKFLOW
    # =========================================================================
    "BL-CHECKOUT-01": ScenarioDefinition(
        id="BL-CHECKOUT-01",
        title="Checkout Completion Without Prior Payment Verification",
        description="Tests whether an order can transition to 'completed' directly without a verified payment step or balance deduction.",
        category="checkout_bypass",
        cwe="CWE-840",
        owasp_category="A06:2025 - Insecure Design",
        severity=InvariantSeverity.CRITICAL,
        required_roles=["alice"],
        steps=[
            ScenarioStep(
                name="direct_checkout_completion_attempt",
                method="POST",
                path="/checkout/complete",
                role="alice",
                body={
                    "items": [{"product_id": 1, "price": 100, "qty": 1}],
                    "shipping_address": "777 Hacker Way, Suite 100",
                },
                # Invariant: Order creation without authorized payment must be rejected (status != 200)
                invariants=[
                    SecurityInvariant(
                        name="payment_verification_required",
                        description="Order completion requires payment step verification before status becomes 'completed'",
                        field_path="status_code",
                        operator=InvariantOperator.NOT_EQUALS,
                        expected_value=200,
                    ),
                ],
            ),
        ],
        vulnerable_target_path="/api/vulnerable",
        secure_target_path="/api/secure",
    ),

    # =========================================================================
    # C. QUANTITY AND PRICE MANIPULATION
    # =========================================================================
    "BL-QTY-01": ScenarioDefinition(
        id="BL-QTY-01",
        title="Negative Cart Item Quantity Leading to Negative Order Cost",
        description="Tests whether the cart allows negative item quantities, reducing total cost or creating negative balances.",
        category="quantity_manipulation",
        cwe="CWE-20",
        owasp_category="A06:2025 - Insecure Design",
        severity=InvariantSeverity.HIGH,
        required_roles=["alice"],
        steps=[
            ScenarioStep(
                name="add_negative_item_to_cart",
                method="POST",
                path="/cart/add",
                role="alice",
                body={"product_id": 1, "quantity": -5},
                # Invariant: Adding items must reject quantity <= 0 (status != 200)
                invariants=[
                    SecurityInvariant(
                        name="positive_quantity_enforced",
                        description="Cart items must have quantity > 0 and reject negative values",
                        field_path="status_code",
                        operator=InvariantOperator.NOT_EQUALS,
                        expected_value=200,
                    ),
                ],
            ),
        ],
        vulnerable_target_path="/api/vulnerable",
        secure_target_path="/api/secure",
    ),

    # =========================================================================
    # D. ACCOUNT AND TENANT WORKFLOWS
    # =========================================================================
    "BL-ROLE-01": ScenarioDefinition(
        id="BL-ROLE-01",
        title="Unauthorized Role Parameter Mutation (Privilege Escalation)",
        description="Tests whether a standard user can elevate their account role to administrator by injecting a 'role' parameter during profile update.",
        category="account_workflows",
        cwe="CWE-269",
        owasp_category="A01:2025 - Broken Access Control",
        severity=InvariantSeverity.CRITICAL,
        required_roles=["alice"],
        steps=[
            ScenarioStep(
                name="submit_profile_update_with_role_injection",
                method="POST",
                path="/profile/update",
                role="alice",
                body={"user_id": 1, "role": "administrator"},
                # Invariant: Profile updates must not reflect unauthenticated role elevation
                invariants=[
                    SecurityInvariant(
                        name="untrusted_role_rejected",
                        description="Ordinary customer profile update must not assign administrator role",
                        field_path="body.updated_role",
                        operator=InvariantOperator.NOT_EXISTS,
                        expected_value=None,
                    ),
                ],
            ),
        ],
        vulnerable_target_path="/api/vulnerable",
        secure_target_path="/api/secure",
    ),

    # =========================================================================
    # E. TRANSACTION ATOMICITY & PARTIAL FAILURES
    # =========================================================================
    "BL-TRANSFER-01": ScenarioDefinition(
        id="BL-TRANSFER-01",
        title="Transaction Exception Handling Atomicity & Balance Consistency",
        description="Tests whether financial transfers roll back atomic changes when an intermediate error or simulated network drop occurs.",
        category="balance_manipulation",
        cwe="CWE-755",
        owasp_category="A10:2025 - Mishandling of Exceptional Conditions",
        severity=InvariantSeverity.HIGH,
        required_roles=["alice"],
        steps=[
            ScenarioStep(
                name="execute_failing_transfer",
                method="POST",
                path="/exceptions/transfer",
                role="alice",
                body={"recipient_id": 2, "amount": 500.0},
                # Invariant: Partial failure without rollback must be prohibited (status != 'partial_failure')
                invariants=[
                    SecurityInvariant(
                        name="transaction_rollback_enforced",
                        description="Database must roll back transfer on failure, not leaving sender debited without credit",
                        field_path="body.status",
                        operator=InvariantOperator.NOT_EQUALS,
                        expected_value="partial_failure",
                    ),
                ],
            ),
        ],
        vulnerable_target_path="/api/vulnerable",
        secure_target_path="/api/secure",
    ),
}


def get_scenario(scenario_id: str) -> ScenarioDefinition:
    if scenario_id not in SCENARIOS:
        raise KeyError(f"Scenario '{scenario_id}' not found in scenario library.")
    return SCENARIOS[scenario_id]


def list_scenarios() -> List[ScenarioDefinition]:
    return list(SCENARIOS.values())
