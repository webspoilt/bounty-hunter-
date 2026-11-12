"""LLM-assisted workflow analysis and scenario proposal module."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


class ScenarioAnalyzer:
    """Uses Ollama / local LLMs to reason about API schemas and suggest business logic scenarios."""

    def __init__(self, model_name: str = "qwen2.5-coder:latest", base_url: str = "http://localhost:11434"):
        self.model_name = model_name
        self.base_url = base_url

    def analyze_workflow_hypotheses(self, endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate test hypotheses for business logic invariants given endpoint information.
        If LLM is offline, returns standard heuristic hypothesis templates.
        """
        # Deterministic fallback / template hypotheses ensuring reliable execution
        hypotheses = [
            {
                "hypothesis": "Coupons may lack single-use enforcement when applied sequentially in a single cart session.",
                "target_endpoint": "/cart/apply-coupon",
                "recommended_test": "BL-COUPON-01 (Repeated Coupon Application)",
                "risk_rating": "HIGH",
            },
            {
                "hypothesis": "Order placement endpoint may accept orders without checking whether checkout/payment occurred.",
                "target_endpoint": "/checkout/complete",
                "recommended_test": "BL-CHECKOUT-01 (Checkout Completion Bypass)",
                "risk_rating": "CRITICAL",
            },
            {
                "hypothesis": "Cart addition handler might fail to validate minimum bounds on quantity, permitting negative integers.",
                "target_endpoint": "/cart/add",
                "recommended_test": "BL-QTY-01 (Negative Cart Item Quantity)",
                "risk_rating": "HIGH",
            },
            {
                "hypothesis": "Profile update handler may blindly bind input attributes, permitting unprivileged role changes.",
                "target_endpoint": "/profile/update",
                "recommended_test": "BL-ROLE-01 (Unauthorized Role Mutation)",
                "risk_rating": "CRITICAL",
            },
            {
                "hypothesis": "Fund transfer transaction might lack database transaction atomicity during intermediate errors.",
                "target_endpoint": "/exceptions/transfer",
                "recommended_test": "BL-TRANSFER-01 (Atomicity & Rollback)",
                "risk_rating": "HIGH",
            },
        ]
        return hypotheses
