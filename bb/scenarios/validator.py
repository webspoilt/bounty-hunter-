"""State invariant evaluator and validator."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from bb.scenarios.models import InvariantOperator, SecurityInvariant


def get_nested_field(data: Any, path: str) -> Tuple[bool, Any]:
    """Retrieve value from a nested dict/list using a dotted path."""
    if not path or data is None:
        return False, None

    tokens = path.split(".")
    current = data

    for token in tokens:
        if isinstance(current, dict):
            if token in current:
                current = current[token]
            else:
                return False, None
        elif isinstance(current, list):
            try:
                idx = int(token)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return False, None
            except ValueError:
                return False, None
        else:
            return False, None

    return True, current


class InvariantValidator:
    """Evaluates security invariants against response payloads and execution contexts."""

    @staticmethod
    def evaluate(invariant: SecurityInvariant, data: Any, context: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Evaluate an invariant.
        Returns (is_violated, reason_message).
        Note: The invariant defines what MUST hold true. If it fails, an invariant violation occurred.
        """
        if invariant.operator == InvariantOperator.CUSTOM:
            if invariant.custom_evaluator:
                passed = invariant.custom_evaluator(data, context)
                if not passed:
                    return True, f"Custom invariant '{invariant.name}' failed: {invariant.description}"
                return False, ""
            return False, ""

        exists, value = get_nested_field(data, invariant.field_path)

        op = invariant.operator
        exp = invariant.expected_value

        if op == InvariantOperator.EXISTS:
            if not exists:
                return True, f"Invariant '{invariant.name}' violated: field '{invariant.field_path}' does not exist"
            return False, ""

        if op == InvariantOperator.NOT_EXISTS:
            if exists:
                return True, f"Invariant '{invariant.name}' violated: field '{invariant.field_path}' exists with value {value}"
            return False, ""

        if not exists:
            # If the field is missing, check if this is NOT_EQUALS (meaning the forbidden value wasn't present)
            if op == InvariantOperator.NOT_EQUALS:
                return False, ""
            if exp is None and op == InvariantOperator.EQUALS:
                return False, ""
            return True, f"Invariant '{invariant.name}' violated: field '{invariant.field_path}' missing in payload"

        if op == InvariantOperator.EQUALS:
            if value != exp:
                return True, f"Invariant '{invariant.name}' violated: expected '{invariant.field_path}' == {exp}, got {value}"

        elif op == InvariantOperator.NOT_EQUALS:
            if value == exp:
                return True, f"Invariant '{invariant.name}' violated: expected '{invariant.field_path}' != {exp}, got {value}"

        elif op == InvariantOperator.GREATER_THAN:
            try:
                if not (float(value) > float(exp)):
                    return True, f"Invariant '{invariant.name}' violated: expected '{invariant.field_path}' > {exp}, got {value}"
            except (ValueError, TypeError):
                return True, f"Invariant '{invariant.name}' evaluation error: non-numeric value {value}"

        elif op == InvariantOperator.GREATER_THAN_OR_EQUAL:
            try:
                if not (float(value) >= float(exp)):
                    return True, f"Invariant '{invariant.name}' violated: expected '{invariant.field_path}' >= {exp}, got {value}"
            except (ValueError, TypeError):
                return True, f"Invariant '{invariant.name}' evaluation error: non-numeric value {value}"

        elif op == InvariantOperator.LESS_THAN:
            try:
                if not (float(value) < float(exp)):
                    return True, f"Invariant '{invariant.name}' violated: expected '{invariant.field_path}' < {exp}, got {value}"
            except (ValueError, TypeError):
                return True, f"Invariant '{invariant.name}' evaluation error: non-numeric value {value}"

        elif op == InvariantOperator.LESS_THAN_OR_EQUAL:
            try:
                if not (float(value) <= float(exp)):
                    return True, f"Invariant '{invariant.name}' violated: expected '{invariant.field_path}' <= {exp}, got {value}"
            except (ValueError, TypeError):
                return True, f"Invariant '{invariant.name}' evaluation error: non-numeric value {value}"

        elif op == InvariantOperator.CONTAINS:
            if exp not in str(value):
                return True, f"Invariant '{invariant.name}' violated: '{exp}' not found in {value}"

        elif op == InvariantOperator.NOT_CONTAINS:
            if exp in str(value):
                return True, f"Invariant '{invariant.name}' violated: '{exp}' unexpectedly found in {value}"

        elif op == InvariantOperator.ONE_OF:
            if value not in exp:
                return True, f"Invariant '{invariant.name}' violated: {value} not one of {exp}"

        return False, ""
