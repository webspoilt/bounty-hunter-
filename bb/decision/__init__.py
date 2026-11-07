"""Decision subsystem: structured, advisory choices from local Tev1.

All decisions are strictly advisory recommendations validated against an
explicit caller-supplied candidate set. Python code and the resource manager
own all permissions, scope checks, budgets, and execution.
"""
from __future__ import annotations

from bb.decision.gateway import DecisionGateway

__all__ = ["DecisionGateway"]
