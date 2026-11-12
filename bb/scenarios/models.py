"""Data models and invariants for stateful business-logic vulnerability testing."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class InvariantOperator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    ONE_OF = "one_of"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    CUSTOM = "custom"


class InvariantSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScenarioVerdict(str, Enum):
    VULNERABLE = "vulnerable"       # Security invariant violated; flaw reproduced
    ENFORCED = "enforced"           # Application correctly enforced security invariant
    INCONCLUSIVE = "inconclusive"   # Step failed unexpectedly or environmental issue
    SKIPPED = "skipped"             # Preconditions or requirements not met


@dataclass
class SecurityInvariant:
    """A formal rule that an application's state or responses must never violate."""
    name: str
    description: str
    field_path: str                 # Dotted path into response JSON or state, e.g. "discount_pct", "body.line_total"
    operator: InvariantOperator = InvariantOperator.EQUALS
    expected_value: Any = None
    severity: InvariantSeverity = InvariantSeverity.HIGH
    cwe: str = "CWE-840"           # Default Business Logic Flaw CWE
    owasp_category: str = "A06:2025 - Insecure Design"
    custom_evaluator: Optional[Callable[[Any, Dict[str, Any]], bool]] = None


@dataclass
class ScenarioStep:
    """A single HTTP transaction in a stateful workflow."""
    name: str
    method: str
    path: str
    role: str = "customer"          # Role identifier (e.g., 'alice', 'bob', 'admin')
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None
    extract: Dict[str, str] = field(default_factory=dict)     # var_name -> dotted path in response
    expected_status: List[int] = field(default_factory=lambda: [200])
    invariants: List[SecurityInvariant] = field(default_factory=list)
    delay_ms: int = 0
    concurrency_group: Optional[str] = None                   # For simulating race conditions


@dataclass
class ScenarioDefinition:
    """Declarative specification of a multi-step business logic test scenario."""
    id: str
    title: str
    description: str
    category: str                   # coupon_abuse, checkout_bypass, quantity_manipulation, etc.
    cwe: str
    owasp_category: str
    severity: InvariantSeverity
    preconditions: Dict[str, Any] = field(default_factory=dict)
    required_roles: List[str] = field(default_factory=lambda: ["customer"])
    steps: List[ScenarioStep] = field(default_factory=list)
    final_invariants: List[SecurityInvariant] = field(default_factory=list)
    database_reset_required: bool = True
    vulnerable_target_path: str = ""
    secure_target_path: str = ""


@dataclass
class StepExecutionLog:
    step_name: str
    method: str
    url: str
    role: str
    status_code: int
    request_headers: Dict[str, str]
    request_body: Any
    response_headers: Dict[str, str]
    response_body: Any
    duration_ms: float
    violations: List[str] = field(default_factory=list)


@dataclass
class ScenarioRunResult:
    scenario_id: str
    scenario_title: str
    target_url: str
    verdict: ScenarioVerdict
    start_time: str
    duration_ms: float
    step_logs: List[StepExecutionLog] = field(default_factory=list)
    violations: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    finding_summary: str = ""
