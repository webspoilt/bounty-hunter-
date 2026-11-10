"""Ground-truth vulnerability benchmark dataset and schema (Strategic P10).

Covers all 10 required vulnerability categories:
1. Broken Object Level Authorization (BOLA / IDOR)
2. Broken Function Level Authorization (BFLA)
3. Property-level authorization (Mass assignment / Excessive data)
4. Authentication and session boundaries
5. Multi-tenant isolation
6. Business logic and workflow state
7. Input validation and injection
8. Sensitive information exposure
9. Security misconfiguration (CORS, headers)
10. Vulnerable component identification with version applicability

Includes vulnerable cases (true positives), secure negative controls,
and ambiguous cases that must not be forced to positive/negative.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Sequence


class BenchmarkCategory(str, Enum):
    BOLA_IDOR = "BOLA_IDOR"
    BFLA = "BFLA"
    PROPERTY_AUTHZ = "PROPERTY_AUTHZ"
    AUTH_SESSION = "AUTH_SESSION"
    MULTI_TENANT = "MULTI_TENANT"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    INJECTION = "INJECTION"
    INFO_EXPOSURE = "INFO_EXPOSURE"
    MISCONFIG = "MISCONFIG"
    VULN_COMPONENT = "VULN_COMPONENT"


class ExpectedVerdict(str, Enum):
    VULNERABLE = "VULNERABLE"           # Ground truth: real security defect present
    SECURE = "SECURE"                   # Ground truth: negative control, access denied / properly enforced
    AMBIGUOUS = "AMBIGUOUS"             # Ground truth: insufficient evidence or indeterminate behavior


@dataclass
class GroundTruthTestCase:
    """Rigorous ground-truth benchmark test case definition."""
    case_id: str
    category: BenchmarkCategory
    title: str
    description: str
    target_endpoint: str
    method: str
    required_roles: list[str]
    expected_verdict: ExpectedVerdict
    expected_status_code: int
    expected_evidence_markers: list[str]
    negative_control: str
    impact: str
    safe_reproduction_procedure: str
    cwe_id: str = ""
    is_ambiguous: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["expected_verdict"] = self.expected_verdict.value
        return d


# Benchmark Dataset: 20 comprehensive test cases (10 vulnerable, 7 secure negative controls, 3 ambiguous)
BENCHMARK_CASES: tuple[GroundTruthTestCase, ...] = (
    # 1. BOLA / IDOR
    GroundTruthTestCase(
        case_id="TC-BOLA-01",
        category=BenchmarkCategory.BOLA_IDOR,
        title="Horizontal IDOR in user profile endpoint",
        description="User B requests User A's profile via direct ID substitution and receives User A's PII.",
        target_endpoint="/api/v1/users/{owner_id}/profile",
        method="GET",
        required_roles=["role_a", "role_b"],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["alice@example.com", "Alice Smith"],
        negative_control="User B requests unowned non-existent ID -> 404 or access denied",
        impact="Unauthorized disclosure of sensitive user profile data.",
        safe_reproduction_procedure="Send GET with Role B Bearer token referencing Role A's user ID.",
        cwe_id="CWE-639",
    ),
    GroundTruthTestCase(
        case_id="TC-BOLA-02-CONTROL",
        category=BenchmarkCategory.BOLA_IDOR,
        title="Secure object boundary enforcement on document retrieval",
        description="User B attempts to access User A's private document; server strictly returns 403 Forbidden.",
        target_endpoint="/api/v1/documents/{owner_doc_id}",
        method="GET",
        required_roles=["role_a", "role_b"],
        expected_verdict=ExpectedVerdict.SECURE,
        expected_status_code=403,
        expected_evidence_markers=["Forbidden", "Access Denied"],
        negative_control="Baseline access enforcement succeeds.",
        impact="None (secure implementation).",
        safe_reproduction_procedure="Send GET with Role B token for Role A document; expect 403.",
        cwe_id="CWE-639",
    ),

    # 2. BFLA (Broken Function Level Authorization)
    GroundTruthTestCase(
        case_id="TC-BFLA-01",
        category=BenchmarkCategory.BFLA,
        title="Administrative user deletion invoked by low-privilege standard user",
        description="Standard member role can trigger administrative user removal API.",
        target_endpoint="/api/v1/admin/users/{user_id}/delete",
        method="POST",
        required_roles=["role_member"],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["user_deleted", "true"],
        negative_control="Unauthenticated request returns 401 Unauthorized.",
        impact="Privilege escalation allowing unauthorized destruction of accounts.",
        safe_reproduction_procedure="Standard user POSTs to admin deletion endpoint.",
        cwe_id="CWE-285",
    ),
    GroundTruthTestCase(
        case_id="TC-BFLA-02-CONTROL",
        category=BenchmarkCategory.BFLA,
        title="Secure administrative function gate",
        description="Standard member role attempting administrative export receives 403 Forbidden.",
        target_endpoint="/api/v1/admin/export_audit_log",
        method="GET",
        required_roles=["role_member"],
        expected_verdict=ExpectedVerdict.SECURE,
        expected_status_code=403,
        expected_evidence_markers=["Admin privilege required"],
        negative_control="Admin role receives 200 OK.",
        impact="None (secure implementation).",
        safe_reproduction_procedure="Member role requests admin export; verify 403.",
        cwe_id="CWE-285",
    ),

    # 3. Property-Level Authorization
    GroundTruthTestCase(
        case_id="TC-PROP-01",
        category=BenchmarkCategory.PROPERTY_AUTHZ,
        title="Mass assignment privilege elevation via role property injection",
        description="Updating account profile allows injecting {'is_admin': true} or {'role': 'superadmin'}.",
        target_endpoint="/api/v1/account/update",
        method="POST",
        required_roles=["role_member"],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["superadmin", "is_admin"],
        negative_control="Valid non-sensitive properties update cleanly.",
        impact="Horizontal to vertical privilege escalation.",
        safe_reproduction_procedure="Submit JSON body with unauthorized admin properties.",
        cwe_id="CWE-915",
    ),

    # 4. Authentication and Session Boundaries
    GroundTruthTestCase(
        case_id="TC-AUTH-01",
        category=BenchmarkCategory.AUTH_SESSION,
        title="Unauthenticated access to internal telemetry API",
        description="Accessing internal telemetry metrics requires zero authentication or session token.",
        target_endpoint="/api/v1/internal/telemetry/metrics",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["jvm_memory_used", "internal_ip"],
        negative_control="Public home page returns 200 without sensitive data.",
        impact="Information disclosure and internal architecture exposure.",
        safe_reproduction_procedure="Anonymous GET request without auth headers.",
        cwe_id="CWE-306",
    ),
    GroundTruthTestCase(
        case_id="TC-AUTH-02-CONTROL",
        category=BenchmarkCategory.AUTH_SESSION,
        title="Enforced authentication boundary on user dashboard",
        description="Anonymous request to user dashboard correctly redirects or returns 401.",
        target_endpoint="/api/v1/dashboard",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.SECURE,
        expected_status_code=401,
        expected_evidence_markers=["Unauthorized", "Authentication required"],
        negative_control="Authenticated user receives 200.",
        impact="None (secure implementation).",
        safe_reproduction_procedure="Anonymous GET to dashboard; verify 401.",
        cwe_id="CWE-306",
    ),

    # 5. Multi-Tenant Isolation
    GroundTruthTestCase(
        case_id="TC-TENANT-01",
        category=BenchmarkCategory.MULTI_TENANT,
        title="Cross-tenant organization billing leak",
        description="Tenant B user supplies Tenant A's organization_id in query and reads invoice metadata.",
        target_endpoint="/api/v1/organizations/{tenant_a_id}/invoices",
        method="GET",
        required_roles=["tenant_b_user"],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["tenant_a_corp", "invoice_total"],
        negative_control="Tenant B user accesses own tenant invoice.",
        impact="Tenant boundary collapse; cross-customer business confidentiality breach.",
        safe_reproduction_procedure="Tenant B user requests Tenant A organization invoices.",
        cwe_id="CWE-639",
    ),
    GroundTruthTestCase(
        case_id="TC-TENANT-02-CONTROL",
        category=BenchmarkCategory.MULTI_TENANT,
        title="Enforced multi-tenant isolation on repository resources",
        description="Tenant B user receives 404/403 when requesting Tenant A repository items.",
        target_endpoint="/api/v1/organizations/{tenant_a_id}/repos",
        method="GET",
        required_roles=["tenant_b_user"],
        expected_verdict=ExpectedVerdict.SECURE,
        expected_status_code=403,
        expected_evidence_markers=["Not authorized for organization"],
        negative_control="Accessing own tenant repos succeeds.",
        impact="None (secure implementation).",
        safe_reproduction_procedure="Request other tenant repos; verify 403.",
        cwe_id="CWE-639",
    ),

    # 6. Business Logic and Workflow State
    GroundTruthTestCase(
        case_id="TC-LOGIC-01",
        category=BenchmarkCategory.BUSINESS_LOGIC,
        title="Payment step bypass in subscription workflow",
        description="Skipping checkout step and calling directly /activate_subscription grants active tier.",
        target_endpoint="/api/v1/subscription/activate_license",
        method="POST",
        required_roles=["role_member"],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["active", "enterprise"],
        negative_control="Normal flow requires payment gateway callback.",
        impact="Financial loss; free unauthorized provisioning of paid services.",
        safe_reproduction_procedure="POST directly to activation endpoint without payment reference.",
        cwe_id="CWE-840",
    ),

    # 7. Input Validation and Injection
    GroundTruthTestCase(
        case_id="TC-INJECT-01",
        category=BenchmarkCategory.INJECTION,
        title="SQL injection in search filtering parameter",
        description="Submitting boolean SQL payload yields deterministic database syntax error / data reflection.",
        target_endpoint="/api/v1/search?q=' OR 1=1--",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["SQL syntax error", "sqlite_master"],
        negative_control="Benign alphanumeric search returns normal catalog items.",
        impact="Complete database compromise and arbitrary data exfiltration.",
        safe_reproduction_procedure="GET search endpoint with single-quote SQL payload.",
        cwe_id="CWE-89",
    ),
    GroundTruthTestCase(
        case_id="TC-INJECT-02-CONTROL",
        category=BenchmarkCategory.INJECTION,
        title="Parameterized search query immune to SQL injection",
        description="Search input is safely parameterized; payload is treated as literal search string.",
        target_endpoint="/api/v1/catalog?search=' OR 1=1--",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.SECURE,
        expected_status_code=200,
        expected_evidence_markers=["No items matching query"],
        negative_control="Literal query string returned safely.",
        impact="None (secure implementation).",
        safe_reproduction_procedure="Send payload; verify zero SQL error or leakage.",
        cwe_id="CWE-89",
    ),

    # 8. Sensitive Information Exposure
    GroundTruthTestCase(
        case_id="TC-INFO-01",
        category=BenchmarkCategory.INFO_EXPOSURE,
        title="Publicly accessible environment variable backup file",
        description="GET /.env returns unredacted database credentials and API secrets.",
        target_endpoint="/.env",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["DB_PASSWORD=", "AWS_SECRET_ACCESS_KEY="],
        negative_control="Public static assets like /favicon.ico return benign binaries.",
        impact="Direct credential compromise and complete system takeover.",
        safe_reproduction_procedure="GET /.env without authentication.",
        cwe_id="CWE-552",
    ),
    GroundTruthTestCase(
        case_id="TC-INFO-02-CONTROL",
        category=BenchmarkCategory.INFO_EXPOSURE,
        title="Blocked access to configuration dotfiles",
        description="Requests to /.env or /.git return 404 or 403 Forbidden.",
        target_endpoint="/api/v1/secure/.env",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.SECURE,
        expected_status_code=404,
        expected_evidence_markers=["Not Found"],
        negative_control="Normal endpoints answer.",
        impact="None (secure implementation).",
        safe_reproduction_procedure="GET /.env; verify 404.",
        cwe_id="CWE-552",
    ),

    # 9. Security Misconfiguration
    GroundTruthTestCase(
        case_id="TC-CONFIG-01",
        category=BenchmarkCategory.MISCONFIG,
        title="CORS arbitrary origin reflection with credentials allowed",
        description="Server reflects Origin header and emits Access-Control-Allow-Credentials: true.",
        target_endpoint="/api/v1/user/account",
        method="GET",
        required_roles=["role_member"],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["Access-Control-Allow-Origin: https://evil-attacker.com", "Access-Control-Allow-Credentials: true"],
        negative_control="Benign origin without credentials header.",
        impact="Cross-origin theft of authenticated session data.",
        safe_reproduction_procedure="GET with Origin: https://evil-attacker.com and Cookie auth.",
        cwe_id="CWE-942",
    ),
    GroundTruthTestCase(
        case_id="TC-CONFIG-02-CONTROL",
        category=BenchmarkCategory.MISCONFIG,
        title="Strict CORS origin allowlist enforcement",
        description="Arbitrary attacker origin is ignored; ACAO is restricted to authorized domain.",
        target_endpoint="/api/v1/secure_user/account",
        method="GET",
        required_roles=["role_member"],
        expected_verdict=ExpectedVerdict.SECURE,
        expected_status_code=200,
        expected_evidence_markers=["Access-Control-Allow-Origin: https://trusted-app.com"],
        negative_control="Trusted origin is allowed.",
        impact="None (secure implementation).",
        safe_reproduction_procedure="Send untrusted Origin; verify not reflected.",
        cwe_id="CWE-942",
    ),

    # 10. Vulnerable Component Intelligence
    GroundTruthTestCase(
        case_id="TC-COMP-01",
        category=BenchmarkCategory.VULN_COMPONENT,
        title="Vulnerable Apache Struts version detected in HTTP banner",
        description="Server header exposes Struts 2.5.10 vulnerable to CVE-2017-5638.",
        target_endpoint="/struts-action.action",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.VULNERABLE,
        expected_status_code=200,
        expected_evidence_markers=["Apache-Coyote/1.1", "Struts 2.5.10"],
        negative_control="Upgraded component version 2.5.30 is unaffected.",
        impact="Remote code execution via known component vulnerability.",
        safe_reproduction_procedure="Inspect HTTP Server and X-Powered-By response headers.",
        cwe_id="CWE-1395",
    ),

    # --- Ambiguous / Inconclusive Ground Truth Cases ---
    GroundTruthTestCase(
        case_id="TC-AMBIG-01",
        category=BenchmarkCategory.BOLA_IDOR,
        title="Profile read returning public company directory information",
        description="Endpoint returns 200 with public business contact info rather than private account PII.",
        target_endpoint="/api/v1/directory/{user_id}",
        method="GET",
        required_roles=["role_b"],
        expected_verdict=ExpectedVerdict.AMBIGUOUS,
        expected_status_code=200,
        expected_evidence_markers=["public_directory: true"],
        negative_control="Public route designed for directory lookup.",
        impact="Uncertain — requires manual researcher evaluation of data classification.",
        safe_reproduction_procedure="Request directory entry; verify if data is intended to be public.",
        cwe_id="CWE-639",
        is_ambiguous=True,
    ),
    GroundTruthTestCase(
        case_id="TC-AMBIG-02",
        category=BenchmarkCategory.INFO_EXPOSURE,
        title="Generic stack trace on malformed integer parameter",
        description="500 Internal Server Error with framework trace but zero secrets, keys, or passwords.",
        target_endpoint="/api/v1/items/invalid_param",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.AMBIGUOUS,
        expected_status_code=500,
        expected_evidence_markers=["ValueError: invalid literal for int()"],
        negative_control="Standard 400 Bad Request.",
        impact="Uncertain — error verbosity without credentials or exploitable injection.",
        safe_reproduction_procedure="Send non-numeric ID parameter; observe 500 error page.",
        cwe_id="CWE-209",
        is_ambiguous=True,
    ),
    GroundTruthTestCase(
        case_id="TC-AMBIG-03",
        category=BenchmarkCategory.MISCONFIG,
        title="Missing Content-Security-Policy header on static asset domain",
        description="CDN origin domain omits CSP headers on pure image/asset host.",
        target_endpoint="/static/logo.png",
        method="GET",
        required_roles=[],
        expected_verdict=ExpectedVerdict.AMBIGUOUS,
        expected_status_code=200,
        expected_evidence_markers=["Content-Type: image/png"],
        negative_control="HTML endpoints should have CSP.",
        impact="Negligible / context-dependent; images cannot execute scripts directly.",
        safe_reproduction_procedure="Inspect headers on static binary response.",
        cwe_id="CWE-16",
        is_ambiguous=True,
    ),
)


class BenchmarkDataset:
    """Manages ground-truth vulnerability test cases and metadata."""

    def __init__(self, cases: tuple[GroundTruthTestCase, ...] = BENCHMARK_CASES):
        self._cases = {c.case_id: c for c in cases}

    def get_case(self, case_id: str) -> GroundTruthTestCase | None:
        return self._cases.get(case_id)

    def list_cases(self, category: BenchmarkCategory | None = None) -> list[GroundTruthTestCase]:
        if category is None:
            return list(self._cases.values())
        return [c for c in self._cases.values() if c.category == category]

    def count_by_verdict(self) -> dict[str, int]:
        counts = {"VULNERABLE": 0, "SECURE": 0, "AMBIGUOUS": 0}
        for c in self._cases.values():
            counts[c.expected_verdict.value] += 1
        return counts

    def version(self) -> str:
        return "1.0.0-p10-standard"
