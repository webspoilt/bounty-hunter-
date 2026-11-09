"""Specialist Worker Definitions for Bounty Hunter Multi-Agent Architecture.

Organized into 5 logical research teams:
1. Discovery Team
   - Asset Discovery Analyst
   - Route Mapper
   - JavaScript/API Analyst
   - API Schema Analyst
   - Application Behavior Mapper

2. Identity and Authorization Team
   - Authentication Analyst
   - Session Analyst
   - Role Analyst
   - Tenant Boundary Analyst
   - Object Ownership Analyst

3. Vulnerability Research Team
   - Broken Access Control Researcher
   - IDOR/BOLA Researcher
   - Function Authorization Researcher
   - Property Authorization Researcher
   - Business Logic Researcher
   - Injection Analyst
   - SSRF Researcher
   - Security Configuration Analyst
   - Software Component Intelligence Analyst

4. Verification Team
   - Independent Verifier
   - Evidence Reviewer
   - False-Positive Analyst
   - Duplicate Analyst
   - Impact Analyst

5. Research and Reporting Team
   - Security Intelligence Researcher
   - Hypothesis Prioritizer
   - Report Preparation Analyst
   - Research Quality Evaluator

These are logical worker definitions sharing unified persistent SQLite storage,
authoritative request budgets, and bounded local model gateways.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TeamType(str, Enum):
    DISCOVERY = "DISCOVERY"
    IDENTITY_AUTH = "IDENTITY_AUTH"
    VULN_RESEARCH = "VULN_RESEARCH"
    VERIFICATION = "VERIFICATION"
    RESEARCH_REPORTING = "RESEARCH_REPORTING"


@dataclass(frozen=True)
class SpecialistRole:
    role_id: str
    name: str
    team: TeamType
    description: str
    supported_task_kinds: frozenset[str]
    safe_methods_only: bool = True
    requires_roles: bool = False
    model_requirement: str = "none"  # "none", "tev1", "qwen"


SPECIALIST_ROLES: tuple[SpecialistRole, ...] = (
    # --- 1. Discovery Team ---
    SpecialistRole(
        role_id="asset_discovery_analyst",
        name="Asset Discovery Analyst",
        team=TeamType.DISCOVERY,
        description="Enumerates subdomains, DNS records, and TLS certificate assets within strict scope.",
        supported_task_kinds=frozenset({"asset_recon", "dns", "subdomain"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="route_mapper",
        name="Route Mapper",
        team=TeamType.DISCOVERY,
        description="Crawls scoped web pages and extracts reachable URL endpoints.",
        supported_task_kinds=frozenset({"crawl", "discovery", "recon"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="js_api_analyst",
        name="JavaScript/API Analyst",
        team=TeamType.DISCOVERY,
        description="Parses client-side JavaScript bundles to extract hidden API routes and parameters.",
        supported_task_kinds=frozenset({"js_ast", "api_extract"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="api_schema_analyst",
        name="API Schema Analyst",
        team=TeamType.DISCOVERY,
        description="Interrogates OpenAPI, Swagger, and GraphQL endpoints to construct route templates.",
        supported_task_kinds=frozenset({"openapi", "graphql_introspect", "schema"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="app_behavior_mapper",
        name="Application Behavior Mapper",
        team=TeamType.DISCOVERY,
        description="Normalizes captured parameters and tracks request-response route behaviors.",
        supported_task_kinds=frozenset({"normalize", "params", "behavior"}),
        safe_methods_only=True,
    ),

    # --- 2. Identity and Authorization Team ---
    SpecialistRole(
        role_id="auth_analyst",
        name="Authentication Analyst",
        team=TeamType.IDENTITY_AUTH,
        description="Validates login endpoints, multi-factor challenges, and token refreshes.",
        supported_task_kinds=frozenset({"auth", "login"}),
        safe_methods_only=True,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="session_analyst",
        name="Session Analyst",
        team=TeamType.IDENTITY_AUTH,
        description="Analyzes session cookie flags, token expiration, and session fixation vulnerabilities.",
        supported_task_kinds=frozenset({"session", "cookie_audit"}),
        safe_methods_only=True,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="role_analyst",
        name="Role Analyst",
        team=TeamType.IDENTITY_AUTH,
        description="Maps hierarchical roles (admin, user, guest) across multi-account contexts.",
        supported_task_kinds=frozenset({"roles", "matrix"}),
        safe_methods_only=True,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="tenant_boundary_analyst",
        name="Tenant Boundary Analyst",
        team=TeamType.IDENTITY_AUTH,
        description="Tests cross-tenant isolation and tenant identifier tampering.",
        supported_task_kinds=frozenset({"tenant", "multi_tenant"}),
        safe_methods_only=True,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="object_ownership_analyst",
        name="Object Ownership Analyst",
        team=TeamType.IDENTITY_AUTH,
        description="Tracks UUID/integer object references and establishes resource ownership baselines.",
        supported_task_kinds=frozenset({"ownership", "object_graph"}),
        safe_methods_only=True,
        requires_roles=True,
    ),

    # --- 3. Vulnerability Research Team ---
    SpecialistRole(
        role_id="bac_researcher",
        name="Broken Access Control Researcher",
        team=TeamType.VULN_RESEARCH,
        description="Identifies vertical and horizontal access control gaps on protected routes.",
        supported_task_kinds=frozenset({"authz", "unauth", "bac"}),
        safe_methods_only=True,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="idor_bola_researcher",
        name="IDOR/BOLA Researcher",
        team=TeamType.VULN_RESEARCH,
        description="Executes two-account differential IDOR probes across object-bearing endpoints.",
        supported_task_kinds=frozenset({"idor", "bola", "scenario"}),
        safe_methods_only=False,  # writes gated by human approval
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="function_authz_researcher",
        name="Function Authorization Researcher",
        team=TeamType.VULN_RESEARCH,
        description="Tests function-level permission bypasses on administrative API actions.",
        supported_task_kinds=frozenset({"function_authz", "admin_bypass"}),
        safe_methods_only=False,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="property_authz_researcher",
        name="Property Authorization Researcher",
        team=TeamType.VULN_RESEARCH,
        description="Tests mass assignment and unauthorized object property mutations.",
        supported_task_kinds=frozenset({"mass_assignment", "property_tampering"}),
        safe_methods_only=False,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="business_logic_researcher",
        name="Business Logic Researcher",
        team=TeamType.VULN_RESEARCH,
        description="Tests multi-step workflow logic flaws, replay attacks, and state machine bypasses.",
        supported_task_kinds=frozenset({"workflow", "logic"}),
        safe_methods_only=False,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="injection_analyst",
        name="Injection Analyst",
        team=TeamType.VULN_RESEARCH,
        description="Probes for SQLi, command injection, and template injection within scope constraints.",
        supported_task_kinds=frozenset({"sqli", "injection", "template_injection"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="ssrf_researcher",
        name="SSRF Researcher",
        team=TeamType.VULN_RESEARCH,
        description="Tests webhook and URL import parameters with DNS rebinding and loopback guards.",
        supported_task_kinds=frozenset({"ssrf", "webhook"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="security_config_analyst",
        name="Security Configuration Analyst",
        team=TeamType.VULN_RESEARCH,
        description="Audits CORS policies, security headers, open redirects, and exposed files.",
        supported_task_kinds=frozenset({"cors", "headers", "exposed", "open_redirect"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="component_intel_analyst",
        name="Component Intelligence Analyst",
        team=TeamType.VULN_RESEARCH,
        description="Evaluates detected software technologies against multi-dimensional CVE/advisories.",
        supported_task_kinds=frozenset({"cve", "intel", "component_match"}),
        safe_methods_only=True,
    ),

    # --- 4. Verification Team ---
    SpecialistRole(
        role_id="independent_verifier",
        name="Independent Verifier",
        team=TeamType.VERIFICATION,
        description="Audits finding evidence offline and executes independent 2-role online replay.",
        supported_task_kinds=frozenset({"verify"}),
        safe_methods_only=True,
        requires_roles=True,
    ),
    SpecialistRole(
        role_id="evidence_reviewer",
        name="Evidence Reviewer",
        team=TeamType.VERIFICATION,
        description="Validates cryptographic hashes, exchange logs, and identity markers in evidence.",
        supported_task_kinds=frozenset({"evidence_audit"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="false_positive_analyst",
        name="False-Positive Analyst",
        team=TeamType.VERIFICATION,
        description="Evaluates negative controls and response similarity to reject spurious claims.",
        supported_task_kinds=frozenset({"fp_audit"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="duplicate_analyst",
        name="Duplicate Analyst",
        team=TeamType.VERIFICATION,
        description="Checks route similarity and existing accepted outcomes to prevent duplicate submissions.",
        supported_task_kinds=frozenset({"duplicate_check"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="impact_analyst",
        name="Impact Analyst",
        team=TeamType.VERIFICATION,
        description="Analyzes technical blast radius and confidentiality/integrity impact.",
        supported_task_kinds=frozenset({"impact_assessment"}),
        safe_methods_only=True,
        model_requirement="tev1",
    ),

    # --- 5. Research and Reporting Team ---
    SpecialistRole(
        role_id="security_intel_researcher",
        name="Security Intelligence Researcher",
        team=TeamType.RESEARCH_REPORTING,
        description="Correlates discovered routes and parameters with CWE weakness and CAPEC patterns.",
        supported_task_kinds=frozenset({"intel_enrich"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="hypothesis_prioritizer",
        name="Hypothesis Prioritizer",
        team=TeamType.RESEARCH_REPORTING,
        description="Ranks test hypotheses using Laplace feedback priors and multi-dimensional CVE scores.",
        supported_task_kinds=frozenset({"rank_hypo"}),
        safe_methods_only=True,
        model_requirement="tev1",
    ),
    SpecialistRole(
        role_id="report_prep_analyst",
        name="Report Preparation Analyst",
        team=TeamType.RESEARCH_REPORTING,
        description="Renders sanitized HackerOne markdown reports for human review.",
        supported_task_kinds=frozenset({"report", "queue"}),
        safe_methods_only=True,
    ),
    SpecialistRole(
        role_id="research_quality_evaluator",
        name="Research Quality Evaluator",
        team=TeamType.RESEARCH_REPORTING,
        description="Audits decision evaluator logs and benchmarks Tev1 vs deterministic baselines.",
        supported_task_kinds=frozenset({"eval_audit"}),
        safe_methods_only=True,
    ),
)


class SpecialistWorkerRegistry:
    """Registry managing all 24 logical specialist worker roles across 5 teams."""

    def __init__(self, roles: tuple[SpecialistRole, ...] = SPECIALIST_ROLES):
        self._roles = {r.role_id: r for r in roles}

    def get_role(self, role_id: str) -> SpecialistRole | None:
        return self._roles.get(role_id)

    def list_roles(self, team: TeamType | None = None) -> list[SpecialistRole]:
        if team is None:
            return list(self._roles.values())
        return [r for r in self._roles.values() if r.team == team]

    def select_role_for_task(self, task_kind: str) -> SpecialistRole:
        kind = task_kind.lower()
        for r in self._roles.values():
            if kind in r.supported_task_kinds:
                return r
        # Safe default mapping
        if "authz" in kind or "idor" in kind or "bola" in kind:
            return self._roles["idor_bola_researcher"]
        if "verify" in kind:
            return self._roles["independent_verifier"]
        if "crawl" in kind or "recon" in kind:
            return self._roles["route_mapper"]
        return self._roles["security_config_analyst"]
