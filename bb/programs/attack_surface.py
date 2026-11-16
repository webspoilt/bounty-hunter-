"""Public attack surface, API capabilities, and multi-tenant feature extraction."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from bb.programs.program_models import DiscoveredProgram

MULTI_TENANT_KEYWORDS = [
    "organization", "workspace", "tenant", "team", "membership",
    "role", "permission", "invitation", "collaborator", "rbac"
]

REST_API_KEYWORDS = [
    "/api/v", "rest api", "endpoints", "bearer token", "api key",
    "openapi", "swagger", "json api", "webhook"
]

GRAPHQL_KEYWORDS = [
    "graphql", "/graphql", "query", "mutation", "schema"
]

AUTH_WORKFLOW_KEYWORDS = [
    "oauth", "saml", "sso", "session", "password reset", "mfa",
    "2fa", "signup", "login", "account linking", "magic link"
]


class AttackSurfaceAnalyzer:
    """Infers application functionality and attack surface based on public policy & documentation."""

    @classmethod
    def analyze(cls, program: DiscoveredProgram) -> None:
        text = f"{program.name} {program.policy_text}".lower()
        features: Set[str] = set()

        # 1. Multi-tenant detection
        if any(kw in text for kw in MULTI_TENANT_KEYWORDS):
            program.is_multi_tenant = True
            features.add("Multi-Tenant RBAC Workspaces")

        # 2. REST API detection
        has_api_asset = any("api" in a.asset_identifier.lower() for a in program.in_scope_assets)
        if has_api_asset or any(kw in text for kw in REST_API_KEYWORDS):
            program.has_rest_api = True
            features.add("REST API Endpoints")

        # 3. GraphQL detection
        if any(kw in text for kw in GRAPHQL_KEYWORDS):
            program.has_graphql = True
            features.add("GraphQL API Interface")

        # 4. Authentication workflows
        if any(kw in text for kw in AUTH_WORKFLOW_KEYWORDS):
            program.has_auth_workflows = True
            features.add("Complex Auth & Session Management")

        # 5. AI features
        if program.ai_classification in ("CONFIRMED_AI_BUILT", "PROBABLE_AI_BUILT", "AI_PRODUCT"):
            program.has_ai_features = True
            features.add("AI/LLM Workflows & Assistants")

        program.features_detected = sorted(list(features))
