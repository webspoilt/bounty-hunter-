"""HackerOne acquisition, guideline reader, ranking and research pipeline.

Phase 2 - 10 implementation & repair:
- Read-only official HackerOne API connector (programs, program, structured_scopes,
  scope_exclusions, weaknesses) with pagination, rate-limit & Retry-After handling.
- Program discovery and multi-factor ranking. Honest 'Not loaded' state when scope
  is not fetched in list view.
- Guideline parsing: preserves full verbatim policy text + machine-readable rules.
- Policy hash, source, retrieval timestamp, ambiguity tracking.
- Browser Research Agent for supplementary guideline inspection & screenshot evidence.
- Program Authorization Brief card generation and explicit human review gating.
- Safe path sanitization preventing directory traversal on program handles.
- H1 draft report preparation with demonstrated impact and verified steps.
- Safe integration with existing Scope, ScopedClient, RequestBudget, Store, and Controller.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

import httpx

from bb.config import DATA, H1_API, H1_TOKEN, H1_USERNAME, now_iso
from bb.models import Finding
from bb.orchestrator.profile import AutonomyLevel, ProfileValidity, ProgramProfile
from bb.scope import Scope, normalize_host, parse_target

log = logging.getLogger(__name__)

# Directory paths for H1 artifacts
H1_DIR = DATA / "h1"
H1_PROGRAMS_DIR = H1_DIR / "programs"
H1_POLICIES_DIR = H1_DIR / "policies"
H1_BRIEFS_DIR = H1_DIR / "briefs"
H1_REPORTS_DIR = H1_DIR / "reports"


def ensure_h1_dirs() -> None:
    for d in (H1_DIR, H1_PROGRAMS_DIR, H1_POLICIES_DIR, H1_BRIEFS_DIR, H1_REPORTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def sanitize_handle(handle: str) -> str:
    """Sanitize program handle to prevent path traversal or invalid filesystem characters."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", (handle or "").strip())
    cleaned = cleaned.strip("._")
    return cleaned or "unknown_program"


class H1Error(RuntimeError):
    pass


class H1RateLimitError(H1Error):
    def __init__(self, message: str, retry_after: float = 60.0):
        super().__init__(message)
        self.retry_after = retry_after


class H1AuthError(H1Error):
    pass


# ---------------------------------------------------------------------------
# PHASE 2 & 3: HACKERONE API CONNECTOR
# ---------------------------------------------------------------------------

class H1Client:
    """Read-only HackerOne Researcher API client.
    
    Security Invariants:
    - Restricts communication exclusively to https://api.hackerone.com (or configured mock base)
    - Strictly read-only: implements GET requests only; cannot mutate H1 state
    - Never logs, prints, or exposes credentials
    - Handles pagination (page[number] and page[size])
    - Respects rate limits, 429 status, and Retry-After headers
    """
    api_base: str = H1_API
    auth: tuple[str, str] = ("", "")
    timeout: float = 30.0
    max_retries: int = 3
    min_delay: float = 0.5
    _last_request_time: float = 0.0

    def __init__(self, username: str = "", token: str = "",
                 api_base: str = H1_API, timeout: float = 30.0,
                 max_retries: int = 3, min_delay: float = 0.5):
        self.username = username or os.environ.get("H1_USERNAME") or H1_USERNAME
        self.token = token or os.environ.get("H1_TOKEN") or H1_TOKEN
        if not self.username or not self.token:
            raise H1AuthError(
                "HackerOne credentials missing. Set H1_USERNAME and H1_TOKEN environment variables "
                "or generate an API token from hackerone.com/settings/api_token"
            )
        self.api_base = api_base.rstrip("/")
        # Verify host restriction
        parsed = urlsplit(self.api_base)
        if parsed.netloc not in ("api.hackerone.com", "localhost", "127.0.0.1"):
            raise H1Error(f"H1Client restricted to official HackerOne API host, got: {parsed.netloc}")

        self.auth = (self.username, self.token)
        self.timeout = timeout
        self.max_retries = max_retries
        self.min_delay = min_delay
        self._last_request_time = 0.0

    def _throttle(self) -> None:
        """Conservative request pacing to respect API rate limits."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
        self._last_request_time = time.time()

    def _get(self, path: str, **params) -> dict:
        """Internal GET with retry on transient network errors & 429 rate limit."""
        url = f"{self.api_base}{path}"
        headers = {"Accept": "application/json", "User-Agent": "BountyHunter-Researcher/1.0"}

        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                r = httpx.get(url, auth=self.auth, params=params, timeout=self.timeout, headers=headers)
            except httpx.HTTPError as exc:
                if attempt == self.max_retries:
                    raise H1Error(f"HackerOne API unreachable at {path}: {exc}") from exc
                time.sleep(1.0 * (attempt + 1))
                continue

            if r.status_code == 200:
                try:
                    return r.json()
                except Exception as exc:
                    raise H1Error(f"Invalid JSON returned from HackerOne API {path}: {exc}") from exc

            if r.status_code == 401:
                raise H1AuthError("HackerOne rejected credentials (401) — check H1_USERNAME and H1_TOKEN")
            if r.status_code == 403:
                raise H1AuthError(f"HackerOne access forbidden (403) for {path} — check token scopes or program membership")
            if r.status_code == 404:
                raise H1Error(f"HackerOne resource not found (404) at {path}")

            if r.status_code == 429:
                retry_after = 60.0
                ra_header = r.headers.get("Retry-After")
                if ra_header:
                    try:
                        retry_after = float(ra_header)
                    except ValueError:
                        pass
                if attempt < self.max_retries:
                    log.warning(f"Rate limited by HackerOne API (429). Retrying after {retry_after}s...")
                    time.sleep(min(retry_after, 10.0))  # sleep up to 10s in retry loop
                    continue
                raise H1RateLimitError(f"HackerOne rate limit exceeded (429) for {path}", retry_after=retry_after)

            if r.status_code >= 500:
                if attempt < self.max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                raise H1Error(f"HackerOne server error {r.status_code} at {path}: {r.text[:200]}")

            raise H1Error(f"HackerOne API error {r.status_code} at {path}: {r.text[:200]}")

        raise H1Error(f"HackerOne request failed after {self.max_retries} retries: {path}")

    def _paginate(self, path: str, page_size: int = 100, max_pages: int = 10, **params) -> list[dict]:
        """Collect all records across pages using JSON:API page[number] and page[size]."""
        results = []
        page_num = 1
        while page_num <= max_pages:
            p_params = dict(params)
            p_params["page[number]"] = page_num
            p_params["page[size]"] = page_size
            data = self._get(path, **p_params)
            items = data.get("data", [])
            if not items:
                break
            results.extend(items)
            # Check pagination links
            links = data.get("links", {})
            if not links.get("next") or len(items) < page_size:
                break
            page_num += 1
        return results

    def programs(self, page_size: int = 100, max_pages: int = 5) -> list[dict]:
        """GET /v1/hackers/programs: Retrieve programs accessible to the authenticated researcher."""
        return self._paginate("/hackers/programs", page_size=page_size, max_pages=max_pages)

    def program(self, handle: str) -> dict:
        """GET /v1/hackers/programs/{handle}: Retrieve program details and policy."""
        safe_handle = sanitize_handle(handle)
        last_exc = None
        for path in (f"/hackers/programs/{safe_handle}", f"/programs/{safe_handle}"):
            try:
                return self._get(path)
            except H1Error as exc:
                last_exc = exc
        raise H1Error(f"Could not load program {handle!r}: {last_exc}")

    def structured_scopes(self, handle: str) -> list[dict]:
        """GET /v1/hackers/programs/{handle}/structured_scopes: Retrieve in-scope and out-of-scope assets."""
        safe_handle = sanitize_handle(handle)
        try:
            return self._paginate(f"/hackers/programs/{safe_handle}/structured_scopes")
        except H1Error as exc:
            # Fallback to embedded relationship in program()
            prog = self.program(safe_handle)
            rel = (prog.get("data", {}).get("relationships") or {}).get("structured_scopes") or {}
            items = rel.get("data") or []
            if items:
                return items
            log.warning(f"Could not fetch structured scopes endpoint for {safe_handle}: {exc}")
            return []

    def scope_exclusions(self, handle: str) -> list[dict]:
        """GET /v1/hackers/programs/{handle}/scope_exclusions: Retrieve excluded vulnerability categories."""
        safe_handle = sanitize_handle(handle)
        try:
            return self._paginate(f"/hackers/programs/{safe_handle}/scope_exclusions")
        except H1Error as exc:
            log.debug(f"Scope exclusions not available for {safe_handle}: {exc}")
            return []

    def weaknesses(self, handle: str) -> list[dict]:
        """GET /v1/hackers/programs/{handle}/weaknesses: Retrieve eligible/ineligible weakness categories."""
        safe_handle = sanitize_handle(handle)
        try:
            return self._paginate(f"/hackers/programs/{safe_handle}/weaknesses")
        except H1Error as exc:
            log.debug(f"Weaknesses endpoint not available or not supported for {safe_handle}: {exc}")
            return []

    def scope(self, handle: str) -> Scope:
        """Construct a validated Bounty Hunter Scope object from program structured scopes."""
        safe_handle = sanitize_handle(handle)
        prog = self.program(safe_handle)
        prog_data = prog.get("data", {})
        rel = (prog_data.get("relationships") or {}).get("structured_scopes") or {}
        entries = [item.get("attributes", {}) for item in (rel.get("data") or [])]

        if not entries:
            # Dedicated endpoint
            entries_data = self.structured_scopes(safe_handle)
            entries = [e.get("attributes", {}) for e in entries_data if isinstance(e, dict)]

        if not entries:
            raise H1Error(
                f"program {handle!r} returned no structured scopes. The public API only exposes "
                "scope for programs you have joined. Add the scope manually instead:\n"
                f"  bb scope import --program {handle} --from file --file data/scopes/{handle}.json"
            )

        updated_at = (prog_data.get("attributes") or {}).get("updated_at")
        scope = Scope.from_h1_structured(handle, entries)
        if updated_at:
            scope.imported_at = updated_at
        return scope


# ---------------------------------------------------------------------------
# PHASE 4 & 5: PROGRAM DISCOVERY AND RANKING
# ---------------------------------------------------------------------------

@dataclass
class RankedProgram:
    handle: str
    name: str
    offers_bounties: bool
    submission_state: str
    bounty_score: float
    asset_count: int
    web_asset_count: int
    wildcard_count: int
    max_severity: str
    open_scope: bool
    state: str
    rating: float
    assets_loaded: bool = False
    reasons: list[str] = field(default_factory=list)
    raw_attributes: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        bounty_str = "💰 BOUNTY" if self.offers_bounties else "FREE / VDP"
        if not self.assets_loaded:
            assets_str = "Assets: Not loaded in list view"
        else:
            assets_str = f"Assets: {self.asset_count:2d} (Web: {self.web_asset_count:2d}, Wildcards: {self.wildcard_count:2d})"
        return (
            f"[{self.bounty_score:4.1f}] {self.handle:<24} {bounty_str:<11} "
            f"{assets_str:<32} State: {self.submission_state}"
        )


class ProgramDiscoveryRanker:
    """Multi-factor research opportunity ranking system for HackerOne programs.
    
    Formula considers:
    1. Monetary bounty offering (+40 pts)
    2. Number and surface of web & API assets (+4 pts per web asset, +6 per wildcard, max 30)
    3. Active submission state (+15 pts for open, -50 for paused, -100 for closed)
    4. Program rating / reputation (+0 to +10 pts)
    5. Maximum reported severity (Critical = +10, High = +5)
    
    Safety Invariant: Ranking is purely advisory; ranking high never grants testing authorization.
    """

    @staticmethod
    def score_program(prog: dict) -> RankedProgram:
        attrs = prog.get("attributes") or {}
        handle = attrs.get("handle") or prog.get("id") or "unknown"
        name = attrs.get("name") or handle
        offers_bounties = bool(attrs.get("offers_bounties"))
        state = attrs.get("state") or "unknown"
        sub_state = attrs.get("submission_state") or "unknown"
        open_scope = bool(attrs.get("open_scope"))
        rating = float(attrs.get("rating") or 0.0)

        # Count structured scopes if present in relationships
        rel = (prog.get("relationships") or {}).get("structured_scopes") or {}
        scope_data = rel.get("data")
        assets_loaded = scope_data is not None
        scope_data = scope_data or []

        asset_count = len(scope_data)
        web_count = 0
        wildcard_count = 0
        max_sev = "medium"

        for s in scope_data:
            s_attrs = s.get("attributes", {})
            atype = (s_attrs.get("asset_type") or "").upper()
            if atype in ("URL", "API", "DOMAIN"):
                web_count += 1
            elif atype == "WILDCARD":
                wildcard_count += 1
                web_count += 1
            sev = (s_attrs.get("max_severity") or "").lower()
            if sev == "critical":
                max_sev = "critical"
            elif sev == "high" and max_sev != "critical":
                max_sev = "high"

        # Calculate score
        score = 0.0
        reasons = []

        if offers_bounties:
            score += 40.0
            reasons.append("Offers cash bounties (+40)")
        else:
            reasons.append("VDP / points only (+0)")

        if sub_state == "open":
            score += 15.0
            reasons.append("Submissions currently open (+15)")
        elif sub_state == "paused":
            score -= 50.0
            reasons.append("Submissions paused (-50)")
        elif sub_state == "closed":
            score -= 100.0
            reasons.append("Program closed (-100)")

        # Web attack surface
        if assets_loaded:
            surface_pts = min(web_count * 4.0 + wildcard_count * 6.0, 30.0)
            score += surface_pts
            if surface_pts > 0:
                reasons.append(f"Web/API attack surface: {web_count} web targets (+{surface_pts:.1f})")
            if max_sev == "critical":
                score += 10.0
                reasons.append("Accepts critical findings (+10)")
            elif max_sev == "high":
                score += 5.0
                reasons.append("Accepts high findings (+5)")
        else:
            reasons.append("Assets not loaded in list view (inspect with `bb h1 brief`)")

        # Program rating (0.0 to 5.0 -> up to +10 pts)
        if rating > 0:
            rating_pts = min(rating * 2.0, 10.0)
            score += rating_pts
            reasons.append(f"Program rating {rating:.1f}/5.0 (+{rating_pts:.1f})")

        return RankedProgram(
            handle=handle,
            name=name,
            offers_bounties=offers_bounties,
            submission_state=sub_state,
            bounty_score=round(max(score, 0.0), 1),
            asset_count=asset_count,
            web_asset_count=web_count,
            wildcard_count=wildcard_count,
            max_severity=max_sev,
            open_scope=open_scope,
            state=state,
            rating=rating,
            assets_loaded=assets_loaded,
            reasons=reasons,
            raw_attributes=attrs,
        )

    @classmethod
    def rank_programs(cls, raw_programs: list[dict]) -> list[RankedProgram]:
        ranked = [cls.score_program(p) for p in raw_programs]
        ranked.sort(key=lambda r: (r.bounty_score, r.offers_bounties), reverse=True)
        return ranked


# ---------------------------------------------------------------------------
# PHASE 6: COMPLETE GUIDELINE READER
# ---------------------------------------------------------------------------

@dataclass
class ProgramPolicyRecord:
    """Verbatim policy preservation + machine-readable semantic extraction."""
    handle: str
    retrieved_at: str
    policy_hash: str
    original_policy_text: str
    # Machine-readable semantic extractions
    rate_limit_rps: float = 3.0
    prohibited_attacks: list[str] = field(default_factory=list)
    permitted_categories: list[str] = field(default_factory=list)
    ineligible_findings: list[str] = field(default_factory=list)
    requires_test_account: bool = False
    requires_custom_header: bool = False
    custom_header_name: str = ""
    custom_header_value: str = ""
    safe_harbor_terms: str = ""
    ambiguous_clauses: list[str] = field(default_factory=list)
    human_review_required: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> ProgramPolicyRecord:
        return cls(**data)


class PolicyParser:
    """Extracts machine-readable constraints from free-text program policies.
    
    Guarantees:
    - Verbatim policy text preserved in full
    - Computes SHA-256 fingerprint of the policy
    - Identifies automated scanning bans, rate limits, custom header requirements,
      prohibited test types (DoS, social engineering, destructive edits)
    - Flags uncertain or contradictory clauses for mandatory human review
    """

    PROHIBITED_PATTERNS = [
        (re.compile(r"\b(denial\s+of\s+service|dos|ddos)\b", re.I), "denial_of_service"),
        (re.compile(r"\b(social\s+engineering|phishing)\b", re.I), "social_engineering"),
        (re.compile(r"\b(automated\s+(?:mass\s+)?scanners?|mass\s+scanners?|automated\s+tooling\s+prohibited)\b", re.I), "automated_scanners_prohibited"),
        (re.compile(r"\b(spam|brute\s*force|credential\s+stuffing)\b", re.I), "brute_force_spam"),
        (re.compile(r"\b(destructive|data\s+destruction|modify\s+other\s+users)\b", re.I), "destructive_write"),
        (re.compile(r"\b(physical\s+security|access\s+to\s+offices)\b", re.I), "physical_testing"),
    ]

    INELIGIBLE_PATTERNS = [
        (re.compile(r"\b(clickjacking|ui\s+redressing)\b", re.I), "clickjacking"),
        (re.compile(r"\b(rate\s+limiting|missing\s+rate\s+limit)\b", re.I), "rate_limiting"),
        (re.compile(r"\b(spf|dkim|dmarc)\b", re.I), "email_dns_records"),
        (re.compile(r"\b(self[- ]xss)\b", re.I), "self_xss"),
        (re.compile(r"\b(ssl/tls\s+ciphers?|tls\s+configuration)\b", re.I), "tls_ciphers"),
        (re.compile(r"\b(cors\s+misconfiguration\s+without\s+impact)\b", re.I), "cors_no_impact"),
        (re.compile(r"\b(logout\s+csrf)\b", re.I), "logout_csrf"),
    ]

    @classmethod
    def parse_policy(cls, handle: str, policy_text: str, metadata: dict | None = None) -> ProgramPolicyRecord:
        policy_text = policy_text or ""
        policy_hash = hashlib.sha256(policy_text.encode("utf-8")).hexdigest()
        retrieved_at = now_iso()

        prohibited = []
        for pat, tag in cls.PROHIBITED_PATTERNS:
            if pat.search(policy_text):
                prohibited.append(tag)

        ineligible = []
        for pat, tag in cls.INELIGIBLE_PATTERNS:
            if pat.search(policy_text):
                ineligible.append(tag)

        # Rate limit extraction
        rate_limit = 3.0
        rl_match = re.search(r"(\d+)\s*(?:req(?:uests?)?|rps)\s*(?:per|/)\s*(?:sec(?:ond)?|s)", policy_text, re.I)
        if rl_match:
            try:
                rate_limit = float(rl_match.group(1))
            except ValueError:
                pass

        # Custom header identification (e.g. X-Bug-Bounty: researcher)
        custom_header = False
        h_name = ""
        h_val = ""
        h_match = re.search(r"(X-[A-Za-z0-9_-]+)\s*:\s*([A-Za-z0-9_\.@-]+)", policy_text)
        if h_match:
            custom_header = True
            h_name = h_match.group(1)
            h_val = h_match.group(2)

        # Account requirement
        requires_account = bool(re.search(r"\b(test\s+account|create\s+an?\s+account|use\s+your\s+@wearehackerone)\b", policy_text, re.I))

        # Check for ambiguity
        ambiguous = []
        if re.search(r"\b(at\s+our\s+discretion|case[- ]by[- ]case|contact\s+support\s+before\s+testing)\b", policy_text, re.I):
            ambiguous.append("Policy specifies discretionary or case-by-case rules")
        if "automated_scanners_prohibited" in prohibited:
            ambiguous.append("Automated scanner prohibition requires careful rate limiting and manual probe review")

        human_review = len(ambiguous) > 0 or ("automated_scanners_prohibited" in prohibited)

        return ProgramPolicyRecord(
            handle=handle,
            retrieved_at=retrieved_at,
            policy_hash=policy_hash,
            original_policy_text=policy_text,
            rate_limit_rps=rate_limit,
            prohibited_attacks=sorted(set(prohibited)),
            permitted_categories=["authz", "idor", "bfla", "open_redirect", "headers", "exposed"],
            ineligible_findings=sorted(set(ineligible)),
            requires_test_account=requires_account,
            requires_custom_header=custom_header,
            custom_header_name=h_name,
            custom_header_value=h_val,
            safe_harbor_terms="Standard HackerOne Gold / Full Safe Harbor" if "safe harbor" in policy_text.lower() else "Standard H1 terms",
            ambiguous_clauses=ambiguous,
            human_review_required=human_review,
            metadata=metadata or {},
        )


# ---------------------------------------------------------------------------
# PHASE 7 & 8: PROGRAM AUTHORIZATION BRIEF CARD
# ---------------------------------------------------------------------------

@dataclass
class StructuredAssetEntry:
    identifier: str
    asset_type: str
    eligible_for_bounty: bool
    eligible_for_submission: bool
    max_severity: str = "medium"
    instruction: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProgramAuthorizationBrief:
    """Human-readable Program Brief for researcher authorization."""
    handle: str
    program_name: str
    offers_bounties: bool
    policy_hash: str
    retrieved_at: str
    in_scope_assets: list[str]
    out_of_scope_assets: list[str]
    structured_asset_entries: list[dict[str, Any]] = field(default_factory=list)
    scope_exclusions: list[str] = field(default_factory=list)
    testing_restrictions: list[str] = field(default_factory=list)
    rate_limit: float = 3.0
    custom_headers: dict[str, str] = field(default_factory=dict)
    human_review_notes: list[str] = field(default_factory=list)
    recommended_first_target: str = ""
    approval_status: str = "PENDING_HUMAN_APPROVAL"  # PENDING_HUMAN_APPROVAL, APPROVED, REJECTED
    approved_by: str = ""
    approved_at: str = ""

    def render_markdown(self) -> str:
        bounty_str = "Yes (Paid Bounties)" if self.offers_bounties else "No (VDP / Points Only)"
        in_assets_str = "\n".join(f"- `{a}`" for a in self.in_scope_assets[:30]) or "- _No accessible structured scope assets returned by API_"
        out_assets_str = "\n".join(f"- `{a}`" for a in self.out_of_scope_assets[:15]) or "- _None specified_"
        excl_str = "\n".join(f"- {e}" for e in self.scope_exclusions[:10]) or "- _Standard H1 exclusions_"
        restr_str = "\n".join(f"- {r}" for r in self.testing_restrictions) or "- _Standard polite rate limits_"
        notes_str = "\n".join(f"- ⚠️ {n}" for n in self.human_review_notes) or "- None. Standard policy terms."

        headers_str = ", ".join(f"`{k}: {v}`" for k, v in self.custom_headers.items()) if self.custom_headers else "_None required_"

        target_callout = f"🎯 **`{self.recommended_first_target}`**" if self.recommended_first_target else "⚠️ _No in-scope web asset identified for testing_"

        return f"""# PROGRAM AUTHORIZATION BRIEF: {self.handle.upper()}

**Program Name:** {self.program_name}  
**Handle:** `{self.handle}`  
**Monetary Bounties:** {bounty_str}  
**Policy Hash:** `{self.policy_hash[:16]}` (Retrieved: {self.retrieved_at})  
**Approval Status:** **`{self.approval_status}`**  

---

### In-Scope Asset Inventory ({len(self.in_scope_assets)} targets)
{in_assets_str}

### Explicit Out-of-Scope Assets ({len(self.out_of_scope_assets)} targets)
{out_assets_str}

### Scope Exclusions & Ineligible Findings
{excl_str}

### Applicable Testing Restrictions
- Maximum request rate: `{self.rate_limit} req/sec`
- Required research headers: {headers_str}
{restr_str}

### Ambiguities & Human Review Items
{notes_str}

### Proposed First Research Target
{target_callout}

---
> [!IMPORTANT]
> **Operator Authorization Gate:** Target investigation cannot commence until this brief is signed off.
> Run: `bb h1 approve --program {self.handle} --target "{self.recommended_first_target or '<target_url>'}"`
"""


class BriefGenerator:
    """Produces the human-readable Program Brief and builds the ProgramProfile."""

    @staticmethod
    def generate_brief(prog: dict, policy: ProgramPolicyRecord,
                       scopes: list[dict], exclusions: list[dict]) -> ProgramAuthorizationBrief:
        attrs = prog.get("attributes") or {}
        handle = sanitize_handle(attrs.get("handle") or prog.get("id") or "unknown")
        name = attrs.get("name") or handle
        offers_bounties = bool(attrs.get("offers_bounties"))

        in_scope = []
        out_of_scope = []
        structured_entries = []

        for s in scopes:
            s_attrs = s.get("attributes") or {}
            identifier = (s_attrs.get("asset_identifier") or "").strip()
            if not identifier:
                continue
            asset_type = (s_attrs.get("asset_type") or "").upper()
            eligible_bounty = bool(s_attrs.get("eligible_for_bounty", True))
            eligible_sub = s_attrs.get("eligible_for_submission", True) is not False
            max_sev = s_attrs.get("max_severity") or "medium"
            instruction = s_attrs.get("instruction") or ""

            entry = StructuredAssetEntry(
                identifier=identifier,
                asset_type=asset_type,
                eligible_for_bounty=eligible_bounty,
                eligible_for_submission=eligible_sub,
                max_severity=max_sev,
                instruction=instruction[:500],
            )
            structured_entries.append(entry.to_dict())

            if not eligible_sub:
                out_of_scope.append(identifier)
            else:
                in_scope.append(identifier)

        excl_list = [e.get("attributes", {}).get("name") or str(e) for e in exclusions if isinstance(e, dict)]
        if not excl_list:
            excl_list = policy.ineligible_findings

        restrictions = [f"Prohibited: {p}" for p in policy.prohibited_attacks]
        custom_headers = {}
        if policy.requires_custom_header and policy.custom_header_name:
            custom_headers[policy.custom_header_name] = policy.custom_header_value

        # Select first target: prefer URL or specific API hostname over wildcard
        first_target = ""
        for a in in_scope:
            if a.startswith("http://") or a.startswith("https://"):
                first_target = a
                break
            if not a.startswith("*.") and ("." in a):
                first_target = f"https://{a}"
                break
        if not first_target and in_scope:
            candidate = in_scope[0]
            if candidate.startswith("*."):
                first_target = f"https://{candidate[2:]}"
            elif "." in candidate:
                first_target = f"https://{candidate}"
            else:
                first_target = candidate

        return ProgramAuthorizationBrief(
            handle=handle,
            program_name=name,
            offers_bounties=offers_bounties,
            policy_hash=policy.policy_hash,
            retrieved_at=policy.retrieved_at,
            in_scope_assets=in_scope,
            out_of_scope_assets=out_of_scope,
            structured_asset_entries=structured_entries,
            scope_exclusions=excl_list,
            testing_restrictions=restrictions,
            rate_limit=policy.rate_limit_rps,
            custom_headers=custom_headers,
            human_review_notes=policy.ambiguous_clauses,
            recommended_first_target=first_target,
        )

    @staticmethod
    def create_program_profile(brief: ProgramAuthorizationBrief) -> ProgramProfile:
        """Converts an approved brief into an official continuous research ProgramProfile."""
        return ProgramProfile(
            program_id=brief.handle,
            in_scope_assets=brief.in_scope_assets,
            out_of_scope_assets=brief.out_of_scope_assets,
            permitted_categories=["authz", "idor", "bfla", "open_redirect", "headers", "exposed"],
            prohibited_activities=["dos", "social_engineering", "destructive_write"],
            rate_limit=brief.rate_limit,
            validity=ProfileValidity.VALID if brief.approval_status == "APPROVED" else ProfileValidity.PENDING_REVIEW,
            autonomy_level=AutonomyLevel.INVESTIGATE,
            metadata={
                "policy_hash": brief.policy_hash,
                "approved_by": brief.approved_by,
                "approved_at": brief.approved_at,
                "custom_headers": brief.custom_headers,
            }
        )


# ---------------------------------------------------------------------------
# PHASE 9: BROWSER RESEARCH AGENT (SUPPLEMENTARY)
# ---------------------------------------------------------------------------

class BrowserResearchAgent:
    """Optional supplementary browser inspector for HackerOne policy and evidence.
    
    Security Invariants:
    - Operates only under local researcher direction
    - Never bypasses login gates, CAPTCHAs, or rate limits
    - Read-only capture: saves screenshots, DOM text, and HAR logs to disk
    """

    def __init__(self, headless: bool = True):
        self.headless = headless

    def inspect_program_page(self, handle: str) -> dict[str, Any]:
        """Inspect publicly available program page to extract missing guidelines."""
        safe_handle = sanitize_handle(handle)
        url = f"https://hackerone.com/{safe_handle}"
        result = {"url": url, "captured": False, "policy_text": "", "error": None}
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                page = browser.new_page()
                page.goto(url, timeout=20000)
                text = page.inner_text("body")
                result["captured"] = True
                result["policy_text"] = text[:15000]
                browser.close()
        except Exception as exc:
            result["error"] = str(exc)
            log.warning(f"Browser inspection unavailable for {safe_handle}: {exc}")
        return result

    def capture_evidence_screenshot(self, target_url: str, output_path: Path) -> bool:
        """Capture visual reproduction evidence for an authorized in-scope endpoint."""
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                page = browser.new_page()
                page.goto(target_url, timeout=15000)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(output_path), full_page=False)
                browser.close()
            return True
        except Exception as exc:
            log.warning(f"Screenshot capture failed for {target_url}: {exc}")
            return False


# ---------------------------------------------------------------------------
# PHASE 10: HACKERONE REPORT PREPARATION
# ---------------------------------------------------------------------------

class HackerOneReportGenerator:
    """Prepares structured, reproducible HackerOne report drafts for human submission."""

    @staticmethod
    def prepare_draft(finding: Finding, brief: ProgramAuthorizationBrief,
                      scope: Optional[Scope] = None, weakness_id: int = 0) -> dict[str, Any]:
        """Generates markdown report content and formatted submission payload."""
        from bb.report import render_h1

        report_md = render_h1(finding, scope=scope)
        payload = submit_payload(
            finding=finding,
            report_markdown=report_md,
            team_handle=brief.handle,
            weakness_id=weakness_id,
        )
        curl_cmd = submit_curl(payload)

        return {
            "title": finding.title,
            "team_handle": brief.handle,
            "severity": finding.severity,
            "vulnerability_information": report_md,
            "payload": payload,
            "curl_command": curl_cmd,
            "generated_at": now_iso(),
            "finding_id": finding.id,
            "asset": finding.url,
            "reproduction_verified": bool(finding.meta.get("verified")),
        }


# ---------------------------------------------------------------------------
# RE-EXPORT COMPATIBILITY UTILITIES
# ---------------------------------------------------------------------------

def submit_payload(finding: Finding, report_markdown: str, team_handle: str,
                   weakness_id: int = 0, structured_scope_id: int = 0) -> dict:
    attrs = {
        "team_handle": team_handle,
        "title": finding.title[:140],
        "vulnerability_information": report_markdown,
        "severity_rating": {"info": "none", "low": "low", "medium": "medium",
                            "high": "high", "critical": "critical"}.get(finding.severity, "medium"),
    }
    if weakness_id:
        attrs["weakness_id"] = weakness_id
    if structured_scope_id:
        attrs["structured_scope_id"] = structured_scope_id
    return {"data": {"type": "report", "attributes": attrs}}


def submit_curl(payload: dict) -> str:
    body = json.dumps(payload, indent=2)
    return (
        "# Review the report first. This command is printed, never executed by bountybot.\n"
        "curl -sS -X POST https://api.hackerone.com/v1/reports \\\n"
        "  -u \"$H1_USERNAME:$H1_TOKEN\" \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        f"  -d @report.json\n\n# report.json:\n# {body.replace(chr(10), chr(10) + '# ')}"
    )


def basic_auth_header(username: str = H1_USERNAME, token: str = H1_TOKEN) -> str:
    raw = f"{username}:{token}".encode()
    return "Basic " + base64.b64encode(raw).decode()
