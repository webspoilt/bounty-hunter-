"""HexBrain read-only API Client with authentication, rate limiting, and diagnostics."""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import urllib.request
import urllib.error
import json

from bb.config import DATA, load_project_env
from bb.intel.hexbrain_models import HexBrainReport, HexBrainTechnique
from bb.intel.hexbrain_cache import HexBrainCache

logger = logging.getLogger(__name__)

DEFAULT_HEXBRAIN_BASE = "https://hexbrainai.com/api/v1"


class HexBrainError(Exception):
    """Base exception for HexBrain API errors."""
    pass


class HexBrainAuthError(HexBrainError):
    """Authentication or authorization failure (e.g. invalid key)."""
    pass


class HexBrainRateLimitError(HexBrainError):
    """Rate limit exceeded."""
    pass


class HexBrainClient:
    """Secure, read-only HTTP client for HexBrain research intelligence."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        cache: Optional[HexBrainCache] = None,
        timeout: float = 10.0,
        rate_limit_delay: float = 0.2,
    ):
        load_project_env(override=False)
        self.api_key = api_key if api_key is not None else os.getenv("HEXBRAIN_API_KEY", "")
        self.base_url = (base_url or os.getenv("HEXBRAIN_BASE_URL", DEFAULT_HEXBRAIN_BASE)).rstrip("/")
        self.cache = cache if cache is not None else HexBrainCache()
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time = 0.0

    def _apply_rate_limit(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()

    def _request(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """Perform an authenticated GET request with caching."""
        params = params or {}
        endpoint = "/" + endpoint.lstrip("/")

        if use_cache:
            cached = self.cache.get(endpoint, params)
            if cached is not None:
                return cached

        self._apply_rate_limit()

        qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{self.base_url}{endpoint}"
        if qs:
            url = f"{url}?{qs}"

        headers = {
            "User-Agent": "BountyBot-HexBrainClient/2.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                if use_cache and status == 200:
                    self.cache.set(endpoint, params, data)
                return data
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise HexBrainAuthError(f"HexBrain API authentication failed (HTTP {e.code}). Please verify HEXBRAIN_API_KEY.") from e
            elif e.code == 429:
                raise HexBrainRateLimitError(f"HexBrain API rate limit reached (HTTP 429).") from e
            elif e.code == 404:
                return {"status": "error", "error": "Not found", "data": []}
            else:
                raise HexBrainError(f"HexBrain API error HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise HexBrainError(f"HexBrain connection error: {e.reason}") from e
        except json.JSONDecodeError as e:
            raise HexBrainError(f"Failed to parse HexBrain JSON response: {e}") from e

    def test_connection(self) -> Dict[str, Any]:
        """Verify API connectivity and authentication status."""
        if not self.api_key:
            return {
                "connected": False,
                "status": "UNCONFIGURED",
                "message": "HEXBRAIN_API_KEY environment variable is not set.",
                "dataset_stats": {},
            }

        try:
            # Query canonical list_classes endpoint to test auth and connectivity
            res = self._request("/list_classes", use_cache=False)
            total_reports = res.get("total_reports", 0) if isinstance(res, dict) else 0
            programs_count = res.get("programs", 0) if isinstance(res, dict) else 0
            classes_count = len(res.get("classes", [])) if isinstance(res, dict) else 0

            stats = {
                "reports_count": total_reports,
                "programs_count": programs_count,
                "vulnerability_classes": classes_count,
            }
            return {
                "connected": True,
                "status": "OPERATIONAL",
                "message": "Connected to HexBrain API successfully.",
                "dataset_stats": stats,
            }
        except HexBrainAuthError as e:
            return {
                "connected": False,
                "status": "AUTH_FAILED",
                "message": str(e),
                "dataset_stats": {},
            }
        except Exception as e:
            return {
                "connected": False,
                "status": "OFFLINE",
                "message": f"Connection failed: {e}",
                "dataset_stats": {},
            }

    def get_stats(self) -> Dict[str, Any]:
        """Retrieve HexBrain catalog statistics."""
        try:
            res = self._request("/list_classes")
            if isinstance(res, dict):
                return {
                    "reports_count": res.get("total_reports", 15244),
                    "programs_count": res.get("programs", 428),
                    "vulnerability_classes": len(res.get("classes", [])),
                    "classes": res.get("classes", []),
                }
            return res
        except Exception as e:
            logger.warning("Could not fetch remote HexBrain stats: %s", e)
            return {
                "reports_count": 15244,
                "technique_passages": 1123,
                "vulnerability_classes": 18,
                "weaknesses_count": 215,
                "programs_count": 428,
                "source": "fallback_metadata",
            }

    def search_reports(
        self,
        query: str = "",
        cwe_id: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        technology: Optional[str] = None,
        program: Optional[str] = None,
        limit: int = 10,
        offset: int = 0,
    ) -> List[HexBrainReport]:
        """Search disclosed reports by query terms and facets."""
        search_term = query or vulnerability_type or technology or (cwe_id or "")
        params = {
            "query": search_term,
            "program": program,
            "limit": limit,
            "offset": offset,
        }
        try:
            res = self._request("/search_reports", params=params)
            raw_reports = res.get("reports", []) if isinstance(res, dict) else []
            reports: List[HexBrainReport] = []
            for item in raw_reports:
                # Map HexBrain API report format to canonical HexBrainReport
                rep_id = str(item.get("id", ""))
                title = item.get("title", "Untitled Report")
                url = item.get("url") or f"https://hackerone.com/reports/{rep_id}"
                cwe_candidate = cwe_id or item.get("weakness")
                bounty = float(item.get("bounty_usd") or 0.0)

                rep = HexBrainReport(
                    report_id=f"H1-{rep_id}",
                    title=title,
                    source="hexbrain_api",
                    source_url=url,
                    cwe_id=cwe_candidate,
                    vulnerability_type=item.get("vuln_class") or "generic",
                    severity=item.get("severity") or "unknown",
                    bounty_amount=bounty,
                    program_handle=item.get("program"),
                    program_name=item.get("program"),
                    summary=item.get("weakness") or "",
                    license="h1_disclosed_rag_only",
                    training_eligible=False,
                    metadata=item,
                )
                reports.append(rep)
            return reports
        except Exception as e:
            logger.error("HexBrain search failed: %s", e)
            return []

    def get_testing_playbook(self, topic: str, program: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve real testing playbook, attack features, and chaining patterns."""
        params = {"topic": topic, "program": program}
        try:
            return self._request("/get_testing_playbook", params=params)
        except Exception as e:
            logger.error("HexBrain playbook lookup failed: %s", e)
            return {}

    def get_program_history(self, program: str) -> Dict[str, Any]:
        """Fetch historical program vulnerability profile and class breakdown."""
        params = {"program": program}
        try:
            return self._request("/get_program_history", params=params)
        except Exception as e:
            logger.error("HexBrain program history lookup failed: %s", e)
            return {}

    def get_report(self, report_id: str) -> Optional[HexBrainReport]:
        """Retrieve full write-up and reproduction steps for a specific disclosed report ID."""
        clean_id = report_id.upper().replace("H1-", "").replace("#", "").strip()
        params = {"id": clean_id}
        try:
            res = self._request("/get_report", params=params)
            if not isinstance(res, dict) or "id" not in res:
                return None
            return HexBrainReport(
                report_id=f"H1-{res.get('id')}",
                title=res.get("title", ""),
                source="hexbrain_api",
                source_url=res.get("url") or f"https://hackerone.com/reports/{res.get('id')}",
                cwe_id=res.get("weakness"),
                vulnerability_type=res.get("vuln_class") or "generic",
                severity=res.get("severity") or "unknown",
                bounty_amount=float(res.get("bounty_usd") or 0.0),
                program_handle=res.get("program"),
                program_name=res.get("program"),
                summary=res.get("summary") or res.get("weakness") or "",
                vulnerability_details=res.get("writeup") or "",
                reproduction_steps=res.get("writeup") or "",
                license="h1_disclosed_rag_only",
                training_eligible=False,
                metadata=res,
            )
        except Exception as e:
            logger.error("HexBrain report lookup failed: %s", e)
            return None

    def get_techniques(self, cwe_id: Optional[str] = None, vuln_type: Optional[str] = None) -> List[HexBrainTechnique]:
        """Fetch testing techniques and verification patterns from HexBrain find_payloads/find_bypasses."""
        topic = vuln_type or cwe_id or "generic"
        params = {"topic": topic}
        try:
            res = self._request("/find_payloads", params=params)
            results = res.get("results", []) if isinstance(res, dict) else []
            techniques: List[HexBrainTechnique] = []
            for idx, r in enumerate(results, start=1):
                tech = HexBrainTechnique(
                    technique_id=f"HEX-{topic[:4].upper()}-{idx:03d}",
                    name=r.get("section") or f"{topic} technique",
                    cwe_id=cwe_id,
                    vulnerability_type=topic,
                    description=r.get("text", "")[:400],
                    payload_examples=r.get("payloads", [])[:10],
                    source="hexbrain_api",
                    confidence=1.0,
                    metadata={"source_url": r.get("source_url")},
                )
                techniques.append(tech)
            return techniques
        except Exception as e:
            logger.error("HexBrain technique lookup failed: %s", e)
            return []
