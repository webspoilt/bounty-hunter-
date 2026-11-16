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

from bb.intel.hexbrain_models import HexBrainReport, HexBrainTechnique
from bb.intel.hexbrain_cache import HexBrainCache

logger = logging.getLogger(__name__)

DEFAULT_HEXBRAIN_BASE = "https://api.hexbrain.io/v1"


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
        self.api_key = api_key or os.getenv("HEXBRAIN_API_KEY", "")
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
            res = self._request("/health", use_cache=False)
            res = self._request("/stats", use_cache=False)
            stats = res.get("data", res) if isinstance(res, dict) else {}
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
            res = self._request("/stats")
            return res.get("data", res)
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
        params = {
            "q": query,
            "cwe_id": cwe_id,
            "vuln_type": vulnerability_type,
            "tech": technology,
            "program": program,
            "limit": limit,
            "offset": offset,
        }
        try:
            res = self._request("/reports/search", params=params)
            items = res.get("data", [])
            reports: List[HexBrainReport] = []
            for item in items:
                reports.append(HexBrainReport.from_dict(item))
            return reports
        except Exception as e:
            logger.error("HexBrain search failed: %s", e)
            return []

    def get_techniques(self, cwe_id: Optional[str] = None, vuln_type: Optional[str] = None) -> List[HexBrainTechnique]:
        """Fetch testing techniques and verification patterns."""
        params = {"cwe_id": cwe_id, "vuln_type": vuln_type}
        try:
            res = self._request("/techniques", params=params)
            items = res.get("data", [])
            return [HexBrainTechnique.from_dict(it) for it in items]
        except Exception as e:
            logger.error("HexBrain technique lookup failed: %s", e)
            return []
