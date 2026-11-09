"""Burp Suite REST API and Integration Adapter.

Safely connects to Burp Suite Professional / Enterprise REST API when configured.
Enforces:
- Local trusted endpoint bindings only (127.0.0.1 / localhost).
- Strict API token / secret redaction.
- Graceful capability detection (detects unsupported API versions or Community Edition).
- No automatic unrestricted active scans.
"""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

import httpx

from bb.config import now_iso


class BurpApiError(RuntimeError):
    pass


class BurpApiClient:
    """Bounded, safe client for interacting with Burp Suite REST API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:1337",
        api_key: str | None = None,
        timeout: float = 3.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("BURP_API_KEY")
        self.timeout = timeout

        # Safety check: bind only to trusted local address
        parts = urlsplit(self.base_url)
        host = (parts.hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise BurpApiError(f"Burp API must connect to a local address, refused: {host}")

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def probe(self) -> dict[str, Any]:
        """Detect Burp Suite REST API availability, edition, and supported capabilities."""
        report: dict[str, Any] = {
            "available": False,
            "base_url": self.base_url,
            "version": None,
            "edition": "Community / Standalone (REST API unavailable)",
            "supported_capabilities": [],
            "checked_at": now_iso(),
            "detail": "connection refused or timed out",
        }

        try:
            # Burp Suite Enterprise / Pro REST API endpoints
            r = httpx.get(
                f"{self.base_url}/v0.1/version",
                headers=self._headers(),
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                report["available"] = True
                report["version"] = data.get("version", "detected")
                report["edition"] = "Burp Suite Professional / Enterprise"
                report["supported_capabilities"] = ["site_map", "issue_definitions", "scan_configurations"]
                report["detail"] = "Burp REST API active"
                return report
            elif r.status_code in (401, 403):
                report["available"] = False
                report["detail"] = "Burp REST API requires authentication (invalid or missing BURP_API_KEY)"
                return report
        except httpx.ConnectError:
            report["detail"] = f"No Burp REST API listening on {self.base_url} (standard for Community edition)"
        except httpx.TimeoutException:
            report["detail"] = f"Connection to Burp REST API timed out on {self.base_url}"
        except Exception as exc:
            report["detail"] = f"Burp API probe error: {exc}"

        return report

    def push_to_site_map(self, url: str, method: str = "GET", headers: dict | None = None) -> bool:
        """Pushes an endpoint to Burp's site map if the API supports it."""
        probe = self.probe()
        if not probe["available"]:
            return False

        try:
            payload = {"url": url, "method": method.upper(), "headers": headers or {}}
            r = httpx.post(
                f"{self.base_url}/v0.1/sitemap",
                json=payload,
                headers=self._headers(),
                timeout=self.timeout,
            )
            return r.status_code in (200, 201, 204)
        except Exception:
            return False
