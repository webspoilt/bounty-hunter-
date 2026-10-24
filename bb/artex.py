"""ARTEX bridge (optional). ARTEX is the dashboard/evidence store already running locally.

We push rather than pull: assets into an ARTEX task, and the exact captured exchanges into
ARTEX traffic so its timeline/search shows the same evidence this tool reports on.
Fire-and-forget: if ARTEX is down or has no token, the pipeline is unaffected.
"""
from __future__ import annotations

import json

import httpx

from bb.config import ARTEX_TOKEN, ARTEX_URL
from bb.models import Exchange, Finding


class ArtexError(RuntimeError):
    pass


class Artex:
    def __init__(self, url: str = ARTEX_URL, token: str = ARTEX_TOKEN, timeout: float = 20.0):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _request(self, method: str, path: str, payload: dict | None = None):
        try:
            r = httpx.request(method, f"{self.url}{path}", headers=self._headers(),
                              json=payload, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise ArtexError(f"ARTEX unreachable at {self.url}: {exc}") from exc
        if r.status_code >= 400:
            hint = "" if self.token else " (set ARTEX_TOKEN — ARTEX → Settings → API token)"
            raise ArtexError(f"ARTEX {method} {path}: HTTP {r.status_code} {r.text[:200]}{hint}")
        try:
            return r.json()
        except Exception:
            return {"status": r.status_code}

    # ---------- reads ----------

    def health(self) -> dict:
        try:
            r = httpx.get(f"{self.url}/api/health", timeout=5.0)
            ok = r.status_code < 500
        except httpx.HTTPError:
            ok = False
        return {"url": self.url, "reachable": ok, "token": bool(self.token)}

    def tasks(self) -> list[dict]:
        data = self._request("GET", "/api/tasks")
        return data if isinstance(data, list) else data.get("tasks", data.get("data", []))

    # ---------- writes ----------

    def create_task(self, description: str, goal: str) -> dict:
        """Create an ARTEX agent task. Use for deep, human-supervised runs only."""
        return self._request("POST", "/api/tasks", {"description": description, "goal": goal})

    def push_assets(self, task_id: int, assets: list[dict]) -> dict:
        payload = {"task_id": task_id, "assets": []}
        for a in assets:
            if a.get("url"):
                payload["assets"].append({
                    "type": "web",
                    "url": a["url"],
                    "status_code": a.get("status"),
                    "page_title": (a.get("title") or "")[:200],
                    "technologies": a.get("tech") or [],
                })
            elif a.get("host"):
                payload["assets"].append({"type": "domain", "domain": a["host"]})
        if not payload["assets"]:
            return {"skipped": "no assets"}
        return self._request("POST", "/api/assets", payload)

    def ingest_traffic(self, exchanges: list[Exchange]) -> dict:
        payload = {"exchanges": [{
            "method": ex.method,
            "url": ex.url,
            "status": ex.status,
            "requestHeaders": ex.request_headers,
            "requestBody": ex.request_body,
            "responseHeaders": ex.response_headers,
            "responseBody": ex.response_body,
        } for ex in exchanges]}
        if not payload["exchanges"]:
            return {"skipped": "no exchanges"}
        return self._request("POST", "/api/traffic/ingest", payload)

    def push_finding(self, finding: Finding) -> dict:
        """Attach the finding as an ARTEX task goal note (ARTEX has no public finding-create API)."""
        goal = (f"[bountybot] {finding.title}\n\n{finding.summary}\n\n"
                f"Asset: {finding.url}\nSeverity: {finding.severity}\n"
                f"Evidence and report: data/reports/{finding.id}/")
        return self.create_task(description=f"bountybot finding {finding.id}", goal=goal)
