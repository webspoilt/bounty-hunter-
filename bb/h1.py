"""HackerOne integration: import real program scope; prepare (never send) a submission.

Scope import is the important half: a hand-edited JSON file goes stale, and testing an
asset the program removed is the fastest way to get banned. `bb scope import --from h1`
records the API response fingerprint and timestamp next to the rules.

Submission is deliberately manual. `submit_payload` + `submit_curl` print a ready request
for you to run after review; this tool never POSTs a report by itself.
"""
from __future__ import annotations

import base64
import json

import httpx

from bb.config import H1_API, H1_TOKEN, H1_USERNAME
from bb.models import Finding
from bb.scope import Scope


class H1Error(RuntimeError):
    pass


class H1Client:
    def __init__(self, username: str = H1_USERNAME, token: str = H1_TOKEN,
                 timeout: float = 30.0):
        if not username or not token:
            raise H1Error("set H1_USERNAME and H1_TOKEN (API token from hackerone.com/settings/api_token)")
        self.auth = (username, token)
        self.timeout = timeout

    def _get(self, path: str, **params) -> dict:
        try:
            r = httpx.get(f"{H1_API}{path}", auth=self.auth, params=params, timeout=self.timeout,
                          headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise H1Error(f"HackerOne API unreachable: {exc}") from exc
        if r.status_code == 401:
            raise H1Error("HackerOne rejected the credentials (401) — check H1_USERNAME/H1_TOKEN")
        if r.status_code == 403:
            raise H1Error("HackerOne refused access (403) — join the program or check token scopes")
        if r.status_code == 404:
            raise H1Error(f"program not found (404) at {path}")
        if r.status_code >= 400:
            raise H1Error(f"HackerOne API {path}: HTTP {r.status_code} {r.text[:200]}")
        return r.json()

    def programs(self) -> list[dict]:
        data = self._get("/hackers/programs", **{"page[size]": 100})
        return data.get("data", [])

    def program(self, handle: str) -> dict:
        """Try the hacker-scoped endpoint first (includes structured scope)."""
        last: Exception | None = None
        for path in (f"/hackers/programs/{handle}", f"/programs/{handle}"):
            try:
                return self._get(path)
            except H1Error as exc:
                last = exc
        raise H1Error(f"could not load program {handle!r}: {last}")

    def scope(self, handle: str) -> Scope:
        payload = self.program(handle)
        data = payload.get("data", {})
        rel = (data.get("relationships") or {}).get("structured_scopes") or {}
        entries = [item.get("attributes", {}) for item in (rel.get("data") or [])]
        if not entries:
            raise H1Error(
                f"program {handle!r} returned no structured scopes. The public API only exposes "
                "scope for programs you have joined. Add the scope manually instead:\n"
                f"  bb scope import --program {handle} --from file data/scopes/{handle}.json")
        attrs = data.get("attributes") or {}
        scope = Scope.from_h1_structured(handle, entries)
        scope.imported_at = attrs.get("updated_at") or scope.imported_at
        return scope


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
