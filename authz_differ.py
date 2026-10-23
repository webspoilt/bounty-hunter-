"""
Authz Differ — replay one request under two roles, diff the responses.
This is the REAL implementation of what ReasonSec faked: actual HTTP,
actual role creds, actual diff. Lab targets only until Phase 5 scope-load.

Verdicts:
    IDENTICAL         -> same bytes both roles: resource may be public (investigate: shared token?)
    ACCESS_CHECKED    -> role B explicitly blocked (401/403 for B): properly enforced
    DIFF_BODY         -> same status, different bodies: check whether B saw A's data
    DIFF_STATUS       -> other status mismatch: manual look
    ERROR             -> request failed; not evidence
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class Credentials:
    """Per-role auth material. Role creds WIN on collision with request template."""
    label: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)   # e.g. Authorization: Bearer tok


@dataclass
class Decision:
    method: str
    url: str
    role_a_status: int
    role_b_status: int
    verdict: str
    notes: str
    body_a_len: int
    body_b_len: int

    def as_payload(self) -> dict:
        return {
            "method": self.method, "url": self.url,
            "role_a_status": self.role_a_status, "role_b_status": self.role_b_status,
            "verdict": self.verdict, "notes": self.notes,
            "body_a_len": self.body_a_len, "body_b_len": self.body_b_len,
        }


def _send(client: httpx.Client, *, method: str, url: str,
          template_headers: dict[str, str] | None, body: Any,
          creds: Credentials, base_cookies: dict[str, str],
          timeout: float = 15.0) -> httpx.Response:
    headers = dict(template_headers or {})
    # role headers override template (case-insensitive delete first)
    lh = {k.lower() for k in creds.headers}
    for k in list(headers):
        if k.lower() in lh:
            del headers[k]
    headers.update(creds.headers)

    cookies = dict(base_cookies or {})
    cookies.update(creds.cookies)

    content: Any = None
    if body is not None:
        content = body if isinstance(body, (bytes, str)) else json_dumps(body)

    return client.request(method=method.upper(), url=url, headers=headers,
                          cookies=cookies, content=content, timeout=timeout)


def _json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj)


def decide(client: httpx.Client, *, method: str, url: str,
           headers: dict[str, str] | None = None, body: Any = None,
           cookies: dict[str, str] | None = None,
           role_a: Credentials, role_b: Credentials,
           timeout: float = 15.0) -> Decision:
    """Replay the same request under both roles and classify the difference."""
    ra = _send(client, method=method, url=url, template_headers=headers, body=body,
               creds=role_a, base_cookies=cookies or {}, timeout=timeout)
    rb = _send(client, method=method, url=url, template_headers=headers, body=body,
               creds=role_b, base_cookies=cookies or {}, timeout=timeout)
    return _classify(method, url, ra, rb)


def _classify(method: str, url: str, ra: httpx.Response, rb: httpx.Response) -> Decision:
    a_status, b_status = ra.status_code, rb.status_code
    ab, bb = ra.content or b"", rb.content or b""
    notes = ""

    if a_status >= 500 or b_status >= 500:
        verdict, notes = "ERROR", "5xx from a role — endpoint unstable, not evidence."
    elif a_status != b_status:
        if a_status < 300 and b_status in (401, 402, 403, 404):
            verdict, notes = "ACCESS_CHECKED", "A granted, B blocked: enforcement working."
        elif a_status < 300 and b_status < 300:
            verdict, notes = "DIFF_STATUS", "Both granted with different codes — inspect content."
        else:
            verdict, notes = "DIFF_STATUS", "Unusual status pair — manual review."
    else:
        same = hashlib.sha256(ab).hexdigest() == hashlib.sha256(bb).hexdigest()
        if same:
            verdict, notes = "IDENTICAL", (
                "Byte-identical for both roles — may be public content "
                "(or a shared/static token). Check for object IDs in URL/body."
            )
        else:
            verdict, notes = "DIFF_BODY", "Same status, different content — compare B's body against A's."

    return Decision(method=method.upper(), url=url, role_a_status=a_status,
                    role_b_status=b_status, verdict=verdict, notes=notes,
                    body_a_len=len(ab), body_b_len=len(bb))
