"""Redaction: evidence must prove impact without leaking secrets or third-party PII.

Order of operations in the pipeline: capture -> redact -> store -> report. Reports are
built only from redacted evidence, so a leaked token cannot reach a markdown file.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlencode, urlsplit, urlunsplit

SECRET_KEYS = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|apikey|authorization|cookie|session|csrf|"
    r"otp|totp|private[_-]?key|client[_-]?secret|access[_-]?key|refresh|signature)",
    re.I,
)
SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "proxy-authorization",
}
QUERY_SECRETS = re.compile(r"^(access_token|token|api_key|apikey|key|secret|password|sig|signature|code)$", re.I)

_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-+/=]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
_KV = re.compile(r"(?i)\b(token|password|passwd|secret|api[_-]?key|session|csrf)=([^&\s\"'<>]+)")
_LONG_HEX = re.compile(r"\b[a-f0-9]{32,}\b", re.I)

MASK = "[REDACTED]"


def _mask_value(value) -> str:
    if isinstance(value, str) and value:
        return MASK
    return MASK


def redact_json(obj):
    """Recursively mask values under secret-looking keys."""
    if isinstance(obj, dict):
        return {
            k: (_mask_value(v) if SECRET_KEYS.search(k) and not isinstance(v, (dict, list))
                else redact_json(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_json(v) for v in obj]
    return obj


def redact_body(body: str, cap: int | None = None) -> str:
    if not body:
        return ""
    text = body
    try:
        parsed = json.loads(body)
        if isinstance(parsed, (dict, list)):
            text = json.dumps(redact_json(parsed), indent=2, default=str)
    except Exception:
        text = _BEARER.sub(r"\1" + MASK, text)
        text = _JWT.sub(MASK, text)
        text = _KV.sub(lambda m: f"{m.group(1)}={MASK}", text)
    # always apply the cheap text patterns (JSON may have embedded strings)
    text = _BEARER.sub(r"\1" + MASK, text)
    text = _JWT.sub(MASK, text)
    if cap is not None and len(text) > cap:
        text = text[:cap] + f"\n… [truncated, {len(text)} bytes total]"
    return text


def redact_headers(headers: dict[str, str] | None, cap_values: int = 400) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        if k.lower() in SENSITIVE_HEADERS or SECRET_KEYS.search(k):
            out[k] = MASK
        else:
            v = str(v)
            out[k] = v[:cap_values] + ("…" if len(v) > cap_values else "")
    return out


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except Exception:
        return url
    if not parts.query:
        return url
    pairs = []
    changed = False
    for pair in parts.query.split("&"):
        k, _, v = pair.partition("=")
        if QUERY_SECRETS.match(k):
            pairs.append(f"{k}={MASK}")
            changed = True
        else:
            pairs.append(pair)
    if not changed:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(pairs), parts.fragment))


def looks_like_pii(text: str) -> bool:
    return bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text or ""))
