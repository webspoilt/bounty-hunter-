"""WAF resilience probe — map normalization, do not exploit.

What this does: sends one harmless, unique canary plus a small set of *encoding
variants* of that canary to one parameter, over GET only, inside scope, under the
same rate/budget/kill-switch rules as every other request. It reports which variants
the edge blocked and which it let through. That is defensive reconnaissance: it tells
you whether a WAF is inspecting this parameter and where its normalization is
inconsistent.

What this deliberately does NOT do: generate exploit payloads, mutate state, brute
force, rotate proxies, or keep retrying a blocked request. There is no SQL injection,
no XSS execution, no command injection, and no authentication bypass here — only
structural encodings of a random marker. Anything beyond mapping belongs in a
human-reviewed scenario, after reading the program's rules.

A "bypass candidate" in the output means: the edge treated an encoded canary
differently from the plain one. It is a lead to review, not a vulnerability claim.
"""
from __future__ import annotations

import json
import re
import secrets
from urllib.parse import parse_qsl, quote, urlsplit

from bb.http import ScopedClient

BLOCK_STATUS = {403, 406, 409, 418, 429, 501, 503}
BLOCK_BODY = re.compile(
    r"(access denied|request blocked|request rejected|attention required|"
    r"web application firewall|mod_security|incapsula|sucuri|cloudflare|"
    r"akamai|imperva|not acceptable|security policy)", re.I)
WAF_HEADERS = {
    "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri", "x-sucuri-cache": "Sucuri",
    "x-akamai-transformed": "Akamai", "x-akamai-request-id": "Akamai",
    "x-amzn-requestid": "AWS", "x-amz-cf-id": "CloudFront",
    "x-waf-event-info": "F5", "x-waf-request-id": "F5",
    "x-powered-by-plesk": "Plesk", "x-iinfo": "Imperva",
}
SERVER_HINTS = {"cloudflare": "Cloudflare", "sucuri": "Sucuri", "akamai": "Akamai",
                "imperva": "Imperva", "incapsula": "Imperva", "barracuda": "Barracuda",
                "f5": "F5", "big-ip": "F5", "mod_security": "ModSecurity",
                "awselb": "AWS", "cloudfront": "CloudFront"}
MAX_VARIANTS = 24


def canary() -> str:
    return "bbwaf" + secrets.token_hex(4)


def variants(marker: str) -> list[dict]:
    """Structural encodings of the same harmless marker. No exploit syntax."""
    encoded = "".join(f"%{ord(c):02x}" if c.isalnum() else quote(c) for c in marker)
    double = encoded.replace("%", "%25")
    utf16 = "".join(f"%u{ord(c):04x}" for c in marker)
    return [
        {"name": "plain", "value": marker,
         "why": "baseline: unencoded marker"},
        {"name": "upper", "value": marker.upper(),
         "why": "case folding"},
        {"name": "url-encoded", "value": encoded,
         "why": "percent-encoded marker"},
        {"name": "double-encoded", "value": double,
         "why": "percent sign encoded again (%25)"},
        {"name": "utf16-encoded", "value": utf16,
         "why": "legacy %uXXXX encoding"},
        {"name": "encoded-angle", "value": f"%3C{marker}%3E",
         "why": "HTML delimiters, encoded"},
        {"name": "encoded-quote", "value": f"%27{marker}",
         "why": "single quote, encoded"},
        {"name": "comment-split", "value": f"{marker}/**/x",
         "why": "comment separators"},
        {"name": "newline", "value": f"{marker}%0a",
         "why": "line-feed suffix"},
        {"name": "tab", "value": f"{marker}%09",
         "why": "tab suffix"},
    ][:MAX_VARIANTS]


def detect_waf(response) -> list[str]:
    """Best-effort vendor names from headers/body/status. Observation only."""
    found: set[str] = set()
    headers = {k.lower(): v for k, v in (response.headers or {}).items()}
    for header, vendor in WAF_HEADERS.items():
        if header in headers:
            found.add(vendor)
    server = headers.get("server", "").lower()
    for hint, vendor in SERVER_HINTS.items():
        if hint in server:
            found.add(vendor)
    try:
        body = (response.text or "")[:4000]
    except Exception:
        body = ""
    low = body.lower()
    for hint, vendor in SERVER_HINTS.items():
        if hint in low:
            found.add(vendor)
    if BLOCK_BODY.search(body):
        found.add("block-page")
    return sorted(found)


def _set_param(url: str, param: str, raw_value: str) -> str:
    """Replace one query parameter with a raw (pre-encoded) value, keeping the rest."""
    parts = urlsplit(url)
    base = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != param]
    encoded = [f"{quote(k)}={quote(v)}" for k, v in pairs]
    encoded.append(f"{quote(param)}={raw_value}")
    return base + "?" + "&".join(encoded)


def _blocked(response, waf: list[str]) -> bool:
    if response.status_code in BLOCK_STATUS:
        return True
    try:
        body = response.text or ""
    except Exception:
        body = ""
    return bool(BLOCK_BODY.search(body) or "block-page" in waf)


def probe(client: ScopedClient, url: str, param: str = "q", *,
          max_requests: int = 20, log=print) -> dict:
    """Send baseline + variants over GET; compare status/size. Never writes."""
    marker = canary()
    plan = variants(marker)[:max(1, min(max_requests - 1, MAX_VARIANTS))]
    results: list[dict] = []
    baseline: dict | None = None
    vendors: set[str] = set()

    for item in plan:
        target = _set_param(url, param, item["value"])
        try:
            response = client.get(target)
        except Exception as exc:                          # noqa: BLE001 — one probe must not stop the scan
            results.append({"name": item["name"], "status": 0, "error": str(exc),
                            "why": item["why"]})
            continue
        waf = detect_waf(response)
        vendors.update(waf)
        blocked = _blocked(response, waf)
        try:
            length = len(response.content)
        except Exception:
            length = len(response.text or "")
        record = {"name": item["name"], "status": response.status_code,
                  "length": length, "blocked": blocked, "waf": waf,
                  "url": _set_param(url, param, item["value"]),
                  "why": item["why"]}
        results.append(record)
        if item["name"] == "plain":
            baseline = record
        log(f"  [waf] {item['name']:16} {response.status_code} "
            f"{'BLOCKED' if blocked else 'allowed'}  ({item['why']})")

    baseline_blocked = bool(baseline and baseline.get("blocked"))
    comparisons = []
    for record in results:
        if record["name"] == "plain" or record["status"] == 0:
            continue
        comparisons.append({
            "name": record["name"],
            "status": record["status"],
            "length": record["length"],
            "blocked": record["blocked"],
            "changed_status": bool(baseline and record["status"] != baseline["status"]),
            "length_delta": (record["length"] - baseline["length"]) if baseline else None,
            "why": record["why"],
        })
    bypass_candidates = [
        c["name"] for c in comparisons
        if baseline and not baseline_blocked and c["status"] == baseline["status"]
        and not c["blocked"] and c["name"] not in ("plain", "upper")
    ]
    blocked_variants = [c["name"] for c in comparisons if c["blocked"]]
    return {
        "url": url,
        "param": param,
        "marker": marker,
        "waf_detected": sorted(vendors),
        "baseline": baseline,
        "variants": comparisons,
        "blocked_variants": blocked_variants,
        "bypass_candidates": bypass_candidates,
        "requests": len([r for r in results if r["status"]]),
        "note": ("encoding differences are a normalization lead, not an exploit; "
                 "review manually and stay inside the program's rules"),
    }


def format_probe(result: dict) -> str:
    lines = [f"WAF probe: {result['url']}  (param {result['param']!r})",
             f"detected: {', '.join(result['waf_detected']) or 'no known WAF signature'}",
             f"baseline: HTTP {result['baseline']['status']} "
             f"({result['baseline']['length']} bytes) "
             f"{'BLOCKED' if result['baseline']['blocked'] else 'allowed'}"
             if result.get("baseline") else "baseline: no response",
             "", f"{'variant':18} {'status':>6} {'bytes':>7}  result"]
    for v in result["variants"]:
        verdict = "blocked" if v["blocked"] else (
            "same as baseline" if not v["changed_status"] else "different response")
        lines.append(f"{v['name']:18} {v['status']:>6} {v['length']:>7}  {verdict}")
    if result["blocked_variants"]:
        lines.append("\nblocked variants: " + ", ".join(result["blocked_variants"]))
    if result["bypass_candidates"]:
        lines.append("normalization leads (review, do not treat as a finding): "
                     + ", ".join(result["bypass_candidates"]))
    lines.append("\n" + result["note"])
    return "\n".join(lines)


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2)
