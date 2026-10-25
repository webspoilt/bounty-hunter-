"""HAR import: turn your own authenticated browsing into a testable inventory.

The HAR is untrusted input. We cap its size, validate UTF-8, strip control characters,
scope-check every URL, redact credentials before persistence, and skip binary bodies.
Import only records observations; it never replays them. Mutating requests belong in a
scenario with `--allow-write`.

`load_har` is the shared, side-effect-free parser used by both the importer and the
scenario proposer.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from bb.config import BODY_CAP
from bb.models import Exchange
from bb.redact import redact_body, redact_headers
from bb.scope import Scope

MAX_HAR_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 50_000
BINARY_MIME = re.compile(r"^(image|font|audio|video)/|octet-stream", re.I)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
TEXT_MIME = re.compile(r"json|xml|text|javascript|x-www-form-urlencoded|graphql", re.I)
ID_PATH = re.compile(r"/\d{1,10}(/|$|\?)")
ID_PARAM = re.compile(r"(^|[?&])(id|user_?id|uid|account_?id|order_?id|item_?id|invoice_?id)=",
                      re.I)


class HarError(RuntimeError):
    pass


@dataclass
class HarEntry:
    index: int
    method: str
    url: str
    status: int
    request_headers: dict[str, str]
    request_body: str
    response_headers: dict[str, str]
    response_body: str
    duration_ms: int


def _clean(text: str) -> str:
    return CONTROL_CHARS.sub("", text or "")


def _decode_body(content: dict) -> str:
    if not isinstance(content, dict):
        return ""
    mime = str(content.get("mimeType") or "")
    if BINARY_MIME.search(mime):
        return ""
    text = content.get("text")
    if not isinstance(text, str):
        return ""
    if content.get("encoding") == "base64":
        try:
            raw = base64.b64decode(text, validate=False)
        except (binascii.Error, ValueError):
            return ""
        if b"\x00" in raw:
            return ""
        text = raw.decode("utf-8", "replace")
    return _clean(text)[:BODY_CAP]


def _headers(items) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name:
            out[name] = str(item.get("value") or "")
    return out


def _request_headers(req: dict) -> dict[str, str]:
    return redact_headers(_headers(req.get("headers")))


def _status(entry: dict) -> int:
    try:
        return int((entry.get("response") or {}).get("status") or 0)
    except (TypeError, ValueError):
        return 0


def _duration(entry: dict) -> int:
    try:
        return int(float(entry.get("time") or 0))
    except (TypeError, ValueError):
        return 0


def count_ids(url: str) -> bool:
    parts = urlsplit(url)
    return bool(ID_PATH.search(parts.path or "/")) or bool(ID_PARAM.search(parts.query or ""))


def load_har(path: str | Path) -> list[HarEntry]:
    """Parse a HAR into redacted entries. No scope checks, no persistence, no network."""
    har_path = Path(path).expanduser().resolve()
    if not har_path.exists():
        raise HarError(f"HAR not found: {har_path}")
    size = har_path.stat().st_size
    if size > MAX_HAR_BYTES:
        raise HarError(f"HAR is {size} bytes; limit is {MAX_HAR_BYTES}")

    text = har_path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HarError(f"invalid HAR JSON: {exc}") from exc
    raw_entries = ((doc.get("log") or {}).get("entries")) if isinstance(doc, dict) else None
    if not isinstance(raw_entries, list):
        raise HarError("not a HAR file: missing log.entries")
    if len(raw_entries) > MAX_ENTRIES:
        raise HarError(f"too many entries ({len(raw_entries)}); limit is {MAX_ENTRIES}")

    entries: list[HarEntry] = []
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            continue
        req = raw.get("request") or {}
        url = _clean(str(req.get("url") or "")).strip()
        if not url.startswith(("http://", "https://")) or re.search(r"[\s\x00-\x1f\x7f]", url):
            continue
        method = str(req.get("method") or "GET").upper()
        if not re.fullmatch(r"[A-Z]{3,10}", method):
            continue
        body = ""
        post = req.get("postData") or {}
        if isinstance(post, dict) and isinstance(post.get("text"), str):
            body = redact_body(_clean(post["text"]), cap=BODY_CAP)
        resp = raw.get("response") or {}
        entries.append(HarEntry(
            index=index, method=method, url=url, status=_status(raw),
            request_headers=_request_headers(req), request_body=body,
            response_headers=redact_headers(_headers(resp.get("headers"))),
            response_body=redact_body(_decode_body(resp.get("content") or {}), cap=BODY_CAP),
            duration_ms=_duration(raw),
        ))
    return entries


def import_har(path: str | Path, scope: Scope, store, run_id: str, log=print) -> dict:
    entries = load_har(path)
    stats = {"entries": len(entries), "in_scope": 0, "denied": 0, "skipped": 0,
             "endpoints": 0, "id_endpoints": 0, "exchanges": 0, "hosts": {},
             "denied_hosts": {}}
    seen_endpoints: set[tuple[str, str]] = set()
    endpoints = []

    for entry in entries:
        decision = scope.check(entry.url)
        host = decision.host or urlsplit(entry.url).hostname or ""
        if not decision.allowed:
            stats["denied"] += 1
            stats["denied_hosts"][host] = stats["denied_hosts"].get(host, 0) + 1
            store.audit_scope(run_id, entry.url, "DENY", decision.reason, host)
            continue

        store.audit_scope(run_id, entry.url, "ALLOW", decision.reason, host)
        stats["in_scope"] += 1
        stats["hosts"][host] = stats["hosts"].get(host, 0) + 1

        ex = Exchange(
            method=entry.method, url=entry.url, status=entry.status,
            request_headers=entry.request_headers, request_body=entry.request_body,
            response_headers=entry.response_headers, response_body=entry.response_body,
            duration_ms=entry.duration_ms, note="HAR import",
        )
        if store.add_exchange(run_id, "har", ex):
            stats["exchanges"] += 1

        key = (entry.method, entry.url)
        if key not in seen_endpoints:
            seen_endpoints.add(key)
            params = sorted(parse_qs(urlsplit(entry.url).query).keys())
            store.add_endpoint(run_id, entry.url, method=entry.method, host=host,
                               path=urlsplit(entry.url).path or "/", source="har",
                               params=params)
            endpoints.append({"method": entry.method, "url": entry.url,
                              "id_bearing": count_ids(entry.url)})
            stats["endpoints"] += 1
            if count_ids(entry.url):
                stats["id_endpoints"] += 1

        parts = urlsplit(entry.url)
        store.add_asset(run_id, host, f"{parts.scheme}://{parts.netloc}", ex.status,
                        ex.response_headers.get("Server", ""), source="har")

    stats["endpoint_list"] = endpoints
    log(f"  [har] {stats['entries']} entries: {stats['in_scope']} in scope, "
        f"{stats['denied']} denied, {stats['endpoints']} endpoints "
        f"({stats['id_endpoints']} id-bearing)")
    if stats["denied_hosts"]:
        top = sorted(stats["denied_hosts"].items(), key=lambda kv: -kv[1])[:5]
        log("  [har] top denied hosts: " + ", ".join(f"{h} ({n})" for h, n in top))
    return stats
