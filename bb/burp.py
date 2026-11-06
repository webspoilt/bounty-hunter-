"""Burp Suite item export import ("Save selected items" XML).

Same contract as the HAR importer: the file is untrusted input, values are decoded
carefully, every URL is scope-checked, credentials are redacted before persistence,
and import only records observations — it never replays a request. Mutating requests
belong in a scenario with `--allow-write`.

Accepted shapes: Burp's `<items><item>...</item></items>` XML with `<url>` (or
`<protocol>/<host>/<port>/<path>`), `<method>`, `<status>`, and optional base64
`<request>` / `<response>` CDATA bodies.
"""
from __future__ import annotations

import base64
import binascii
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from bb.config import BODY_CAP
from bb.har import count_ids, CONTROL_CHARS
from bb.models import Exchange
from bb.redact import redact_body, redact_headers
from bb.scope import Scope

MAX_BURP_BYTES = 128 * 1024 * 1024
MAX_ITEMS = 50_000
METHOD_RE = re.compile(r"[A-Z]{3,10}")


class BurpError(RuntimeError):
    pass


def _dec(elem, attr_base64: bool) -> str:
    """Decode an element's text; honor Burp's base64="true" attribute, reject binary."""
    if elem is None:
        return ""
    text = elem.text or ""
    if attr_base64:
        try:
            raw = base64.b64decode("".join(text.split()), validate=False)
        except (binascii.Error, ValueError):
            return ""
        if b"\x00" in raw:
            return ""
        return CONTROL_CHARS.sub("", raw.decode("utf-8", "replace"))[:BODY_CAP]
    return CONTROL_CHARS.sub("", text)[:BODY_CAP]


def _attr_base64(elem) -> bool:
    return (elem.get("base64", "").lower() in ("true", "1")) if elem is not None else False


def _split_http(raw: str) -> tuple[dict[str, str], str]:
    """Split a raw HTTP message into (redacted headers, redacted body)."""
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""
    headers: dict[str, str] = {}
    for line in head.splitlines()[1:]:            # [1:] skips the request/status line
        if ":" in line:
            name, _, value = line.partition(":")
            if name.strip():
                headers[name.strip()] = value.strip()
    return redact_headers(headers), redact_body(body, cap=BODY_CAP)


def _item_url(item) -> str:
    url = (item.findtext("url") or "").strip()
    if url.startswith(("http://", "https://")):
        return url
    protocol = (item.findtext("protocol") or "").strip().lower()
    host_el = item.find("host")
    host = (host_el.text or "").strip() if host_el is not None else ""
    port = (item.findtext("port") or "").strip()
    path = (item.findtext("path") or "/").strip()
    if protocol not in ("http", "https") or not host:
        return ""
    if (protocol == "https" and port == "443") or (protocol == "http" and port == "80"):
        port_part = ""
    else:
        port_part = f":{port}" if port.isdigit() else ""
    return f"{protocol}://{host}{port_part}{path}"


def load_burp(path: str | Path, log=print) -> list[dict]:
    """Parse a Burp item-export XML into redacted entry dicts. No scope, no persistence."""
    burp_path = Path(path).expanduser().resolve()
    if not burp_path.exists():
        raise BurpError(f"Burp export not found: {burp_path}")
    size = burp_path.stat().st_size
    if size > MAX_BURP_BYTES:
        raise BurpError(f"Burp export is {size} bytes; limit is {MAX_BURP_BYTES}")

    entries: list[dict] = []
    seen = 0
    try:
        events = ET.iterparse(burp_path, events=("end",))
        for event, elem in events:
            if elem.tag != "item":
                continue
            seen += 1
            entries.append(_parse_item(elem))
            elem.clear()
            if seen > MAX_ITEMS:
                raise BurpError(f"too many items (>{MAX_ITEMS})")
    except ET.ParseError as exc:
        raise BurpError(f"invalid Burp XML: {exc}") from exc
    return [e for e in entries if e is not None]


def _parse_item(item) -> dict | None:
    url = _item_url(item)
    if not url.startswith(("http://", "https://")) or re.search(r"\s", url):
        return None
    method = (item.findtext("method") or "GET").upper()
    if not METHOD_RE.fullmatch(method):
        return None
    req_elem = item.find("request")
    resp_elem = item.find("response")
    try:
        status = int((item.findtext("status") or "0").strip())
    except ValueError:
        status = 0
    req_headers, req_body = _split_http(_dec(req_elem, _attr_base64(req_elem)))
    resp_headers, resp_body = _split_http(_dec(resp_elem, _attr_base64(resp_elem)))
    return {"method": method, "url": url, "status": status,
            "request_headers": req_headers, "request_body": req_body,
            "response_headers": resp_headers, "response_body": resp_body}


def import_burp(path: str | Path, scope: Scope, store, run_id: str, log=print) -> dict:
    entries = load_burp(path, log=log)
    stats = {"entries": len(entries), "in_scope": 0, "denied": 0, "skipped": 0,
             "endpoints": 0, "id_endpoints": 0, "exchanges": 0, "hosts": {},
             "denied_hosts": {}}
    seen_endpoints: set[tuple[str, str]] = set()
    endpoints = []

    for entry in entries:
        decision = scope.check(entry["url"])
        host = decision.host or urlsplit(entry["url"]).hostname or ""
        if not decision.allowed:
            stats["denied"] += 1
            stats["denied_hosts"][host] = stats["denied_hosts"].get(host, 0) + 1
            store.audit_scope(run_id, entry["url"], "DENY", decision.reason, host)
            continue

        store.audit_scope(run_id, entry["url"], "ALLOW", decision.reason, host)
        stats["in_scope"] += 1
        stats["hosts"][host] = stats["hosts"].get(host, 0) + 1

        ex = Exchange(method=entry["method"], url=entry["url"], status=entry["status"],
                      request_headers=entry["request_headers"],
                      request_body=entry["request_body"],
                      response_headers=entry["response_headers"],
                      response_body=entry["response_body"], note="Burp import")
        if store.add_exchange(run_id, "burp", ex):
            stats["exchanges"] += 1

        key = (entry["method"], entry["url"])
        if key not in seen_endpoints:
            seen_endpoints.add(key)
            params = sorted(parse_qs(urlsplit(entry["url"]).query).keys())
            store.add_endpoint(run_id, entry["url"], method=entry["method"], host=host,
                               path=urlsplit(entry["url"]).path or "/", source="burp",
                               params=params)
            endpoints.append({"method": entry["method"], "url": entry["url"],
                              "id_bearing": count_ids(entry["url"])})
            stats["endpoints"] += 1
            if count_ids(entry["url"]):
                stats["id_endpoints"] += 1

        parts = urlsplit(entry["url"])
        store.add_asset(run_id, host, f"{parts.scheme}://{parts.netloc}", ex.status,
                        source="burp")

    stats["endpoint_list"] = endpoints
    log(f"  [burp] {stats['entries']} items: {stats['in_scope']} in scope, "
        f"{stats['denied']} denied, {stats['endpoints']} endpoints "
        f"({stats['id_endpoints']} id-bearing)")
    if stats["denied_hosts"]:
        top = sorted(stats["denied_hosts"].items(), key=lambda kv: -kv[1])[:5]
        log("  [burp] top denied hosts: " + ", ".join(f"{h} ({n})" for h, n in top))
    return stats


def summary_line(stats: dict) -> str:
    return (f"{stats['endpoints']} endpoints ({stats['id_endpoints']} id-bearing), "
            f"{stats['exchanges']} exchanges, {stats['denied']} denied")
