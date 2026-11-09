"""Burp Suite Export and Compatibility Utilities.

Supports exporting Bounty Hunter exchanges, candidate findings, and verification
evidence into Burp Suite XML format for manual inspection, replay, and repeater analysis.
Retains explicit references between:
- Investigation ID
- Hypothesis ID
- Task fingerprint
- HTTP exchange
- Candidate finding
- Verification result
"""
from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

from bb.config import now_iso
from bb.models import Exchange, Finding


def _format_http_request(ex: Exchange) -> bytes:
    """Reconstruct raw HTTP request bytes from an Exchange."""
    parts = urlsplit(ex.url)
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    host = parts.netloc or parts.hostname or ""

    lines = [f"{ex.method.upper()} {path} HTTP/1.1"]
    headers = dict(ex.request_headers or {})
    if "Host" not in headers and "host" not in headers:
        lines.append(f"Host: {host}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    header_block = "\r\n".join(lines) + "\r\n"
    body_bytes = (ex.request_body or "").encode("utf-8")
    return header_block.encode("utf-8") + body_bytes


def _format_http_response(ex: Exchange) -> bytes:
    """Reconstruct raw HTTP response bytes from an Exchange."""
    lines = [f"HTTP/1.1 {ex.status} OK"]
    headers = dict(ex.response_headers or {})
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    header_block = "\r\n".join(lines) + "\r\n"
    body_bytes = (ex.response_body or "").encode("utf-8")
    return header_block.encode("utf-8") + body_bytes


def export_exchanges_to_burp_xml(
    exchanges: Sequence[Exchange | dict[str, Any]],
    output_path: str | Path | None = None,
    comment_prefix: str = "BountyHunter",
) -> str:
    """Exports exchanges into standard Burp Suite XML item format.

    Compatible with Burp Suite Repeater, Intruder, and Target site map.
    """
    root = ET.Element("items")
    root.set("burpVersion", "2024.1")
    root.set("exportTime", now_iso())

    for idx, item in enumerate(exchanges):
        if isinstance(item, dict):
            ex = Exchange.from_dict(item)
            ref_info = item.get("ref_info") or {}
        else:
            ex = item
            ref_info = getattr(ex, "ref_info", {}) or {}

        parts = urlsplit(ex.url)
        protocol = parts.scheme or "https"
        host = parts.hostname or ""
        port = str(parts.port or (443 if protocol == "https" else 80))
        path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")

        elem = ET.SubElement(root, "item")
        ET.SubElement(elem, "time").text = ex.at
        ET.SubElement(elem, "url").text = ex.url
        ET.SubElement(elem, "host", ip="").text = host
        ET.SubElement(elem, "port").text = port
        ET.SubElement(elem, "protocol").text = protocol
        ET.SubElement(elem, "method").text = ex.method.upper()
        ET.SubElement(elem, "path").text = path
        ET.SubElement(elem, "status").text = str(ex.status)

        # Linked provenance comment
        comment_parts = [comment_prefix]
        if ref_info.get("investigation_id"):
            comment_parts.append(f"inv:{ref_info['investigation_id']}")
        if ref_info.get("hypothesis_id"):
            comment_parts.append(f"hypo:{ref_info['hypothesis_id']}")
        if ref_info.get("finding_id"):
            comment_parts.append(f"finding:{ref_info['finding_id']}")
        if ref_info.get("verification_status"):
            comment_parts.append(f"verif:{ref_info['verification_status']}")
        if ex.note:
            comment_parts.append(ex.note)

        ET.SubElement(elem, "comment").text = " | ".join(comment_parts)

        # Base64 request
        raw_req = _format_http_request(ex)
        req_b64 = base64.b64encode(raw_req).decode("ascii")
        req_el = ET.SubElement(elem, "request", base64="true")
        req_el.text = req_b64

        # Base64 response
        raw_resp = _format_http_response(ex)
        resp_b64 = base64.b64encode(raw_resp).decode("ascii")
        resp_el = ET.SubElement(elem, "response", base64="true")
        resp_el.text = resp_b64

    xml_text = ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(xml_text, encoding="utf-8")
    return xml_text


def export_finding_to_burp(
    finding: Finding,
    output_path: str | Path | None = None,
    investigation_id: str | None = None,
) -> str:
    """Exports all evidence exchanges of a candidate finding to Burp XML with full links."""
    items = []
    verif_status = finding.meta.get("verify", {}).get("verdict") if finding.meta.get("verify") else finding.status
    for ev in finding.evidence:
        if ev.exchange:
            item_dict = ev.exchange.to_dict()
            item_dict["ref_info"] = {
                "investigation_id": investigation_id or finding.meta.get("investigation_id"),
                "hypothesis_id": finding.meta.get("hypothesis_id"),
                "finding_id": finding.id,
                "verification_status": verif_status,
            }
            items.append(item_dict)

    prefix = f"BountyHunter [{finding.bug_class}] ({finding.status})"
    return export_exchanges_to_burp_xml(items, output_path=output_path, comment_prefix=prefix)
