"""Offline CVE / CISA-KEV knowledge base.

Bug-bounty triage needs one question answered fast: *does the technology this asset
runs have a known, exploited vulnerability?* This module answers it from local files
only. Nothing here fetches NVD or KEV over the network; you export the JSON once and
import it, which keeps the tool usable offline and keeps scope/traffic promises intact.

Accepted inputs (auto-detected):

  * NVD 2.0 JSON      ``{"vulnerabilities": [{"cve": {...}}]}``
  * CISA KEV JSON     ``{"vulnerabilities": [{"cveID": ..., "product": ...}]}``
  * a simple list     ``[{"id": "CVE-...", "products": ["nginx 1.18"], ...}]``

The index is a small JSON document (``data/cve.json``) so it can be reviewed, diffed,
and shipped between machines. Queries are lexical and deterministic; no embeddings and
no model are required.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from bb.config import DATA, now_iso

CVE_PATH = Path(os.environ.get("BB_CVE_INDEX", DATA / "cve.json"))
MAX_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 400_000
CPE_RE = re.compile(r"cpe:2\.3:[aho]:([^:]+):([^:]+):([^:]*):")
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{1,40}")
STOP = {"the", "and", "for", "with", "that", "this", "from", "allows", "via", "which",
        "vulnerability", "versions", "before", "after", "remote", "attacker"}


class CveError(RuntimeError):
    pass


def _tokens(text: str) -> set[str]:
    return {t for t in TOKEN_RE.findall((text or "").lower()) if t not in STOP and len(t) > 2}


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def _first_description(cve: dict) -> str:
    for d in _as_list(cve.get("descriptions")):
        if isinstance(d, dict) and d.get("lang") == "en" and d.get("value"):
            return str(d["value"])
    for d in _as_list(cve.get("descriptions")):
        if isinstance(d, dict) and d.get("value"):
            return str(d["value"])
    return ""


def _cvss(cve: dict) -> float | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in _as_list(metrics.get(key)):
            data = item.get("cvssData") if isinstance(item, dict) else None
            if isinstance(data, dict) and data.get("baseScore") is not None:
                try:
                    return float(data["baseScore"])
                except (TypeError, ValueError):
                    pass
    return None


def _cwe(cve: dict) -> list[str]:
    out = []
    for weakness in _as_list(cve.get("weaknesses")):
        for desc in _as_list((weakness or {}).get("description")):
            value = str((desc or {}).get("value") or "")
            if value.startswith("CWE-"):
                out.append(value)
    return sorted(set(out))


def _products(cve: dict) -> list[str]:
    """Extract 'vendor product version' strings from CPE configurations."""
    out: set[str] = set()
    for config in _as_list(cve.get("configurations")):
        for node in _as_list((config or {}).get("nodes")):
            for match in _as_list((node or {}).get("cpeMatch")):
                criteria = str((match or {}).get("criteria") or "")
                m = CPE_RE.search(criteria)
                if m:
                    vendor, product, version = m.group(1), m.group(2), m.group(3)
                    parts = [p for p in (vendor.replace("_", " "), product.replace("_", " "),
                                        "" if version in ("*", "-", "") else version) if p]
                    out.add(" ".join(parts))
    return sorted(out)[:40]


def _normalize_nvd(record: dict) -> dict | None:
    cve = (record or {}).get("cve")
    if not isinstance(cve, dict):
        return None
    cve_id = str(cve.get("id") or "").strip()
    if not cve_id.startswith("CVE-"):
        return None
    return {
        "id": cve_id,
        "title": _first_description(cve)[:300],
        "description": _first_description(cve)[:4000],
        "products": _products(cve),
        "cwe": _cwe(cve),
        "cvss": _cvss(cve),
        "kev": False,
        "published": str(cve.get("published") or "")[:40],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "source": "nvd",
    }


def _normalize_kev(record: dict) -> dict | None:
    cve_id = str((record or {}).get("cveID") or "").strip()
    if not cve_id.startswith("CVE-"):
        return None
    vendor = str(record.get("vendorProject") or "").strip()
    product = str(record.get("product") or "").strip()
    name = str(record.get("vulnerabilityName") or "").strip()
    return {
        "id": cve_id,
        "title": name[:300] or f"{vendor} {product}".strip(),
        "description": str(record.get("shortDescription") or name)[:4000],
        "products": [p for p in (f"{vendor} {product}".strip(), product) if p],
        "cwe": [],
        "cvss": None,
        "kev": True,
        "published": str(record.get("dateAdded") or "")[:40],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "source": "kev",
        "required_action": str(record.get("requiredAction") or "")[:500],
        "due_date": str(record.get("dueDate") or "")[:40],
    }


def _normalize_simple(record: dict) -> dict | None:
    cve_id = str((record or {}).get("id") or (record or {}).get("cve") or "").strip()
    if not cve_id.startswith("CVE-"):
        return None
    products = record.get("products") or []
    if isinstance(products, str):
        products = [products]
    cwe = record.get("cwe") or []
    if isinstance(cwe, str):
        cwe = [cwe]
    return {
        "id": cve_id,
        "title": str(record.get("title") or record.get("name") or "")[:300],
        "description": str(record.get("description") or "")[:4000],
        "products": [str(p)[:200] for p in products][:40],
        "cwe": [str(c) for c in cwe][:20],
        "cvss": float(record["cvss"]) if record.get("cvss") is not None else None,
        "kev": bool(record.get("kev")),
        "published": str(record.get("published") or "")[:40],
        "url": str(record.get("url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}")[:500],
        "source": str(record.get("source") or "local")[:40],
    }


class CveIndex:
    def __init__(self, path: str | Path = CVE_PATH):
        self.path = Path(path)
        self.entries: dict[str, dict] = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise CveError(f"CVE index {self.path} is corrupt: {exc}") from exc
            items = raw.get("entries") if isinstance(raw, dict) else raw
            for item in items or []:
                if isinstance(item, dict) and item.get("id"):
                    self.entries[item["id"]] = item

    def stats(self) -> dict:
        kev = sum(1 for e in self.entries.values() if e.get("kev"))
        with_products = sum(1 for e in self.entries.values() if e.get("products"))
        return {"entries": len(self.entries), "kev": kev, "with_products": with_products,
                "path": str(self.path)}

    def add(self, records: list[dict]) -> int:
        added = 0
        for rec in records:
            if not rec or not rec.get("id"):
                continue
            old = self.entries.get(rec["id"])
            if old:
                # KEV and NVD records complement each other; keep the richer fields.
                merged = dict(old)
                for key, value in rec.items():
                    if value and not merged.get(key):
                        merged[key] = value
                if rec.get("kev"):
                    merged["kev"] = True
                    merged["source"] = "nvd+kev"
                    for key in ("required_action", "due_date"):
                        if rec.get(key):
                            merged[key] = rec[key]
                self.entries[rec["id"]] = merged
            else:
                self.entries[rec["id"]] = rec
                added += 1
        return added

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, "updated_at": now_iso(),
                                   "entries": list(self.entries.values())},
                                  separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, self.path)

    def query(self, text: str, k: int = 10, *, kev_only: bool = False,
              min_cvss: float | None = None) -> list[dict]:
        terms = _tokens(text)
        terms |= {t for t in re.findall(r"\b\d+(?:\.\d+){1,3}\b", text or "")}
        if not terms and not kev_only:
            return []
        scored = []
        for entry in self.entries.values():
            if kev_only and not entry.get("kev"):
                continue
            if min_cvss is not None and (entry.get("cvss") or 0) < min_cvss:
                continue
            product_text = " ".join(entry.get("products") or []).lower()
            title_text = (entry.get("title") or "").lower()
            desc_text = (entry.get("description") or "").lower()
            score = 0.0
            for term in terms:
                if term in product_text:
                    score += 4.0
                if term in title_text:
                    score += 2.0
                if term in desc_text:
                    score += 1.0
            if score <= 0:
                continue
            if entry.get("kev"):
                score += 2.5
            if entry.get("cvss"):
                score += min(float(entry["cvss"]), 10.0) / 10.0
            scored.append((score, entry))
        scored.sort(key=lambda pair: (-pair[0], pair[1].get("id", "")))
        return [dict(entry) | {"match_score": round(score, 2)}
                for score, entry in scored[:k]]

    def match_products(self, products: list[str], k: int = 20) -> list[dict]:
        return self.query(" ".join(products), k=k)


def load_file(path: str | Path) -> list[dict]:
    """Parse NVD, KEV, or simple JSON without guessing wrong. No network, bounded."""
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise CveError(f"CVE file not found: {p}")
    size = p.stat().st_size
    if size > MAX_BYTES:
        raise CveError(f"CVE file is {size} bytes; limit is {MAX_BYTES}")
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise CveError(f"invalid JSON in {p.name}: {exc}") from exc

    records: list[dict] = []
    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
        raw = data["vulnerabilities"][:MAX_ENTRIES]
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("cve"), dict):
                rec = _normalize_nvd(item)
            else:
                rec = _normalize_kev(item)
            if rec:
                records.append(rec)
    elif isinstance(data, list):
        for item in data[:MAX_ENTRIES]:
            rec = _normalize_simple(item) if isinstance(item, dict) else None
            if rec:
                records.append(rec)
    elif isinstance(data, dict) and isinstance(data.get("entries"), list):
        for item in data["entries"][:MAX_ENTRIES]:
            rec = _normalize_simple(item) if isinstance(item, dict) else None
            if rec:
                records.append(rec)
    else:
        raise CveError("unrecognized CVE format (expected NVD, KEV, or a simple list)")
    return records


def import_file(path: str | Path, index: CveIndex | None = None, *, save: bool = True) -> dict:
    index = index or CveIndex()
    records = load_file(path)
    added = index.add(records)
    if save:
        index.save()
    return {"records": len(records), "added": added, "total": len(index.entries),
            "kev": index.stats()["kev"], "path": str(index.path)}


def format_hits(hits: list[dict]) -> str:
    if not hits:
        return "no matching CVEs in the local index"
    lines = []
    for h in hits:
        flags = []
        if h.get("kev"):
            flags.append("KEV")
        if h.get("cvss") is not None:
            flags.append(f"CVSS {h['cvss']:g}")
        if h.get("cwe"):
            flags.append(",".join(h["cwe"][:2]))
        head = f"{h['id']}  [{h.get('match_score', 0):g}]  " + " · ".join(flags)
        lines.append(head)
        if h.get("title"):
            lines.append(f"  {h['title'][:180]}")
        if h.get("products"):
            lines.append(f"  products: {', '.join(h['products'][:4])[:200]}")
        if h.get("required_action"):
            lines.append(f"  action: {h['required_action'][:200]}")
    return "\n".join(lines)
