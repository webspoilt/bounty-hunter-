"""Intelligence ingestion adapters.

Modular adapters for ingesting:
- CVE records (NVD 2.0 and generic CVE formats)
- CWE weakness catalogs
- CAPEC attack pattern catalogs
- Vendor security advisories (e.g. GitHub Advisory Database format)
- Security patch notes & commit advisories
- Disclosed vulnerability research (H1 writeups, disclosure reports)

Maintains source provenance, source URLs, publication dates, and handles
invalid / incomplete records safely with validation error tracking.
"""
from __future__ import annotations

import json
import re
from typing import Any, Sequence

from bb.config import now_iso
from bb.intelligence.models import IntelligenceRecord, VersionConstraint


def _first_desc(obj: dict) -> str:
    descriptions = obj.get("descriptions")
    if isinstance(descriptions, list):
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en" and d.get("value"):
                return str(d["value"]).strip()
        for d in descriptions:
            if isinstance(d, dict) and d.get("value"):
                return str(d["value"]).strip()
    desc = obj.get("description")
    if isinstance(desc, str):
        return desc.strip()
    return ""


class NvdCveAdapter:
    """Ingests NVD 2.0 CVE vulnerability records."""

    @staticmethod
    def parse_item(cve_item: dict, source_url: str = "https://nvd.nist.gov") -> IntelligenceRecord:
        cve_data = cve_item.get("cve", cve_item)
        cve_id = cve_data.get("id") or cve_data.get("cveId") or cve_data.get("cveID")
        if not cve_id:
            return IntelligenceRecord(
                id=f"INVALID-CVE-{now_iso()}",
                source="nvd",
                source_id="",
                source_url=source_url,
                title="Invalid CVE item",
                description="Missing CVE identifier",
                vuln_class="unknown",
                retrieved_at=now_iso(),
                parse_status="malformed",
            )

        description = _first_desc(cve_data)
        published_at = cve_data.get("published")
        updated_at = cve_data.get("lastModified")

        # CVSS base score and severity
        metrics = cve_data.get("metrics") or {}
        cvss_score = None
        severity = None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            items = metrics.get(k)
            if isinstance(items, list) and items:
                cvss_data = items[0].get("cvssData") if isinstance(items[0], dict) else None
                if isinstance(cvss_data, dict):
                    try:
                        cvss_score = float(cvss_data.get("baseScore"))
                    except (TypeError, ValueError):
                        pass
                    severity = (cvss_data.get("baseSeverity") or items[0].get("baseSeverity") or "").lower() or None
                    if cvss_score is not None:
                        break

        # CWEs
        cwes = []
        for w in cve_data.get("weaknesses") or []:
            if isinstance(w, dict):
                for desc in w.get("description") or []:
                    val = desc.get("value")
                    if val and str(val).startswith("CWE-"):
                        cwes.append(str(val))
        cwes = sorted(set(cwes))

        # References
        refs = []
        for ref in cve_data.get("references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append(ref["url"])
            elif isinstance(ref, str):
                refs.append(ref)

        # Configurations & Version Constraints
        version_constraints: list[VersionConstraint] = []
        affected_vendor = None
        affected_product = None
        affected_component = None

        configurations = cve_data.get("configurations") or []
        for conf in configurations:
            nodes = conf.get("nodes") if isinstance(conf, dict) else []
            for node in nodes:
                cpe_matches = node.get("cpeMatch") or []
                for match in cpe_matches:
                    cpe23 = match.get("criteria", "")
                    # Extract vendor/product from cpe:2.3:a:vendor:product:version:...
                    parts = cpe23.split(":")
                    if len(parts) > 3 and not affected_vendor:
                        affected_vendor = parts[3]
                    if len(parts) > 4 and not affected_product:
                        affected_product = parts[4]
                    if len(parts) > 5 and parts[5] != "*":
                        affected_component = parts[5]

                    v_start_inc = match.get("versionStartIncluding")
                    v_start_exc = match.get("versionStartExcluding")
                    v_end_inc = match.get("versionEndIncluding")
                    v_end_exc = match.get("versionEndExcluding")

                    if any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
                        version_constraints.append(
                            VersionConstraint(
                                version_start_including=v_start_inc,
                                version_start_excluding=v_start_exc,
                                version_end_including=v_end_inc,
                                version_end_excluding=v_end_exc,
                            )
                        )
                    elif len(parts) > 5 and parts[5] not in ("*", "-"):
                        version_constraints.append(
                            VersionConstraint(exact_version=parts[5])
                        )

        # Classify vuln_class from description and CWEs
        vuln_class = "unknown"
        desc_lower = description.lower()
        if "sql injection" in desc_lower or "cwe-89" in [c.lower() for c in cwes]:
            vuln_class = "SQL Injection"
        elif "cross-site scripting" in desc_lower or "xss" in desc_lower or "cwe-79" in [c.lower() for c in cwes]:
            vuln_class = "Cross-Site Scripting"
        elif "idor" in desc_lower or "insecure direct object" in desc_lower or "cwe-639" in [c.lower() for c in cwes]:
            vuln_class = "IDOR"
        elif "authentication" in desc_lower or "cwe-287" in [c.lower() for c in cwes]:
            vuln_class = "Broken Authentication"
        elif "open redirect" in desc_lower or "cwe-601" in [c.lower() for c in cwes]:
            vuln_class = "Open Redirect"
        elif "remote code execution" in desc_lower or "command injection" in desc_lower:
            vuln_class = "Remote Code Execution"
        elif "server-side request forgery" in desc_lower or "ssrf" in desc_lower or "cwe-918" in [c.lower() for c in cwes]:
            vuln_class = "SSRF"

        parse_status = "valid"
        if not description or not affected_product:
            parse_status = "incomplete"

        # Attack surface detection from CVSS / description
        attack_surface = "web_application"
        desc_low = description.lower()
        if any(k in desc_low for k in ("kernel", "privilege escalation", "local application", "driver", "system call")):
            attack_surface = "local"
        elif any(k in desc_low for k in ("network", "remote code execution", "http", "api", "web")):
            attack_surface = "network"

        return IntelligenceRecord(
            id=cve_id,
            source="nvd",
            source_id=cve_id,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            title=cve_id,
            description=description,
            vuln_class=vuln_class,
            retrieved_at=now_iso(),
            published_at=published_at,
            updated_at=updated_at,
            affected_vendor=affected_vendor,
            affected_product=affected_product,
            affected_component=affected_component,
            attack_surface=attack_surface,
            version_constraints=version_constraints,
            cwe_ids=cwes,
            references=refs[:15],
            cvss_score=cvss_score,
            severity=severity,
            parse_status=parse_status,
        )


class CweAdapter:
    """Ingests CWE weakness catalog items."""

    @staticmethod
    def parse_item(item: dict, source_url: str = "https://cwe.mitre.org") -> IntelligenceRecord:
        cwe_id = str(item.get("id") or item.get("cwe_id") or "")
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}" if cwe_id else ""
        if not cwe_id or cwe_id == "CWE-":
            return IntelligenceRecord(
                id=f"INVALID-CWE-{now_iso()}",
                source="cwe",
                source_id="",
                source_url=source_url,
                title="Invalid CWE",
                description="Missing CWE id",
                vuln_class="unknown",
                retrieved_at=now_iso(),
                parse_status="malformed",
            )

        name = item.get("name") or item.get("title") or cwe_id
        description = item.get("description") or item.get("summary") or ""
        capec_ids = [str(c) for c in item.get("capec_ids") or []]

        return IntelligenceRecord(
            id=cwe_id,
            source="cwe",
            source_id=cwe_id,
            source_url=f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
            title=f"{cwe_id}: {name}",
            description=description,
            vuln_class=name,
            retrieved_at=now_iso(),
            cwe_ids=[cwe_id],
            capec_ids=capec_ids,
            parse_status="valid" if description else "incomplete",
        )


class CapecAdapter:
    """Ingests CAPEC attack pattern items."""

    @staticmethod
    def parse_item(item: dict, source_url: str = "https://capec.mitre.org") -> IntelligenceRecord:
        capec_id = str(item.get("id") or item.get("capec_id") or "")
        if not capec_id.startswith("CAPEC-"):
            capec_id = f"CAPEC-{capec_id}" if capec_id else ""
        if not capec_id or capec_id == "CAPEC-":
            return IntelligenceRecord(
                id=f"INVALID-CAPEC-{now_iso()}",
                source="capec",
                source_id="",
                source_url=source_url,
                title="Invalid CAPEC",
                description="Missing CAPEC id",
                vuln_class="unknown",
                retrieved_at=now_iso(),
                parse_status="malformed",
            )

        name = item.get("name") or item.get("title") or capec_id
        description = item.get("description") or item.get("summary") or ""
        cwe_ids = [str(c) for c in item.get("cwe_ids") or []]

        return IntelligenceRecord(
            id=capec_id,
            source="capec",
            source_id=capec_id,
            source_url=f"https://capec.mitre.org/data/definitions/{capec_id.replace('CAPEC-', '')}.html",
            title=f"{capec_id}: {name}",
            description=description,
            vuln_class=name,
            retrieved_at=now_iso(),
            cwe_ids=cwe_ids,
            capec_ids=[capec_id],
            parse_status="valid" if description else "incomplete",
        )


class AdvisoryAdapter:
    """Ingests vendor security advisories and security patch notes."""

    @staticmethod
    def parse_item(item: dict, source_name: str = "advisory") -> IntelligenceRecord:
        adv_id = item.get("id") or item.get("advisory_id") or item.get("ghsa_id")
        if not adv_id:
            return IntelligenceRecord(
                id=f"INVALID-ADV-{now_iso()}",
                source=source_name,
                source_id="",
                source_url=item.get("url", ""),
                title="Invalid Advisory",
                description="Missing advisory identifier",
                vuln_class="unknown",
                retrieved_at=now_iso(),
                parse_status="malformed",
            )

        title = item.get("title") or item.get("summary") or adv_id
        description = item.get("description") or item.get("details") or ""
        product = item.get("product") or item.get("package")
        version_constraints: list[VersionConstraint] = []

        raw_ranges = item.get("affected_ranges") or item.get("versions") or []
        for r in raw_ranges:
            if isinstance(r, dict):
                version_constraints.append(VersionConstraint.from_dict(r))
            elif isinstance(r, str):
                # E.g. "< 2.4.5"
                if r.startswith("<="):
                    version_constraints.append(VersionConstraint(version_end_including=r[2:].strip()))
                elif r.startswith("<"):
                    version_constraints.append(VersionConstraint(version_end_excluding=r[1:].strip()))
                elif r.startswith("=="):
                    version_constraints.append(VersionConstraint(exact_version=r[2:].strip()))
                else:
                    version_constraints.append(VersionConstraint(exact_version=r.strip()))

        return IntelligenceRecord(
            id=adv_id,
            source=source_name,
            source_id=adv_id,
            source_url=item.get("url") or item.get("references", [""])[0] if item.get("references") else "",
            title=title,
            description=description,
            vuln_class=item.get("vuln_class", "unknown"),
            retrieved_at=now_iso(),
            published_at=item.get("published_at"),
            updated_at=item.get("updated_at"),
            affected_product=product,
            affected_component=item.get("component"),
            version_constraints=version_constraints,
            cwe_ids=item.get("cwe_ids") or [],
            references=item.get("references") or [],
            severity=item.get("severity"),
            cvss_score=item.get("cvss_score"),
            parse_status="valid" if (description and product) else "incomplete",
        )


class ResearchDisclosureAdapter:
    """Ingests publicly disclosed vulnerability research, bug bounty reports, and writeups."""

    @staticmethod
    def parse_item(item: dict) -> IntelligenceRecord:
        disc_id = item.get("id") or item.get("report_id") or item.get("slug")
        if not disc_id:
            return IntelligenceRecord(
                id=f"INVALID-DISC-{now_iso()}",
                source="disclosure",
                source_id="",
                source_url=item.get("url", ""),
                title="Invalid Disclosure",
                description="Missing disclosure identifier",
                vuln_class="unknown",
                retrieved_at=now_iso(),
                parse_status="malformed",
            )

        title = item.get("title") or disc_id
        description = item.get("summary") or item.get("body") or item.get("description") or ""
        product = item.get("product") or item.get("target_software")

        return IntelligenceRecord(
            id=disc_id,
            source="disclosure",
            source_id=disc_id,
            source_url=item.get("url", ""),
            title=title,
            description=description,
            vuln_class=item.get("vuln_class", "unknown"),
            retrieved_at=now_iso(),
            published_at=item.get("published_at") or item.get("disclosed_at"),
            affected_product=product,
            affected_component=item.get("component") or item.get("endpoint"),
            cwe_ids=item.get("cwe_ids") or [],
            references=item.get("references") or [item.get("url")] if item.get("url") else [],
            severity=item.get("severity"),
            parse_status="valid" if description else "incomplete",
            meta={
                "bounty_amount": item.get("bounty"),
                "researcher": item.get("researcher"),
                "technique": item.get("technique"),
            },
        )
