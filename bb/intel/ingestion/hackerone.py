"""Parsers for HackerOne disclosed reports datasets (CSV metadata index & Markdown files)."""
from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path
from typing import Generator, List, Optional

from bb.intel.hexbrain_models import HexBrainReport
from bb.intel.ingestion.normalize import normalize_record
from bb.intel.ingestion.deduplicate import Deduplicator

logger = logging.getLogger(__name__)


def parse_h1_reports_csv(
    file_path: Path,
    limit: Optional[int] = None,
    deduplicator: Optional[Deduplicator] = None,
) -> List[HexBrainReport]:
    """Parse reddelexc/hackerone-reports CSV index."""
    if not file_path.exists():
        logger.warning("CSV index file not found: %s", file_path)
        return []

    reports: List[HexBrainReport] = []
    dedup = deduplicator or Deduplicator()

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if limit and len(reports) >= limit:
                break

            record_dict = {
                "id": f"H1-{row.get('id', i)}",
                "title": row.get("title", ""),
                "url": row.get("url", f"https://hackerone.com/reports/{row.get('id', '')}"),
                "program": row.get("program", ""),
                "severity": row.get("severity", ""),
                "bounty": row.get("bounty_amount", 0),
                "date": row.get("submitted_at") or row.get("disclosed_at", ""),
                "cwe": row.get("cwe", ""),
                "vuln_type": row.get("vulnerability_information", ""),
                "summary": row.get("summary", ""),
            }

            report = normalize_record(record_dict, source_name="hackerone_csv_index", default_license="public_metadata")
            is_dup, _ = dedup.is_duplicate(report)
            if not is_dup:
                dedup.register(report)
                reports.append(report)

    return reports


def parse_h1_disclosed_markdown(
    file_path: Path,
    report_id: Optional[str] = None,
) -> Optional[HexBrainReport]:
    """Parse an individual disclosed markdown report from ajaysenr/HackerOne-Disclosed-Reports."""
    if not file_path.exists():
        return None

    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()

    title = file_path.stem.replace("-", " ").title()
    summary = ""
    details = content
    program = None

    # Parse common header formats if present
    for line in lines[:15]:
        if line.lower().startswith("# title:"):
            title = line.split(":", 1)[1].strip()
        elif line.lower().startswith("# program:"):
            program = line.split(":", 1)[1].strip()

    r_id = report_id or f"H1-DISCLOSED-{file_path.stem}"
    record = {
        "id": r_id,
        "title": title,
        "url": f"https://hackerone.com/reports/{file_path.stem}",
        "program": program,
        "summary": summary,
        "details": details,
        "source": "h1_disclosed_reports",
    }
    return normalize_record(record, source_name="h1_disclosed_reports", default_license="h1_disclosed_rag_only")
