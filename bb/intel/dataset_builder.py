"""Dataset preparation, export pipelines (JSONL, Alpaca, ShareGPT), and provenance manifest."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from bb.intel.hexbrain_models import HexBrainReport
from bb.intel.knowledge_base import KnowledgeBase
from bb.intel.ingestion.provenance import ProvenanceTracker


class DatasetBuilder:
    """Prepares and exports curated datasets strictly respecting licensing and training boundaries."""

    def __init__(self, kb: Optional[KnowledgeBase] = None):
        self.kb = kb or KnowledgeBase()

    def export_rag_corpus(self, output_path: Path) -> int:
        """Export all reports (both RAG-only and training-eligible) for RAG embedding/indexing."""
        count = 0
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.kb._get_connection() as conn, open(output_path, "w", encoding="utf-8") as f:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reports")
            for row in cursor:
                rep = self.kb._row_to_report(row)
                record = {
                    "id": rep.report_id,
                    "title": rep.title,
                    "cwe": rep.cwe_id,
                    "source": rep.source,
                    "license": rep.license,
                    "training_eligible": rep.training_eligible,
                    "text": f"{rep.title}\n{rep.summary}\n{rep.vulnerability_details}\n{rep.remediation}".strip(),
                }
                f.write(json.dumps(record) + "\n")
                count += 1
        return count

    def export_training_eligible_alpaca(self, output_path: Path) -> int:
        """Export ONLY permissively licensed records in instruction-tuning Alpaca format."""
        count = 0
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.kb._get_connection() as conn, open(output_path, "w", encoding="utf-8") as f:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reports WHERE training_eligible = 1")
            for row in cursor:
                rep = self.kb._row_to_report(row)
                alpaca_entry = {
                    "instruction": f"Analyze the following vulnerability pattern and provide remediation guidance for weakness {rep.cwe_id or 'generic'}.",
                    "input": f"Vulnerability Title: {rep.title}\nDetails: {rep.vulnerability_details}",
                    "output": f"Impact:\n{rep.impact}\n\nRemediation:\n{rep.remediation}",
                    "metadata": {
                        "source": rep.source,
                        "license": rep.license,
                        "cwe": rep.cwe_id,
                    },
                }
                f.write(json.dumps(alpaca_entry) + "\n")
                count += 1
        return count

    def export_provenance_manifest(self, output_path: Path) -> int:
        """Export complete DATASET_PROVENANCE.csv tracking source attribution and licenses."""
        count = 0
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.kb._get_connection() as conn, open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "report_id", "source", "source_url", "license", "training_eligible",
                "cwe_id", "severity", "bounty_amount", "content_sha256"
            ])
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reports")
            for row in cursor:
                rep = self.kb._row_to_report(row)
                content = f"{rep.title}{rep.summary}{rep.vulnerability_details}"
                sha = ProvenanceTracker.compute_sha256(content)
                writer.writerow([
                    rep.report_id,
                    rep.source,
                    rep.source_url,
                    rep.license,
                    rep.training_eligible,
                    rep.cwe_id or "",
                    rep.severity,
                    rep.bounty_amount,
                    sha,
                ])
                count += 1
        return count
