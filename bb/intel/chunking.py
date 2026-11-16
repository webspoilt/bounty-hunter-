"""Semantic chunker for vulnerability research reports and techniques."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, List, Optional
from bb.intel.hexbrain_models import HexBrainReport


@dataclass
class VulnerabilityChunk:
    """Semantically coherent passage chunk from a vulnerability report."""
    chunk_id: str
    report_id: str
    section: str  # "overview", "root_cause", "prerequisites", "reproduction", "impact", "remediation"
    content: str
    cwe_id: Optional[str]
    technologies: List[str]
    training_eligible: bool


def chunk_vulnerability_report(
    report: HexBrainReport,
    max_chunk_chars: int = 1200,
) -> List[VulnerabilityChunk]:
    """Break a vulnerability report into structured semantic chunks."""
    chunks: List[VulnerabilityChunk] = []

    # 1. Overview chunk
    overview_text = f"Title: {report.title}\nCWE: {report.cwe_id or 'None'}\nSeverity: {report.severity}\nProgram: {report.program_name or report.program_handle or 'Unknown'}\nSummary: {report.summary}"
    chunks.append(
        VulnerabilityChunk(
            chunk_id=f"{report.report_id}-sec-overview",
            report_id=report.report_id,
            section="overview",
            content=overview_text.strip(),
            cwe_id=report.cwe_id,
            technologies=report.technologies,
            training_eligible=report.training_eligible,
        )
    )

    # 2. Root cause / Details chunk
    if report.vulnerability_details:
        details_text = f"Vulnerability Details:\n{report.vulnerability_details}"
        # If too long, partition cleanly on paragraphs
        paragraphs = details_text.split("\n\n")
        curr_buf: List[str] = []
        curr_len = 0
        part_idx = 1
        for p in paragraphs:
            if curr_len + len(p) > max_chunk_chars and curr_buf:
                chunks.append(
                    VulnerabilityChunk(
                        chunk_id=f"{report.report_id}-sec-root_cause-{part_idx}",
                        report_id=report.report_id,
                        section="root_cause",
                        content="\n\n".join(curr_buf).strip(),
                        cwe_id=report.cwe_id,
                        technologies=report.technologies,
                        training_eligible=report.training_eligible,
                    )
                )
                curr_buf = [p]
                curr_len = len(p)
                part_idx += 1
            else:
                curr_buf.append(p)
                curr_len += len(p)

        if curr_buf:
            chunks.append(
                VulnerabilityChunk(
                    chunk_id=f"{report.report_id}-sec-root_cause-{part_idx}",
                    report_id=report.report_id,
                    section="root_cause",
                    content="\n\n".join(curr_buf).strip(),
                    cwe_id=report.cwe_id,
                    technologies=report.technologies,
                    training_eligible=report.training_eligible,
                )
            )

    # 3. Reproduction steps chunk
    if report.reproduction_steps:
        chunks.append(
            VulnerabilityChunk(
                chunk_id=f"{report.report_id}-sec-reproduction",
                report_id=report.report_id,
                section="reproduction",
                content=f"Reproduction Steps:\n{report.reproduction_steps}".strip(),
                cwe_id=report.cwe_id,
                technologies=report.technologies,
                training_eligible=report.training_eligible,
            )
        )

    # 4. Impact chunk
    if report.impact:
        chunks.append(
            VulnerabilityChunk(
                chunk_id=f"{report.report_id}-sec-impact",
                report_id=report.report_id,
                section="impact",
                content=f"Impact:\n{report.impact}".strip(),
                cwe_id=report.cwe_id,
                technologies=report.technologies,
                training_eligible=report.training_eligible,
            )
        )

    # 5. Remediation chunk
    if report.remediation:
        chunks.append(
            VulnerabilityChunk(
                chunk_id=f"{report.report_id}-sec-remediation",
                report_id=report.report_id,
                section="remediation",
                content=f"Remediation Guidance:\n{report.remediation}".strip(),
                cwe_id=report.cwe_id,
                technologies=report.technologies,
                training_eligible=report.training_eligible,
            )
        )

    return chunks
