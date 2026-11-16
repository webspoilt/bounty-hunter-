"""Parser for PayloadsAllTheThings structured catalog with MIT license attribution."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional
from bb.intel.hexbrain_models import HexBrainTechnique
from bb.intel.hexbrain_search import normalize_cwe_id

logger = logging.getLogger(__name__)

# Mapping directory names to common CWE identifiers
PAYLOADS_CWE_MAP = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "cross-site scripting": "CWE-79",
    "ssrf": "CWE-918",
    "server side request forgery": "CWE-918",
    "command injection": "CWE-78",
    "directory traversal": "CWE-22",
    "file inclusion": "CWE-98",
    "xxe": "CWE-611",
    "xml external entity": "CWE-611",
    "open redirect": "CWE-601",
    "csrf": "CWE-352",
    "cors": "CWE-942",
    "jwt": "CWE-1270",
}


def parse_payloads_markdown(
    file_path: Path,
    category_name: Optional[str] = None,
) -> List[HexBrainTechnique]:
    """Parse PayloadsAllTheThings cheatsheet markdown into structured HexBrainTechnique objects."""
    if not file_path.exists():
        return []

    cat = (category_name or file_path.parent.name).lower()
    cwe = PAYLOADS_CWE_MAP.get(cat)

    content = file_path.read_text(encoding="utf-8", errors="replace")
    techniques: List[HexBrainTechnique] = []

    # Extract code blocks as payloads and headers as technique descriptions
    sections = content.split("## ")
    for idx, sec in enumerate(sections[1:], start=1):
        lines = sec.splitlines()
        if not lines:
            continue
        title = lines[0].strip()
        body = "\n".join(lines[1:])

        # Extract payloads from ``` code blocks
        payloads: List[str] = []
        in_code = False
        curr_code: List[str] = []
        for line in lines[1:]:
            if line.startswith("```"):
                if in_code:
                    payloads.append("\n".join(curr_code).strip())
                    curr_code = []
                    in_code = False
                else:
                    in_code = True
            elif in_code:
                curr_code.append(line)

        tech_id = f"PATT-{cat.upper()[:4]}-{idx:03d}"
        tech = HexBrainTechnique(
            technique_id=tech_id,
            name=f"{cat.title()}: {title}",
            cwe_id=cwe,
            vulnerability_type=cat,
            description=body[:400].strip(),
            payload_examples=payloads[:10],
            source="PayloadsAllTheThings",
            confidence=1.0,
            metadata={
                "license": "MIT",
                "training_eligible": True,
                "file_path": str(file_path),
            },
        )
        techniques.append(tech)

    return techniques
