"""Provenance tracking, license enforcement, and PII/credential sanitization."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

ALLOWED_LICENSES = {
    "mit": "MIT License - Open usage & training eligible",
    "apache-2.0": "Apache 2.0 - Open usage & training eligible",
    "cc0": "Creative Commons Zero - Public domain & training eligible",
    "cc-by-4.0": "Creative Commons Attribution 4.0 - Attribution required",
    "public_metadata": "Factual metadata / index headers - RAG & research only",
    "h1_disclosed_rag_only": "HackerOne publicly disclosed report - RAG & research only (not model training)",
    "restricted": "Restricted license - Do not distribute or train",
}

# Regex patterns for redacting sensitive values before storage
PII_EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PII_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CREDENTIAL_TOKEN_PATTERN = re.compile(r"(?i)(bearer\s+[a-z0-9_\-\.]{16,}|api[_\-]?key[\s:=]+['\"]?[a-z0-9_\-]{16,}['\"]?|session[_\-]?id[\s:=]+['\"]?[a-z0-9_\-]{16,}['\"]?)")
PROMPT_INJECTION_PATTERN = re.compile(r"(?i)(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt|you\s+are\s+now\s+an\s+unfiltered|assistant\s*:\s*)")


class ProvenanceTracker:
    """Tracks dataset provenance, enforces licensing boundaries, and sanitizes untrusted text."""

    @staticmethod
    def compute_sha256(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """Sanitize raw text by redacting PII, credentials, and neutralizing prompt injections."""
        if not text:
            return ""
        # Redact credentials
        clean = CREDENTIAL_TOKEN_PATTERN.sub("[REDACTED_CREDENTIAL]", text)
        # Redact emails (except known placeholder @example.com)
        clean = PII_EMAIL_PATTERN.sub(lambda m: m.group(0) if "@example." in m.group(0) else "[REDACTED_EMAIL]", clean)
        # Defuse potential prompt injections by escaping brackets and neutralizing keywords
        clean = PROMPT_INJECTION_PATTERN.sub(r"[UNTRUSTED_INSTRUCTION_NEUTRALIZED: \1]", clean)
        return clean

    @classmethod
    def determine_training_eligibility(cls, license_name: str, source: str) -> Tuple[bool, str]:
        """Strictly determine if a record is legally and ethically eligible for model fine-tuning."""
        lic = license_name.lower().strip()
        src = source.lower().strip()

        # HackerOne disclosed reports and HexBrain passages are strictly RAG & research only
        if "hackerone" in src or "hexbrain" in src or lic in ("public_metadata", "h1_disclosed_rag_only"):
            return False, "RAG_AND_RESEARCH_ONLY: Publicly disclosed reports require explicit permission for model weights training."

        # MIT, Apache-2.0, CC0 from verified repositories (e.g. PayloadsAllTheThings) are eligible
        if lic in ("mit", "apache-2.0", "cc0"):
            return True, f"TRAINING_ELIGIBLE: Permissive license ({lic})"

        return False, f"INELIGIBLE: License {license_name} does not explicitly permit training"
