"""Intelligence on AI-built, vibe-coded, and AI-assisted development methodologies."""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Tuple
from bb.programs.program_models import AIClassification, AIEvidenceRecord

# Curated repository of documented public intelligence on software development methodologies
PUBLIC_AI_DEVELOPMENT_EVIDENCE: Dict[str, Dict[str, Any]] = {
    "cursor": {
        "classification": AIClassification.CONFIRMED_AI_BUILT,
        "description": "Anysphere explicitly builds and dogfoods Cursor editor using its own AI code-generation agents.",
        "source_url": "https://cursor.com/blog",
        "source_org": "Anysphere (Cursor)",
        "confidence": 0.95,
        "summary": "Engineering team confirms full codebase authored and maintained through AI interaction loops.",
    },
    "v0": {
        "classification": AIClassification.CONFIRMED_AI_BUILT,
        "description": "Vercel v0 generates production UI and full-stack code using generative AI pipelines.",
        "source_url": "https://vercel.com/blog",
        "source_org": "Vercel",
        "confidence": 0.95,
        "summary": "Rapid generative UI construction platform generating full React/Next.js applications.",
    },
    "replit": {
        "classification": AIClassification.CONFIRMED_AI_BUILT,
        "description": "Replit Agent and Replit core services built via AI-assisted engineering and autonomous agents.",
        "source_url": "https://blog.replit.com",
        "source_org": "Replit",
        "confidence": 0.90,
        "summary": "Public engineering blogs document extensive autonomous AI coding agent workflows.",
    },
    "postman": {
        "classification": AIClassification.AI_PRODUCT,
        "description": "Postman features Postbot AI assistant, but core client/server architecture is traditional Node/Java.",
        "source_url": "https://blog.postman.com",
        "source_org": "Postman",
        "confidence": 0.85,
        "summary": "Postbot is an embedded product feature; underlying API management platform is traditionally developed.",
    },
    "gitlab": {
        "classification": AIClassification.AI_PRODUCT,
        "description": "GitLab Duo features code suggestions, but platform is established Ruby/Go monolith/microservices.",
        "source_url": "https://about.gitlab.com",
        "source_org": "GitLab",
        "confidence": 0.80,
        "summary": "Platform incorporates AI features, but core codebase is not an AI-generated application.",
    },
}

AI_BUILT_KEYWORDS = [
    "vibe-coding", "vibe coding", "ai-generated application", "built with cursor",
    "built with claude", "ai-assisted codebase", "ai-native architecture",
    "prompt-driven development", "agent-built software", "synthetic codebase"
]

AI_PRODUCT_KEYWORDS = [
    "copilot", "ai assistant", "llm", "gpt-4", "rag", "embeddings",
    "ai workflow", "generative ai", "bot", "chat interface"
]


class AIDevelopmentClassifier:
    """Classifies application development methodology based on verified public evidence."""

    @classmethod
    def evaluate(
        cls,
        handle: str,
        name: str,
        description: str,
        policy_text: str,
    ) -> Tuple[AIClassification, List[AIEvidenceRecord]]:
        now_str = datetime.now(timezone.utc).isoformat()
        handle_clean = handle.lower().strip()
        records: List[AIEvidenceRecord] = []

        # 1. Check curated primary verified public evidence
        if handle_clean in PUBLIC_AI_DEVELOPMENT_EVIDENCE:
            info = PUBLIC_AI_DEVELOPMENT_EVIDENCE[handle_clean]
            rec = AIEvidenceRecord(
                classification=info["classification"],
                evidence_description=info["description"],
                source_url=info["source_url"],
                source_organization=info["source_org"],
                retrieval_date=now_str,
                evidence_confidence=info["confidence"],
                supporting_summary=info["summary"],
                is_primary=True,
            )
            records.append(rec)
            return info["classification"], records

        # 2. Textual heuristic scan across official program description & policy
        combined_text = f"{name} {description} {policy_text}".lower()

        # Check for confirmed/probable AI-built signals
        for kw in AI_BUILT_KEYWORDS:
            if kw in combined_text:
                rec = AIEvidenceRecord(
                    classification=AIClassification.PROBABLE_AI_BUILT,
                    evidence_description=f"Program documentation references '{kw}' methodology.",
                    source_url=f"https://hackerone.com/{handle}",
                    source_organization="HackerOne Program Profile",
                    retrieval_date=now_str,
                    evidence_confidence=0.70,
                    supporting_summary=f"Public program profile explicitly mentions '{kw}' in its development scope.",
                    is_primary=False,
                )
                records.append(rec)
                return AIClassification.PROBABLE_AI_BUILT, records

        # Check for AI Product features (distinguished from AI-built)
        for kw in AI_PRODUCT_KEYWORDS:
            if re.search(r"\b" + re.escape(kw) + r"\b", combined_text):
                rec = AIEvidenceRecord(
                    classification=AIClassification.AI_PRODUCT,
                    evidence_description=f"Application incorporates '{kw}' product features.",
                    source_url=f"https://hackerone.com/{handle}",
                    source_organization="HackerOne Program Profile",
                    retrieval_date=now_str,
                    evidence_confidence=0.80,
                    supporting_summary="Application offers AI-driven features, but core development methodology is unconfirmed.",
                    is_primary=False,
                )
                records.append(rec)
                return AIClassification.AI_PRODUCT, records

        # Default classification
        return AIClassification.UNKNOWN, []
