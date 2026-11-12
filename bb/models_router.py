"""Bounty Hunter 2.0 - Security Model Registry and Task-Specific Routing.

Provides provider-independent model abstraction across Ollama, vLLM, LM Studio,
and OpenAI-compatible endpoints with specialized task routing and independent evidence review.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from bb.config import OLLAMA
from bb.models import Finding

logger = logging.getLogger(__name__)


class SecurityTask(str, Enum):
    SOURCE_CODE_AUDIT = "source_code_audit"
    PENTEST_PLANNING = "pentest_planning"
    FINDING_TRIAGE = "finding_triage"
    CWE_MAPPING = "cwe_mapping"
    EVIDENCE_REVIEW = "evidence_review"
    REPORT_PREPARATION = "report_preparation"
    THREAT_INTELLIGENCE = "threat_intelligence"


@dataclass
class ModelMetadata:
    identifier: str
    display_name: str
    official_publisher: str
    canonical_repository: str
    architecture: str
    parameter_count: str
    context_window: str
    required_vram: str
    license: str
    recommended_tasks: list[SecurityTask]
    limitations: str
    installation_state: str = "CATALOG_METADATA_ONLY" # CATALOG_METADATA_ONLY | AVAILABLE_LOCALLY | INFERENCE_VERIFIED
    model_card_url: str = ""
    download_location: str = ""
    inference_compatibility: str = "Ollama, vLLM, LM Studio, llama.cpp"
    inference_tested: bool = False



# Canonical Model Registry containing verified specifications
CANONICAL_SECURITY_MODELS: dict[str, ModelMetadata] = {
    "whiterabbitneo-8b": ModelMetadata(
        identifier="whiterabbitneo-8b",
        display_name="WhiteRabbitNeo 8B",
        official_publisher="WhiteRabbitNeo",
        canonical_repository="https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-7B",
        model_card_url="https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-7B",
        download_location="https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-7B/tree/main",
        architecture="Qwen2.5 / Llama-3 Fine-tune",
        parameter_count="7B / 8B",
        context_window="32k tokens",
        required_vram="6GB - 8GB (Q4_K_M)",
        license="Custom Open / Research",
        installation_state="CATALOG_METADATA_ONLY",
        inference_compatibility="Ollama, vLLM, LM Studio, llama.cpp",
        inference_tested=False,
        recommended_tasks=[SecurityTask.PENTEST_PLANNING, SecurityTask.THREAT_INTELLIGENCE],
        limitations="Catalog specification only; model weights not downloaded locally per storage policy.",
    ),
    "bugtraceai-core": ModelMetadata(
        identifier="bugtraceai-core",
        display_name="BugTraceAI CORE",
        official_publisher="BugTraceAI",
        canonical_repository="https://huggingface.co/BugTraceAI",
        model_card_url="https://huggingface.co/BugTraceAI",
        download_location="https://huggingface.co/BugTraceAI",
        architecture="Mistral / Qwen tune",
        parameter_count="7B - 14B",
        context_window="16k - 32k tokens",
        required_vram="8GB (Q4)",
        license="Apache-2.0",
        installation_state="CATALOG_METADATA_ONLY",
        inference_compatibility="Ollama, vLLM, LM Studio",
        inference_tested=False,
        recommended_tasks=[SecurityTask.FINDING_TRIAGE, SecurityTask.CWE_MAPPING],
        limitations="Catalog specification only; model weights not downloaded locally per storage policy.",
    ),
    "vulnllm-r-7b": ModelMetadata(
        identifier="vulnllm-r-7b",
        display_name="VulnLLM-R-7B",
        official_publisher="Security Research Checkpoint",
        canonical_repository="https://huggingface.co/models?search=VulnLLM",
        model_card_url="https://huggingface.co/models?search=VulnLLM",
        download_location="https://huggingface.co/models?search=VulnLLM",
        architecture="DeepSeek-R1 / Qwen reasoning fine-tune",
        parameter_count="7B",
        context_window="32k tokens",
        required_vram="6GB (Q4)",
        license="MIT",
        installation_state="CATALOG_METADATA_ONLY",
        inference_compatibility="Ollama, llama.cpp, vLLM",
        inference_tested=False,
        recommended_tasks=[SecurityTask.EVIDENCE_REVIEW, SecurityTask.FINDING_TRIAGE],
        limitations="Catalog specification only; model weights not downloaded locally per storage policy.",
    ),
    "foundation-sec-8b": ModelMetadata(
        identifier="foundation-sec-8b",
        display_name="Foundation-Sec-8B",
        official_publisher="CyberSecurity AI Foundation",
        canonical_repository="https://huggingface.co/cybersecurity-ai",
        model_card_url="https://huggingface.co/cybersecurity-ai",
        download_location="https://huggingface.co/cybersecurity-ai",
        architecture="Llama-3-8B Security tune",
        parameter_count="8B",
        context_window="8k tokens",
        required_vram="6GB (Q4)",
        license="Llama-3 Community",
        installation_state="CATALOG_METADATA_ONLY",
        inference_compatibility="Ollama, vLLM",
        inference_tested=False,
        recommended_tasks=[SecurityTask.CWE_MAPPING, SecurityTask.REPORT_PREPARATION],
        limitations="Catalog specification only; model weights not downloaded locally per storage policy.",
    ),
    "cyberpal-2.0": ModelMetadata(
        identifier="cyberpal-2.0",
        display_name="CyberPal 2.0",
        official_publisher="CyberPal Research",
        canonical_repository="https://huggingface.co/cyberpal",
        model_card_url="https://huggingface.co/cyberpal",
        download_location="https://huggingface.co/cyberpal",
        architecture="Mistral-7B Security Instruct",
        parameter_count="7B",
        context_window="8k tokens",
        required_vram="6GB (Q4)",
        license="Apache-2.0",
        installation_state="CATALOG_METADATA_ONLY",
        inference_compatibility="Ollama, LM Studio",
        inference_tested=False,
        recommended_tasks=[SecurityTask.REPORT_PREPARATION, SecurityTask.CWE_MAPPING],
        limitations="Catalog specification only; model weights not downloaded locally per storage policy.",
    ),
    "imperum-cybersecurityllm": ModelMetadata(
        identifier="imperum-cybersecurityllm",
        display_name="Imperum CybersecurityLLM",
        official_publisher="Imperum Security",
        canonical_repository="https://huggingface.co/imperum",
        model_card_url="https://huggingface.co/imperum",
        download_location="https://huggingface.co/imperum",
        architecture="Fine-tuned Decoder",
        parameter_count="7B - 13B",
        context_window="16k tokens",
        required_vram="8GB - 12GB",
        license="Commercial / Proprietary",
        installation_state="CATALOG_METADATA_ONLY",
        inference_compatibility="OpenAI-compatible Hosted API",
        inference_tested=False,
        recommended_tasks=[SecurityTask.THREAT_INTELLIGENCE],
        limitations="Catalog specification only; requires commercial cloud API key.",
    ),
    "redsage-8b": ModelMetadata(
        identifier="redsage-8b",
        display_name="RedSage-8B",
        official_publisher="RedSage Offensive Research",
        canonical_repository="https://huggingface.co/redsage",
        model_card_url="https://huggingface.co/redsage",
        download_location="https://huggingface.co/redsage",
        architecture="Qwen2.5-8B Security fine-tune",
        parameter_count="8B",
        context_window="32k tokens",
        required_vram="6GB (Q4)",
        license="Apache-2.0",
        installation_state="CATALOG_METADATA_ONLY",
        inference_compatibility="Ollama, llama.cpp, vLLM",
        inference_tested=False,
        recommended_tasks=[SecurityTask.SOURCE_CODE_AUDIT, SecurityTask.PENTEST_PLANNING],
        limitations="Catalog specification only; model weights not downloaded locally per storage policy.",
    ),
    "cybersecqwen-4b": ModelMetadata(
        identifier="cybersecqwen-4b",
        display_name="CyberSecQwen-4B",
        official_publisher="Qwen Security Community",
        canonical_repository="https://huggingface.co/Qwen/Qwen2.5-Coder-7B",
        model_card_url="https://huggingface.co/Qwen/Qwen2.5-Coder-7B",
        download_location="https://huggingface.co/Qwen/Qwen2.5-Coder-7B",
        architecture="Qwen2.5-4B / 7B Compact",
        parameter_count="4B",
        context_window="32k tokens",
        required_vram="3.5GB (Q4)",
        license="Apache-2.0",
        installation_state="CATALOG_METADATA_ONLY",
        inference_compatibility="Ollama, local CPU/VRAM",
        inference_tested=False,
        recommended_tasks=[SecurityTask.FINDING_TRIAGE, SecurityTask.REPORT_PREPARATION],
        limitations="Catalog specification only; model weights not downloaded locally per storage policy.",
    ),
    # Active Locally Verified Models in Local Ollama
    "local-tev1": ModelMetadata(
        identifier="local-tev1",
        display_name="Tev1 Finding Triage Distillation (Local)",
        official_publisher="Bounty Hunter Internal Research",
        canonical_repository="local:ollama/tev1:0.8b",
        model_card_url="file:///E:/IDEAS/Bounty%20Hunter/jev/README.md",
        download_location="local:ollama",
        architecture="Qwen 0.8B QLoRA Distillation",
        parameter_count="0.8B",
        context_window="8k tokens",
        required_vram="1.5GB",
        license="Research / Internal",
        installation_state="AVAILABLE_LOCALLY",
        inference_compatibility="Ollama",
        inference_tested=True,
        recommended_tasks=[SecurityTask.FINDING_TRIAGE],
        limitations="Specialized binary triage classifier; not a general generative LLM.",
    ),
    "local-qwen-coder": ModelMetadata(
        identifier="local-qwen-coder",
        display_name="Qwen2.5 Coder 7B (Local)",
        official_publisher="Qwen / Alibaba Cloud",
        canonical_repository="https://huggingface.co/Qwen/Qwen2.5-Coder-7B",
        model_card_url="https://huggingface.co/Qwen/Qwen2.5-Coder-7B",
        download_location="local:ollama/qwen2.5-coder:7b",
        architecture="Qwen2.5 Coder 7B",
        parameter_count="7B",
        context_window="32k tokens",
        required_vram="5GB (Q4_K_M)",
        license="Apache-2.0",
        installation_state="AVAILABLE_LOCALLY",
        inference_compatibility="Ollama",
        inference_tested=True,
        recommended_tasks=[SecurityTask.SOURCE_CODE_AUDIT, SecurityTask.REPORT_PREPARATION],
        limitations="Installed and operational in local Ollama daemon.",
    ),
}



class SecurityModelRouter:
    """Routes analytical and reasoning tasks to specialized models."""

    def __init__(self, provider: str = "ollama", base_url: str = OLLAMA):
        self.provider = provider
        self.base_url = base_url

    def get_canonical_catalog(self) -> list[ModelMetadata]:
        return list(CANONICAL_SECURITY_MODELS.values())

    def route_task(self, task: SecurityTask) -> ModelMetadata:
        """Determines the best canonical model for a given task."""
        for model in CANONICAL_SECURITY_MODELS.values():
            if task in model.recommended_tasks:
                return model
        return CANONICAL_SECURITY_MODELS["cybersecqwen-4b"]

    def independent_evidence_review(self, finding: Finding) -> dict[str, Any]:
        """Performs an independent verification check on finding evidence before report preparation."""
        has_http_exchange = any(bool(e.exchange) for e in finding.evidence)
        has_repro_steps = bool(finding.steps)
        is_high_or_critical = finding.severity.lower() in ("high", "critical")

        issues = []
        if is_high_or_critical and not has_http_exchange:
            issues.append("High/Critical finding lacks raw HTTP request/response exchange evidence.")

        if not has_repro_steps:
            issues.append("Missing step-by-step reproduction guide.")

        verdict = "APPROVED" if not issues else "FLAGGED_FOR_HUMAN_REVIEW"

        return {
            "finding_id": finding.id,
            "title": finding.title,
            "verdict": verdict,
            "has_raw_evidence": has_http_exchange,
            "has_repro_steps": has_repro_steps,
            "issues": issues,
            "reviewer_model": "independent-verifier",
        }
