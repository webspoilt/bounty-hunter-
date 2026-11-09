"""Local Ollama Qwen Coder adapter for offline code generation and review.

Interfaces with the local Ollama runtime for code generation and analysis while
preserving strict separation from the Tev1 structured decision interface.
Includes concurrency bounding to ensure long code-generation runs never starve
high-priority Tev1 decision queries.
"""
from __future__ import annotations

import os
import threading
from typing import Any

from bb.config import MODEL, OLLAMA
from bb.llm import Ollama, OllamaError

# Global concurrency guard: limits simultaneous heavy code-generation requests
# to prevent monopolizing local GPU/CPU and starving Tev1 decision requests.
_CODER_SEMAPHORE = threading.BoundedSemaphore(value=1)
_DECISION_PRIORITY_LOCK = threading.Lock()


class QwenCoderAdapter:
    """Adapter for local Qwen Coder models running on Ollama."""

    # Common tags in order of preference for coding tasks
    PREFERRED_TAGS = [
        os.environ.get("BB_CODER_MODEL", ""),
        "qwen2.5-coder:7b",
        "qwen2.5-coder:14b",
        "qwen2.5-coder:32b",
        "qwen2.5-coder:1.5b",
        "qwen2.5-coder:latest",
        "freehuntx/qwen3-coder:8b",
        MODEL,
    ]

    def __init__(
        self,
        base_url: str = OLLAMA,
        model_tag: str | None = None,
        timeout: float = 300.0,
        keep_alive: str = "5m",
    ):
        self.base_url = base_url.rstrip("/")
        self.preferred_model = model_tag
        self.timeout = timeout
        self.keep_alive = keep_alive
        self.client = Ollama(base=self.base_url, timeout=self.timeout)

    def is_available(self) -> bool:
        """Check if Ollama is running."""
        return self.client.available()

    def get_installed_models(self) -> list[str]:
        """Return list of models installed in local Ollama runtime."""
        return self.client.models()

    def is_model_installed(self, tag: str) -> bool:
        """Check if a specific model tag is installed in Ollama."""
        installed = self.get_installed_models()
        if not installed:
            return False
        if tag in installed:
            return True
        for m in installed:
            if m.startswith(tag + ":") or tag.startswith(m + ":"):
                return True
        return False

    def resolve_model(self, validate: bool = True) -> str:
        """Probe Ollama and validate the configured tag or pick the best installed coder model.

        Raises:
            OllamaError: If the configured model or any coder model is not installed.
        """
        configured = (self.preferred_model or os.environ.get("BB_CODER_MODEL", "")).strip()
        installed = self.get_installed_models()

        if configured:
            if validate and installed and not self.is_model_installed(configured):
                raise OllamaError(
                    f"Configured Qwen coder model '{configured}' is not installed in local Ollama. "
                    f"Installed models: {', '.join(installed)}."
                )
            return configured

        if not installed:
            if validate:
                raise OllamaError("No models found in local Ollama runtime. Qwen Coder must be installed.")
            return MODEL

        # 1. Exact match against preferred list
        for candidate in self.PREFERRED_TAGS:
            if candidate and candidate in installed:
                return candidate

        # 2. Fuzzy match: contains 'qwen' and 'coder'
        for model_name in installed:
            lower = model_name.lower()
            if "qwen" in lower and "coder" in lower:
                return model_name

        # 3. Fuzzy match: contains 'coder'
        for model_name in installed:
            if "coder" in model_name.lower():
                return model_name

        if validate:
            raise OllamaError(
                f"No Qwen coder model found among installed Ollama models: {', '.join(installed)}. "
                "Please install a Qwen Coder model (e.g. 'ollama pull qwen2.5-coder:7b')."
            )
        return installed[0]

    def _chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        num_ctx: int = 8192,
    ) -> str:
        """Send chat request bounded by concurrency semaphore."""
        if not self.is_available():
            raise OllamaError("Local Ollama runtime is not reachable at " + self.base_url)

        model = self.resolve_model()

        # Concurrency bounding: acquire semaphore so code gen doesn't starve decisions
        acquired = _CODER_SEMAPHORE.acquire(timeout=self.timeout)
        if not acquired:
            raise OllamaError(
                "Local coder is busy: could not acquire generation lock within timeout."
            )
        try:
            # We call client.chat with the resolved model and configured residency
            return self.client.chat(
                messages,
                model=model,
                temperature=temperature,
                timeout=self.timeout,
                num_ctx=num_ctx,
                keep_alive=self.keep_alive,
            )
        finally:
            _CODER_SEMAPHORE.release()

    def inspect_code(self, files: dict[str, str], task_objective: str) -> str:
        """Ask Qwen Coder to inspect files and summarize context before editing."""
        files_text = "\n\n".join(
            f"--- FILE: {path} ---\n{content}" for path, content in files.items()
        )
        prompt = (
            f"You are a careful security and systems programmer.\n"
            f"TASK OBJECTIVE: {task_objective}\n\n"
            f"INSPECT THE FOLLOWING RELEVANT FILES BEFORE EDITING:\n"
            f"{files_text}\n\n"
            f"Provide a concise analysis:\n"
            f"1. Existing architecture & patterns observed in the files.\n"
            f"2. Precise points where modifications should be made.\n"
            f"3. Potential pitfalls, backward compatibility concerns, and edge cases.\n"
            f"Do not write final implementation code yet; perform inspection only."
        )
        messages = [
            {"role": "system", "content": "You are an expert code inspection assistant."},
            {"role": "user", "content": prompt},
        ]
        return self._chat(messages, temperature=0.1)

    def generate_diff(
        self,
        objective: str,
        files: dict[str, str],
        acceptance_criteria: list[str],
        instructions: str = "",
    ) -> str:
        """Ask Qwen Coder to generate minimal unified diff / patch for the task."""
        files_text = "\n\n".join(
            f"--- FILE: {path} ---\n{content}" for path, content in files.items()
        )
        criteria_text = "\n".join(f"- {c}" for c in acceptance_criteria) if acceptance_criteria else "Standard quality"
        prompt = (
            f"You are an expert coding assistant.\n"
            f"OBJECTIVE: {objective}\n\n"
            f"ACCEPTANCE CRITERIA:\n{criteria_text}\n\n"
            f"ADDITIONAL INSTRUCTIONS:\n{instructions or 'Follow existing style and idioms.'}\n\n"
            f"SOURCE FILES:\n{files_text}\n\n"
            f"Please output clean code changes or a unified diff that implements ONLY the assigned objective.\n"
            f"Do not modify unrelated code or tests."
        )
        messages = [
            {"role": "system", "content": "You are a precise coding agent generating clean changes."},
            {"role": "user", "content": prompt},
        ]
        return self._chat(messages, temperature=0.2)

    def review_diff(self, diff: str, acceptance_criteria: list[str]) -> str:
        """Ask Qwen Coder to review a diff against acceptance criteria."""
        criteria_text = "\n".join(f"- {c}" for c in acceptance_criteria) if acceptance_criteria else "None"
        prompt = (
            f"Review the following diff against the given acceptance criteria:\n\n"
            f"ACCEPTANCE CRITERIA:\n{criteria_text}\n\n"
            f"DIFF:\n{diff}\n\n"
            f"Provide:\n"
            f"1. Check whether each criterion is met.\n"
            f"2. Any syntax, logical, or safety flaws.\n"
            f"3. Verdict: APPROVED or NEEDS_REVISION."
        )
        messages = [
            {"role": "system", "content": "You are a thorough code review assistant."},
            {"role": "user", "content": prompt},
        ]
        return self._chat(messages, temperature=0.1)
