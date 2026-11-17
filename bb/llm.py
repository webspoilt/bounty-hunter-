"""Ollama client: chat + embeddings, with timeouts and honest failures.

The tool works without a model (deterministic templates); the model makes reports better.
"""
from __future__ import annotations

import json
import re

import httpx

from bb.config import (COARENA_API_KEY, COARENA_BASE, COARENA_MODEL,
                       EMBED_MODEL, LLM_PROVIDER, MODEL, OLLAMA)


class LLMError(RuntimeError):
    pass


# historical name: callers still catch OllamaError
OllamaError = LLMError


class Ollama:
    def __init__(self, base: str = OLLAMA, chat_model: str = MODEL,
                 embed_model: str = EMBED_MODEL, timeout: float = 180.0):
        self.base = base.rstrip("/")
        self.chat_model = chat_model
        self.embed_model = embed_model
        self.timeout = timeout

    def available(self) -> bool:
        try:
            r = httpx.get(f"{self.base}/api/tags", timeout=3.0)
            return r.status_code == 200
        except Exception:
            return False

    def models(self) -> list[str]:
        try:
            r = httpx.get(f"{self.base}/api/tags", timeout=5.0)
            r.raise_for_status()
            return [m.get("name", "") for m in r.json().get("models", [])]
        except Exception:
            return []

    def chat(self, messages: list[dict], *, model: str | None = None,
             temperature: float = 0.2, timeout: float | None = None,
             num_ctx: int = 8192, keep_alive: str | None = None) -> str:
        payload = {
            "model": model or self.chat_model,
            "stream": False,
            "messages": messages,
            "options": {"temperature": temperature, "num_ctx": num_ctx},
        }
        if keep_alive is not None:
            payload["keep_alive"] = keep_alive
        last_err: Exception | None = None
        for _ in range(2):
            try:
                r = httpx.post(f"{self.base}/api/chat", json=payload,
                               timeout=timeout or self.timeout)
                r.raise_for_status()
                return r.json().get("message", {}).get("content", "")
            except Exception as exc:                       # one retry, then surface it
                last_err = exc
        raise OllamaError(f"ollama chat failed: {last_err}")

    def embed(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        if not texts:
            return []
        payload = {"model": model or self.embed_model, "input": texts}
        try:
            r = httpx.post(f"{self.base}/api/embed", json=payload, timeout=180.0)
            r.raise_for_status()
            data = r.json()
            embeddings = data.get("embeddings")
            if not embeddings:
                raise OllamaError("no embeddings in response")
            return embeddings
        except OllamaError:
            raise
        except Exception as exc:
            raise OllamaError(f"ollama embed failed: {exc}") from exc

    def json_reply(self, messages: list[dict], *, model: str | None = None) -> dict | None:
        text = self.chat(messages, model=model, temperature=0.1)
        return extract_json(text)


class OpenAICompatible:
    """Hosted OpenAI-compatible chat API (e.g. Coarena's free Model API).

    The hosted endpoint has no embeddings route, so embeddings are delegated to
    a local Ollama instance. The API key is sent only in the Authorization
    header and is never written to logs or exception text.
    """

    def __init__(self, base: str = COARENA_BASE, api_key: str = COARENA_API_KEY,
                 chat_model: str = COARENA_MODEL, timeout: float = 180.0,
                 embed_fallback: "Ollama | None" = None):
        self.base = base.rstrip("/")
        self._api_key = api_key
        self.chat_model = chat_model
        self.timeout = timeout
        self._embed_fallback = embed_fallback

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json"}

    def available(self) -> bool:
        if not self._api_key:
            return False
        try:
            r = httpx.get(f"{self.base}/models", headers=self._headers(), timeout=5.0)
            return r.status_code == 200
        except Exception:
            return False

    def models(self) -> list[str]:
        if not self._api_key:
            return []
        try:
            r = httpx.get(f"{self.base}/models", headers=self._headers(), timeout=5.0)
            r.raise_for_status()
            return [m.get("id", "") for m in r.json().get("data", [])]
        except Exception:
            return []

    def chat(self, messages: list[dict], *, model: str | None = None,
             temperature: float = 0.2, timeout: float | None = None,
             max_tokens: int | None = None, **_: object) -> str:
        payload: dict = {
            "model": model or self.chat_model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        last_err: Exception | None = None
        for _ in range(2):
            try:
                r = httpx.post(f"{self.base}/chat/completions", json=payload,
                               headers=self._headers(),
                               timeout=timeout or self.timeout)
                if r.status_code >= 400:
                    try:
                        detail = r.json().get("error", {}).get("message", "")
                    except Exception:
                        detail = ""
                    raise LLMError(
                        f"hosted chat failed: HTTP {r.status_code}"
                        + (f": {detail}" if detail else ""))
                choices = r.json().get("choices") or []
                message = (choices[0].get("message") or {}) if choices else {}
                return message.get("content") or ""
            except LLMError:
                raise                                   # API errors are not retried
            except Exception as exc:                    # network/parse: one retry
                last_err = exc
        raise LLMError(f"hosted chat failed: {last_err}")

    def embed(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        if not texts:
            return []
        if self._embed_fallback is None:
            self._embed_fallback = Ollama(embed_model=model or EMBED_MODEL)
        return self._embed_fallback.embed(texts, model=model)

    def json_reply(self, messages: list[dict], *, model: str | None = None) -> dict | None:
        text = self.chat(messages, model=model, temperature=0.1)
        return extract_json(text)


LLMProvider = Ollama | OpenAICompatible


def get_llm(provider: str | None = None, **kwargs) -> "Ollama | OpenAICompatible":
    """Return the configured chat client without changing any caller contract."""
    chosen = (provider or LLM_PROVIDER or "ollama").strip().lower()
    if chosen in ("coarena", "openai"):
        if not COARENA_API_KEY:
            raise LLMError("COARENA_API_KEY is not configured")
        return OpenAICompatible(**kwargs)
    if chosen == "ollama":
        return Ollama(**kwargs)
    raise LLMError(f"unknown LLM provider: {chosen}")


def extract_json(text: str) -> dict | None:
    """Pull the first balanced JSON object out of model output."""
    if not text:
        return None
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def split_sections(text: str) -> dict[str, str]:
    """Parse '## Summary' style output from a model into a dict."""
    out: dict[str, str] = {}
    current = None
    for line in (text or "").splitlines():
        m = re.match(r"^#{1,3}\s*(summary|impact|remediation|steps|title)\s*$", line.strip(), re.I)
        if m:
            current = m.group(1).lower()
            out[current] = ""
        elif current:
            out[current] += line + "\n"
    return {k: v.strip() for k, v in out.items() if v.strip()}
