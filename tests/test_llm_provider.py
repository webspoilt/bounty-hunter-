"""Regression tests for the hosted OpenAI-compatible chat provider.

No network is used: httpx.get/post are replaced with in-process fakes.
"""
from __future__ import annotations

import httpx
import pytest

from bb import llm as llm_mod
from bb.llm import LLMError, OpenAICompatible, get_llm


def test_get_llm_selects_coarena_when_configured(monkeypatch):
    monkeypatch.setattr(llm_mod, "COARENA_API_KEY", "test-key")
    client = get_llm("coarena")
    assert isinstance(client, OpenAICompatible)
    assert client.chat_model == llm_mod.COARENA_MODEL
    assert client.base == llm_mod.COARENA_BASE.rstrip("/")


def test_get_llm_rejects_missing_key(monkeypatch):
    monkeypatch.setattr(llm_mod, "COARENA_API_KEY", "")
    with pytest.raises(LLMError, match="COARENA_API_KEY"):
        get_llm("coarena")


def test_get_llm_rejects_unknown_provider():
    with pytest.raises(LLMError, match="unknown LLM provider"):
        get_llm("does-not-exist")


def test_chat_parses_openai_response_and_sends_bearer(monkeypatch):
    seen = {}

    def fake_post(url, **kwargs):
        seen["url"] = url
        seen["headers"] = kwargs.get("headers", {})
        seen["json"] = kwargs.get("json", {})
        return httpx.Response(200, json={
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        })

    monkeypatch.setattr(llm_mod.httpx, "post", fake_post)
    client = OpenAICompatible(base="https://example.test/v1", api_key="secret-key",
                              chat_model="some-model")
    out = client.chat([{"role": "user", "content": "hi"}], temperature=0.3)

    assert out == "ok"
    assert seen["url"] == "https://example.test/v1/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer secret-key"
    assert seen["json"]["model"] == "some-model"
    assert seen["json"]["stream"] is False
    assert seen["json"]["temperature"] == 0.3


def test_chat_api_error_never_leaks_key(monkeypatch):
    monkeypatch.setattr(
        llm_mod.httpx, "post",
        lambda url, **kw: httpx.Response(
            401, json={"error": {"message": "invalid api key"}}))

    client = OpenAICompatible(base="https://example.test/v1", api_key="super-secret")
    with pytest.raises(LLMError) as excinfo:
        client.chat([{"role": "user", "content": "hi"}])

    msg = str(excinfo.value)
    assert "HTTP 401" in msg
    assert "invalid api key" in msg
    assert "super-secret" not in msg


def test_embed_delegates_to_local_fallback():
    class FakeOllama:
        def __init__(self):
            self.calls = []

        def embed(self, texts, *, model=None):
            self.calls.append((list(texts), model))
            return [[0.1, 0.2] for _ in texts]

    fallback = FakeOllama()
    client = OpenAICompatible(api_key="k", embed_fallback=fallback)
    assert client.embed(["a", "b"]) == [[0.1, 0.2], [0.1, 0.2]]
    assert fallback.calls == [(["a", "b"], None)]
