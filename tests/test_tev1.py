"""Tev1 structured decision client — contract validation and fallback behaviour.

All tests are offline: they inject an httpx.MockTransport, so nothing touches
the network or a live Ollama. The auto-loop integration test proves the real
execution path runs and records the decision metadata on findings.
"""
import json

import httpx
import pytest

from bb import tev1
from bb.tev1 import Tev1Client, decide

OLLAMA_FIXTURE = {
    "version": "9.9.9-test",
}


def _router(handler):
    return httpx.MockTransport(handler)


def _tags_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/api/version":
        return httpx.Response(200, json={"version": "9.9.9-test"})
    if request.url.path == "/api/tags":
        return httpx.Response(200, json={"models": [
            {"name": "tev1:0.8b", "digest": "abc123digest"}]})
    return httpx.Response(404)


def test_probe_reports_truthfully_when_endpoint_answers():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == tev1.ENDPOINT_PATH:
            body = json.loads(request.content.decode())
            assert body["contract"] == tev1.CONTRACT
            return httpx.Response(200, json={"contract": tev1.CONTRACT,
                                             "choice": "ok", "confidence": 0.9})
        return _tags_handler(request)

    rep = Tev1Client(transport=_router(handler)).probe()
    assert rep["endpoint_ok"] is True
    assert rep["ollama_version"] == "9.9.9-test"
    assert rep["digest"] == "abc123digest"


def test_probe_records_missing_model_without_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "9.9.9-test"})
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [
                {"name": "qwen2.5:3b", "digest": "d1"}]})
        # stock ollama fallthrough: unknown model -> 404 error json
        return httpx.Response(404, json={"error":
                                         "model 'tev1:0.8b' not found"})

    rep = Tev1Client(transport=_router(handler)).probe()
    assert rep["endpoint_ok"] is False
    assert rep["digest"] == ""
    assert "not present" in rep["detail"]


def test_decide_validates_choice_against_exact_options():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == tev1.ENDPOINT_PATH:
            return httpx.Response(200, json={"contract": tev1.CONTRACT,
                                             "choice": "likely-real",
                                             "confidence": 0.75,
                                             "reason": "evidence consistent"})
        return _tags_handler(request)

    r = Tev1Client(transport=_router(handler)).decide(
        "auto-triage", ["likely-real", "inconclusive"], {"bug_class": "IDOR"})
    assert r["source"] == "tev1"
    assert r["choice"] == "likely-real"
    assert r["confidence"] == 0.75
    assert r["contract"] == tev1.CONTRACT


def test_decide_refuses_choice_outside_options():
    """A choice not supplied by the caller must never be respected."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == tev1.ENDPOINT_PATH:
            return httpx.Response(200, json={"contract": tev1.CONTRACT,
                                             "choice": "grant-full-write-access"})
        return _tags_handler(request)

    r = Tev1Client(transport=_router(handler)).decide(
        "auto-triage", ["likely-real", "none"], {})
    assert r["source"] == "deterministic-fallback"
    assert r["choice"] == "none"
    assert "not one of the supplied options" in r["reason"]


def test_decide_rejects_contract_mismatch():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == tev1.ENDPOINT_PATH:
            return httpx.Response(200, json={"contract": "whatever/v0",
                                             "choice": "likely-real"})
        return _tags_handler(request)

    r = Tev1Client(transport=_router(handler)).decide(
        "point", ["likely-real"], {})
    assert r["source"] == "deterministic-fallback"
    assert r["choice"] == "none"
    assert "does not match" in r["reason"]


def test_decide_falls_back_when_endpoint_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    r = Tev1Client(transport=_router(handler)).decide(
        "point", ["a", "none"], {}, default="a")
    assert r["source"] == "deterministic-fallback"
    assert r["choice"] == "a"
    assert "unavailable" in r["reason"]


def test_decide_context_is_redacted_before_sending():
    sent = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"contract": tev1.CONTRACT,
                                         "choice": "none"})

    Tev1Client(transport=_router(handler)).decide(
        "point", ["none"],
        {"token": "supersecret-tok", "note": "bearer 0123456789abcdef secret",
         "bug_class": "IDOR"})
    ctx = sent["body"]["context"]
    assert ctx["token"] == "[REDACTED]"
    assert "0123456789abcdef" not in json.dumps(ctx)
    assert ctx["bug_class"] == "IDOR"


def test_decide_oversized_context_never_sends_payload():
    sent = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"contract": tev1.CONTRACT, "choice": "none"})

    huge = {"blob": "x" * (tev1.MAX_CONTEXT_CHARS * 3)}
    r = Tev1Client(transport=_router(handler)).decide("point", ["none"], huge)
    body = sent["body"]
    assert len(json.dumps(body["context"])) <= tev1.MAX_CONTEXT_CHARS
    assert r["choice"] == "none"    # service still answered; oversized state reduced


def test_decide_confidence_out_of_range_is_dropped():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == tev1.ENDPOINT_PATH:
            return httpx.Response(200, json={"contract": tev1.CONTRACT,
                                             "choice": "none",
                                             "confidence": 7.5})
        return _tags_handler(request)

    r = Tev1Client(transport=_router(handler)).decide("point", ["none"], {})
    assert r["confidence"] is None
    assert r["source"] == "tev1"


def test_decide_records_runtime_provenance():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == tev1.ENDPOINT_PATH:
            return httpx.Response(200, json={"contract": tev1.CONTRACT, "choice": "none"})
        return _tags_handler(request)

    r = Tev1Client(transport=_router(handler)).decide("point", ["none"], {})
    assert r["model"] == tev1.MODEL_TAG
    assert r["digest"] == "abc123digest"
    assert r["ollama_version"] == "9.9.9-test"
    assert r["contract"] == tev1.CONTRACT


def _finding(base_id="f-tv1"):
    from bb.models import Evidence, Exchange, Finding
    ex = Exchange(method="GET", url="https://app.example.com/api/x", status=200,
                  request_body="", response_body="", response_headers={})
    return Finding(id=base_id, title="t", bug_class="IDOR", severity="high",
                   confidence="high", status="candidate",
                   url="https://app.example.com/api/x",
                   host="app.example.com", summary="s",
                   evidence=[Evidence(summary="e", exchange=ex)])


def test_auto_loop_consults_decision_model_with_valid_option_set(tmp_path, monkeypatch):
    """The real triage helper validates against engine options + none/defer."""
    from bb.auto import AutoHunter, AutoHunterConfig
    from bb.scope import Scope
    from bb.store import Store

    calls = []

    def fake_decide(point, options, ctx, **kw):
        calls.append((point, list(options), ctx))
        return {"decision_point": point, "model": tev1.MODEL_TAG,
                "digest": "d", "ollama_version": "9.9.9-test",
                "contract": tev1.CONTRACT, "source": "tev1",
                "choice": "likely-real", "confidence": 0.8, "reason": "ok",
                "options": list(options)}

    monkeypatch.setattr(tev1, "decide", fake_decide)

    store = Store(path=tmp_path / "tv1.db")
    scope = Scope(["app.example.com"])
    cfg = AutoHunterConfig(program="example", scope=scope,
                           entry_urls=["https://app.example.com/"],
                           dry_run=True, llm=False, run_waf_probe=False,
                           cve_match=False, ai_analysis=False, queue=False)
    hunter = AutoHunter(cfg, store=store, log=lambda m: None)
    meta = hunter._tev1_triage(_finding())
    assert calls, "triage path did not consult the decision model"
    point, options, ctx = calls[0]
    assert point == "auto-triage"
    assert "none" in options and "defer" in options
    assert meta["source"] == "tev1" and meta["choice"] == "likely-real"
    # compact structured context only — no bodies, no credentials
    assert "evidence_count" in ctx and ctx["bug_class"] == "IDOR"
    assert all(len(json.dumps(v)) < 1200 for v in ctx.values())


def test_auto_loop_persists_te1_metadata_end_to_end(tmp_path, monkeypatch):
    """Integration: run() phase 7 really records tev1_triage for a found finding."""
    from bb import checks
    from bb.auto import AutoHunter, AutoHunterConfig
    from bb.scope import Scope
    from bb.store import Store

    finding = _finding("f-loop")
    finding.meta["similarity"] = 0.93

    monkeypatch.setattr(checks.Checker, "run_all",
                        lambda self, entries, endpoints: [finding])
    monkeypatch.setattr(tev1, "decide", lambda *a, **k: {
        "decision_point": a[0], "model": tev1.MODEL_TAG, "digest": "d",
        "ollama_version": "9.9.9-test", "contract": tev1.CONTRACT,
        "source": "tev1", "choice": "defer", "confidence": None, "reason": "r",
        "options": list(a[1])})

    store = Store(path=tmp_path / "tv1b.db")
    scope = Scope(["app.example.com"])
    cfg = AutoHunterConfig(program="example", scope=scope,
                           entry_urls=["https://app.example.com/"], dry_run=True,
                           llm=False, run_waf_probe=False, cve_match=False,
                           ai_analysis=False, queue=False)
    hunter = AutoHunter(cfg, store=store, log=lambda m: None)
    res = hunter.run()
    assert res["status"] == "completed"
    stored = store.get_finding("f-loop")
    assert stored is not None
    rec = stored.meta["tev1_triage"]
    assert rec["source"] == "tev1"
    assert rec["choice"] == "defer"
    assert rec["contract"] == tev1.CONTRACT
