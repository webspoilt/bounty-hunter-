"""Tev1 — local structured decision model client (Ollama `/v1/systemone`).

Decision points need a *choice*, not prose. Tev1 is asked to pick exactly one
option from a caller-supplied list; Python validates the reply against the
exact options and owns the consequences. The model only recommends; it can
never grant authorization.

Realities this client faces honestly (verified 2026-11-07 against Ollama
0.40.15):

* The decision endpoint is probed first. On stock Ollama, an unknown route
  falls through to the generate handler and answers ``404 model not found``
  — that is recorded as "endpoint not implemented", not hidden.
* Ordinary chat completion is never used as a substitute for the decision
  endpoint.
* If Tev1 is unavailable or returns a schema-invalid reply, a deterministic
  fallback decision is returned instead, and the *reason* travels with the
  result so operators see exactly why.

Invariants:
* Recorded in every result: model tag, model digest, Ollama version and the
  contract version that governed the exchange.
* State sent is compact and structured: secret-looking keys are redacted,
  long strings are truncated, there are no request bodies, no HAR files and
  no credentials.
* ``confidence`` is advisory metadata only — nothing reads it to decide
  whether an action is permitted.
* This module performs no writes: it cannot change scope, permissions,
  request limits or kill-switch state. Callers decide what to do with the
  validated choice.
"""
from __future__ import annotations

import json

import httpx

from bb import redact
from bb.config import OLLAMA
from bb.llm import Ollama

CONTRACT = "tev1-decision/v1"
MODEL_TAG = "tev1:0.8b"
ENDPOINT_PATH = "/v1/systemone"
MAX_CONTEXT_CHARS = 4096          # whole serialized context cap; larger -> no send
MAX_ITEM_CHARS = 500              # per-string truncation inside the context
NONE = "none"

FALLBACK_SOURCE = "deterministic-fallback"
TEV1_SOURCE = "tev1"


def _sanitize(value, depth: int = 0):
    """Compact, redacted representation of caller state. No bodies, no secrets."""
    if depth > 6:
        return "[DEPTH]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if redact.SECRET_KEYS.search(str(k)) and not isinstance(v, (dict, list)):
                out[str(k)] = redact.MASK
            else:
                out[str(k)] = _sanitize(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_sanitize(v, depth + 1) for v in value[:20]]
    if isinstance(value, str):
        text = redact.redact_body(value, cap=MAX_ITEM_CHARS)
        return text[:MAX_ITEM_CHARS]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_ITEM_CHARS]


def _compact(context: dict | None) -> dict:
    ctx = _sanitize(context or {})
    text = json.dumps(ctx, default=str)
    while len(text) > MAX_CONTEXT_CHARS:
        # drop the deepest items first: walk once, halve any overlong lists
        trimmed = False
        for v in ctx.values():
            if isinstance(v, list) and v:
                v[:] = v[: max(1, len(v) // 2)]
                trimmed = True
        if not trimmed:                      # dictionaries won that argument already
            for v in ctx.values():
                if isinstance(v, dict) and v:
                    k0 = next(iter(v))
                    v.pop(k0)
                    trimmed = True
                    break
        if not trimmed:
            ctx = {"note": "context too large to serialize", "dropped": True}
            break
        text = json.dumps(ctx, default=str)
    return json.loads(text) if text else {}


class Tev1Client:
    """Validated decision client. One deterministic answer per call, always."""

    def __init__(self, base: str = OLLAMA, model: str = MODEL_TAG,
                 transport: httpx.BaseTransport | None = None, timeout: float = 30.0):
        self.base = base.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._http = httpx.Client(base_url=self.base, transport=transport,
                                  timeout=timeout)
        self._probe: dict | None = None

    def _ask(self, payload: dict) -> dict | None:
        """POST the decision contract. Returns parsed dict or None (unavailable)."""
        try:
            r = self._http.post(ENDPOINT_PATH, json=payload)
            if r.status_code != 200:
                return None
            body = r.json()
            return body if isinstance(body, dict) else None
        except Exception:
            return None

    def _tags(self) -> dict:
        try:
            r = self._http.get("/api/tags")
            models = r.json().get("models", []) if r.status_code == 200 else []
            for m in models:
                if m.get("name") == self.model or m.get("name") == f"{self.model}:latest":
                    return {"name": m.get("name", ""), "digest": m.get("digest", "")}
        except Exception:
            pass
        return {"name": "", "digest": ""}

    def _version(self) -> str:
        try:
            r = self._http.get("/api/version")
            return str(r.json().get("version", "")) if r.status_code == 200 else ""
        except Exception:
            return ""

    def probe(self, force: bool = False) -> dict:
        """Truthful availability report. Deterministic fallback must stay reliable."""
        if self._probe is not None and not force:
            return self._probe
        report = {
            "endpoint": f"{self.base}{ENDPOINT_PATH}",
            "model": self.model,
            "digest": "",
            "ollama_version": self._version(),
            "endpoint_ok": False,
            "detail": "",
        }
        tags = self._tags()
        report["digest"] = tags.get("digest", "")
        if not report["ollama_version"]:
            report["detail"] = "ollama not reachable"
            self._probe = report
            return report
        if not tags.get("digest"):
            report["detail"] = f"model {self.model!r} not present in ollama tags"
            self._probe = report
            return report
        body = self._ask({"contract": CONTRACT, "model": self.model,
                          "decision_point": "probe", "question": "selftest",
                          "options": ["ok"], "context": {}})
        if isinstance(body, dict) and body.get("choice") == "ok":
            report["endpoint_ok"] = True
            report["detail"] = "decision contract answered"
        else:
            report["detail"] = "endpoint did not answer the decision contract"
        self._probe = report
        return report

    def metadata(self) -> dict:
        """Model/runtime provenance recorded with every decision."""
        tags = self._tags()
        return {
            "model": self.model,
            "digest": tags.get("digest", ""),
            "ollama_version": self._version(),
            "contract": CONTRACT,
            "endpoint": f"{self.base}{ENDPOINT_PATH}",
        }

    def decide(self, decision_point: str, options: list[str], context: dict | None = None,
               *, question: str = "", allow_none: bool = True,
               default: str | None = None) -> dict:
        """Ask Tev1 to pick exactly one option. Always returns a decision dict.

        The validated choice is trusted as a *recommendation* only. On outside
        the option list, schema failure or unreachable endpoint, a fallback
        choice is returned with an explaining reason.
        """
        choices = [str(o) for o in options]
        if allow_none and NONE not in choices:
            choices.append(NONE)
        if not choices:
            raise ValueError("decide() requires at least one option")

        ctx = _compact(context)
        result = self.metadata()
        result.update({
            "decision_point": decision_point,
            "options": list(choices),
            "source": FALLBACK_SOURCE,
            "choice": default if (default in choices and default is not None) else NONE,
        })

        payload = {"contract": CONTRACT, "model": self.model,
                   "decision_point": decision_point, "question": question[:500],
                   "options": choices, "context": ctx}
        body = self._ask(payload)

        if not isinstance(body, dict):
            result["reason"] = ("decision endpoint unavailable; deterministic "
                                "fallback applied")
            return result
        if body.get("contract") not in (None, CONTRACT):
            result["reason"] = (f"reply contract {body.get('contract')!r} does not "
                                f"match {CONTRACT!r}")
            return result
        choice = body.get("choice")
        if not isinstance(choice, str) or choice.strip() not in choices:
            result["reason"] = (f"reply choice {choice!r} is not one of the "
                                "supplied options; refused")
            return result
        confidence = body.get("confidence")
        if confidence is not None and not isinstance(confidence, (int, float)):
            confidence = None
        elif isinstance(confidence, (int, float)) and not (0.0 <= confidence <= 1.0):
            confidence = None
        result.update({
            "source": TEV1_SOURCE,
            "choice": choice.strip(),
            "confidence": None if confidence is None else round(float(confidence), 4),
            "reason": str(body.get("reason") or "")[:300] or "model recommended a "
                                                               "listed choice",
        })
        return result

    def close(self) -> None:
        self._http.close()


def decide(decision_point: str, options: list[str], context: dict | None = None,
           *, question: str = "", allow_none: bool = True, default: str | None = None,
           client: Tev1Client | None = None) -> dict:
    """Convenience entry point used by execution paths (one probe per client)."""
    c = client or Tev1Client()
    try:
        return c.decide(decision_point, options, context, question=question,
                        allow_none=allow_none, default=default)
    finally:
        if client is None:
            c.close()


def format_status(report: dict) -> str:
    ok = report.get("endpoint_ok", False)
    return (f"endpoint: {report.get('endpoint', '?')}\n"
            f"model:    {report.get('model', '?')}\n"
            f"digest:   {report.get('digest') or 'n/a'}\n"
            f"decision endpoint: {'OK' if ok else 'MISS'}  "
            f"({report.get('detail') or 'no probe yet'})\n"
            f"ollama:   {report.get('ollama_version') or '?'}")
