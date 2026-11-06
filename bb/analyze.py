"""AI response analysis and next-test suggestions — grounded, redacted, advisory.

This is deliberately *not* an autonomous agent. It reads what the run already captured
(redacted exchanges), asks the local model for a structured second opinion, validates
every field, and returns suggestions for a human to run. It never sends a request,
never changes a finding's status, and never queues anything.

The deterministic analyzer always works (no model, no network). The model pass only
adds nuance; if Ollama is down or the reply fails validation, the offline result is
returned unchanged. That keeps the tool usable on a laptop with no GPU.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from bb.llm import Ollama, OllamaError

MAX_TESTS = 8
MAX_BODY = 2500
VERDICTS = ("likely-real", "needs-ownership-check", "likely-false-positive", "inconclusive")
RISKS = ("read-only", "state-change", "needs-write-permission")
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


def _strip_secrets(text: str) -> str:
    """Defence in depth: exchanges are already redacted, but never leak a bearer token."""
    text = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,}\"']+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|token|secret|password)\"?\s*[:=]\s*\")[^\"]+",
                  r"\1[REDACTED]", text)
    return text


def build_context(finding) -> dict:
    evidence = []
    for ev in finding.evidence[:4]:
        ex = ev.exchange
        if ex is None:
            evidence.append({"summary": ev.summary, "exchange": None})
            continue
        evidence.append({
            "summary": ev.summary,
            "method": ex.method,
            "url": ex.url,
            "status": ex.status,
            "response_headers": {k: v for k, v in ex.response_headers.items()
                                 if k.lower() in ("content-type", "location", "access-control-allow-origin",
                                                  "access-control-allow-credentials", "server")},
            "body_excerpt": _strip_secrets((ex.response_body or "")[:MAX_BODY]),
        })
    return {
        "id": finding.id,
        "title": finding.title,
        "bug_class": finding.bug_class,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": finding.status,
        "url": finding.url,
        "host": finding.host,
        "summary": _strip_secrets(finding.summary or ""),
        "impact": _strip_secrets(finding.impact or ""),
        "signals": finding.meta.get("similarity") and {
            "similarity": finding.meta.get("similarity"),
            "a_owns": finding.meta.get("a_owns"),
            "b_owns": finding.meta.get("b_owns"),
        } or {},
        "evidence": evidence,
    }


def _path_of(url: str) -> str:
    parts = urlsplit(url or "")
    return parts.path or "/"


def analyze_offline(finding) -> dict:
    """Deterministic next tests from the finding shape. No model involvement."""
    path = _path_of(finding.url)
    tests: list[dict] = []
    cls = finding.bug_class

    def add(method: str, p: str, why: str, risk: str = "read-only") -> None:
        if len(tests) < MAX_TESTS and not any(
                t["method"] == method and t["path"] == p for t in tests):
            tests.append({"method": method, "path": p, "why": why, "risk": risk})

    if cls == "IDOR":
        add("GET", path, "Repeat the replay with the other role after a fresh login; "
                         "confirm the owner marker still appears.")
        add("GET", path, "Try the sibling object one id higher/lower with the attacker "
                         "session to confirm the boundary is missing, not just this row.")
        add("HEAD", path, "Check whether the same path leaks existence via status/length "
                          "differences to an unauthorised role.")
        add("GET", path, "Add a second account from a different tenant if the program "
                          "provides one; tenant boundaries often fail separately.")
    elif cls == "Broken Authentication":
        add("GET", path, "Replay anonymously from a clean client (no cookies/tokens).")
        add("GET", path, "Replay with a deliberately invalid/expired token to distinguish "
                          "'no auth check' from 'weak auth check'.")
    elif cls == "Open Redirect":
        add("GET", finding.url, "Vary the redirect parameter with a relative path and a "
                                "scheme-relative target; note which are accepted.")
    elif cls == "CORS":
        add("GET", finding.url, "Replay with a second attacker origin to confirm the "
                                "reflection is generic, not a one-off allow-list entry.")
    elif cls == "GraphQL":
        add("POST", path, "Re-run introspection after authentication to see whether hidden "
                          "types/fields appear only for a privileged role.")
        add("POST", path, "Try a query for a field the UI never requests; confirm the "
                          "resolver enforces authorization, not the UI.")
    else:
        add("GET", path, "Re-request the exact endpoint with a clean session and compare "
                          "the response to the captured evidence.")
        add("GET", path, "Diff two responses for the same route with different roles.")

    return {
        "verdict": _offline_verdict(finding),
        "reasons": _offline_reasons(finding),
        "missing_evidence": _missing_evidence(finding),
        "next_tests": tests,
        "source": "offline-rules",
    }


def _offline_verdict(finding) -> str:
    if finding.confidence == "high" and finding.meta.get("evidence") in ("dual-role", None):
        return "likely-real"
    if finding.confidence == "low":
        return "inconclusive"
    if finding.bug_class == "IDOR" and not finding.meta.get("identity_a"):
        return "needs-ownership-check"
    return "inconclusive"


def _offline_reasons(finding) -> list[str]:
    reasons = []
    if finding.meta.get("similarity") is not None:
        reasons.append(f"captured similarity {finding.meta['similarity']}")
    if finding.meta.get("identity_a"):
        reasons.append("owner identity is recorded")
    if not finding.evidence:
        reasons.append("no exchange evidence attached")
    if finding.status == "candidate":
        reasons.append("still a candidate: verification has not confirmed it")
    return reasons


def _missing_evidence(finding) -> list[str]:
    missing = []
    if finding.bug_class == "IDOR":
        if len(finding.evidence) < 2:
            missing.append("owner baseline and attacker replay are both required")
        if not finding.meta.get("identity_a"):
            missing.append("owner identity marker")
    if not any(e.exchange for e in finding.evidence):
        missing.append("raw request/response exchange")
    return missing


SYSTEM = (
    "You are a careful bug-bounty triage assistant. Use ONLY the supplied finding and "
    "redacted evidence. Do not invent endpoints, parameters, tokens, or impact. Judge "
    "whether the evidence supports the claim, name what is missing, and propose concrete "
    "follow-up tests that are read-only by default. Output exactly one JSON object with "
    "keys: verdict (one of likely-real|needs-ownership-check|likely-false-positive|"
    "inconclusive), reasons (array of short strings), missing_evidence (array), "
    "next_tests (array of objects with method, path, why, risk). No prose outside JSON."
)


def _validate(raw: dict, finding) -> dict | None:
    if not isinstance(raw, dict):
        return None
    verdict = str(raw.get("verdict") or "").strip().lower()
    if verdict not in VERDICTS:
        return None
    reasons = [str(x).strip()[:300] for x in (raw.get("reasons") or [])
               if str(x).strip()][:6]
    missing = [str(x).strip()[:300] for x in (raw.get("missing_evidence") or [])
               if str(x).strip()][:6]
    tests = []
    for item in raw.get("next_tests") or []:
        if not isinstance(item, dict):
            continue
        method = str(item.get("method") or "GET").upper()
        path = str(item.get("path") or "").strip()
        if method not in METHODS or not path:
            continue
        if not (path.startswith("/") or path.startswith(("http://", "https://"))):
            continue
        risk = str(item.get("risk") or "read-only").lower()
        if risk not in RISKS:
            risk = "read-only"
        why = str(item.get("why") or "").strip()[:300]
        if not why:
            continue
        if any(t["method"] == method and t["path"] == path for t in tests):
            continue
        tests.append({"method": method, "path": path[:500], "why": why, "risk": risk})
        if len(tests) >= MAX_TESTS:
            break
    if not tests and not reasons and not missing:
        return None
    return {"verdict": verdict, "reasons": reasons, "missing_evidence": missing,
            "next_tests": tests, "source": "ollama"}


def analyze(finding, llm: Ollama | None = None, *, use_llm: bool = True) -> dict:
    """Offline analysis + optional validated model pass. Never sends a request."""
    base = analyze_offline(finding)
    if not use_llm:
        return base
    llm = llm or Ollama()
    if not llm.available():
        base["note"] = "Ollama unavailable; returned deterministic analysis"
        return base
    context = build_context(finding)
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": "FINDING:\n" + json.dumps(context, indent=2)},
    ]
    try:
        raw = llm.json_reply(messages)
    except (OllamaError, Exception) as exc:          # noqa: BLE001 — analysis is optional
        base["note"] = f"model analysis skipped: {exc}"
        return base
    validated = _validate(raw or {}, finding)
    if not validated:
        base["note"] = "model output failed validation; returned deterministic analysis"
        return base
    # keep deterministic tests as a floor: model suggestions supplement, never erase them
    merged = list(validated["next_tests"])
    for test in base["next_tests"]:
        if len(merged) >= MAX_TESTS:
            break
        if not any(t["method"] == test["method"] and t["path"] == test["path"]
                   for t in merged):
            merged.append(test)
    validated["next_tests"] = merged[:MAX_TESTS]
    validated["offline_verdict"] = base["verdict"]
    return validated


def format_analysis(result: dict) -> str:
    lines = [f"verdict: {result['verdict']}  (source: {result.get('source', '?')})"]
    if result.get("note"):
        lines.append(f"note: {result['note']}")
    if result.get("reasons"):
        lines.append("why:")
        lines += [f"  - {r}" for r in result["reasons"]]
    if result.get("missing_evidence"):
        lines.append("missing evidence:")
        lines += [f"  - {m}" for m in result["missing_evidence"]]
    if result.get("next_tests"):
        lines.append("next tests (advisory; nothing was executed):")
        for t in result["next_tests"]:
            lines.append(f"  [{t['risk']}] {t['method']:6} {t['path']}")
            lines.append(f"           {t['why']}")
    return "\n".join(lines)
