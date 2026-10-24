"""Report generation: deterministic H1-ready markdown, optionally sharpened by local LLM.

The deterministic template always works (no model, no network). The LLM pass may rewrite
Summary / Impact / Remediation, and is discarded unless it returns all three sections with
sane lengths. Evidence is rendered from redacted exchanges only.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from bb.config import REPORTS, now_iso
from bb.llm import Ollama, OllamaError, split_sections
from bb.models import Evidence, Exchange, Finding

SEV_LABEL = {"info": "Informational", "low": "Low", "medium": "Medium",
             "high": "High", "critical": "Critical"}


def _http_block(ex: Exchange, title: str) -> str:
    path = urlsplit(ex.url).path or "/"
    query = urlsplit(ex.url).query
    if query:
        path += "?" + query
    host = urlsplit(ex.url).netloc
    req = [f"{ex.method} {path} HTTP/1.1", f"Host: {host}"]
    for k in ("authorization", "cookie", "content-type", "accept"):
        for hk, hv in ex.request_headers.items():
            if hk.lower() == k:
                req.append(f"{hk}: {hv}")
                break
    body = (ex.request_body or "").strip()
    response = [f"HTTP/1.1 {ex.status}"]
    for k in ("content-type", "content-length", "location"):
        for hk, hv in ex.response_headers.items():
            if hk.lower() == k:
                response.append(f"{hk}: {hv}")
                break
    resp_body = (ex.response_body or "").strip()
    if len(resp_body) > 1200:
        resp_body = resp_body[:1200] + "\n… [truncated]"
    return (f"**{title}**\n\n```http\n" + "\n".join(req) +
            ("\n\n" + body[:800] if body else "") + "\n\n" + "\n".join(response) +
            ("\n\n" + resp_body if resp_body else "") + "\n```\n")


def _curl(f: Finding, evidence: Evidence, role: str) -> str:
    ex = evidence.exchange
    if not ex:
        return ""
    return (f"curl -s -i -H 'Authorization: Bearer $TOKEN_{role}' "
            f"'{ex.url}'")


def data_classes(f: Finding) -> str:
    """What the evidence actually exposes — the part a triager grades."""
    blob = " ".join((e.exchange.response_body or "") for e in f.evidence if e.exchange)
    found = []
    if re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", blob, re.I):
        found.append("email address(es)")
    if re.search(r'"(deluxe)?token"\s*:\s*"[^"]+"', blob, re.I):
        found.append("credential/token material")
    if re.search(r'"role"\s*:\s*"admin"', blob, re.I):
        found.append("privilege/role metadata")
    if re.search(r'"(id|user_?id)"\s*:', blob, re.I):
        found.append("object identifier and profile fields")
    return ", ".join(found) or "response content that belongs to another account"


def novelty_note(f: Finding, kb=None) -> str:
    """Honest novelty status: a local corpus check plus the manual step that remains."""
    path = urlsplit(f.url).path or "/"
    hits = 0
    if kb is not None:
        try:
            hits = kb.lexical_contains(path)
        except Exception:
            hits = 0
    if kb is None:
        return ("Novelty not checked (knowledge base unavailable). Search H1 Hacktivity and the "
                "program's disclosed reports before submitting.")
    if hits:
        return (f"{hits} local disclosed-report chunk(s) mention {path}. Read them before "
                "submitting — this may be a duplicate. Also search H1 Hacktivity.")
    return (f"No precedent for {path} among {len(kb.entries)} local disclosed-report chunks. "
            "Confirm on H1 Hacktivity before submitting; treat it as a duplicate if it is listed.")


def build_facts(f: Finding) -> str:
    parts = [
        f"BUG CLASS: {f.bug_class}",
        f"URL: {f.url}",
        f"HOST: {f.host}",
        f"SEVERITY: {f.severity} ({f.confidence} confidence)",
        f"OBSERVED: {f.summary}",
        f"PLATFORM NOTES: {f.meta.get('similarity', '')}",
    ]
    for e in f.evidence[:3]:
        if e.exchange:
            parts.append(f"EXCHANGE [{e.summary}] {e.exchange.method} {e.exchange.url} -> "
                         f"{e.exchange.status}; body: {(e.exchange.response_body or '')[:700]}")
    return "\n".join(parts)


SYSTEM = (
    "You write HackerOne reports for a professional bug-bounty researcher. "
    "Use ONLY the facts supplied; never invent endpoints, parameters, or impact. "
    "Be specific and neutral. Output exactly three sections with these headers and no "
    "preamble:\n## Summary\n## Impact\n## Remediation\n"
    "Summary: 2-4 sentences, what the bug is and where. Impact: concrete consequences for "
    "the program (data classes, accounts affected, what an attacker gains). "
    "Remediation: 1-3 sentences, the correct server-side fix."
)


def polish(f: Finding, kb=None, llm: Ollama | None = None, log=print) -> dict:
    """Ask the local model to improve the narrative. Returns {} when unavailable/unusable."""
    llm = llm or Ollama()
    if not llm.available():
        return {}
    context = ""
    if kb is not None:
        try:
            hits = kb.query(f"{f.bug_class} {f.title} vulnerability report", k=3)
            context = "\n---\n".join(f"[{h['title']}] {h['text'][:500]}" for h in hits)
        except Exception:
            context = ""
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content":
            f"FACTS:\n{build_facts(f)}\n\n"
            + (f"PRECEDENT FROM DISCLOSED REPORTS (style only):\n{context}\n\n" if context else "")
            + f"CURRENT DRAFT:\n## Summary\n{f.summary}\n## Impact\n{f.impact}\n"
              f"## Remediation\n{f.remediation}\n\nRewrite the three sections now."},
    ]
    try:
        out = llm.chat(messages, temperature=0.2)
    except OllamaError as exc:
        log(f"  [llm] report polish skipped: {exc}")
        return {}
    sections = split_sections(out)
    if not all(k in sections for k in ("summary", "impact", "remediation")):
        return {}
    if not (40 <= len(sections["summary"]) <= 2000
            and 40 <= len(sections["impact"]) <= 2000
            and 30 <= len(sections["remediation"]) <= 1000):
        return {}
    if re.search(r"\b(TBD|todo|placeholder|\[insert)", " ".join(sections.values()), re.I):
        return {}
    return sections


def render_h1(f: Finding, *, scope=None, polished: dict | None = None,
              include_evidence: bool = True, novelty: str = "") -> str:
    summary = (polished or {}).get("summary") or f.summary
    impact = (polished or {}).get("impact") or f.impact
    remediation = (polished or {}).get("remediation") or f.remediation
    scope_block = ""
    if scope is not None:
        scope_block = (
            f"- Program: `{scope.program}`\n"
            f"- Scope fingerprint: `{scope.fingerprint}` (imported {scope.imported_at})\n"
            f"- Target `{f.host}` matched an in-scope rule before every request was sent.\n"
            f"- Testing was read-only: no writes, no destructive actions, rate-limited to a "
            f"polite level.\n")
    steps = f.steps or [f"Send the request shown in the evidence to `{f.url}`."]
    evidence_md = ""
    if include_evidence:
        blocks = []
        for i, e in enumerate(f.evidence, 1):
            if e.exchange:
                blocks.append(_http_block(e.exchange, f"{i}. {e.summary}"))
        curls = "\n".join(c for c in (_curl(f, e, "A" if i == 0 else "B")
                                      for i, e in enumerate(f.evidence)) if c)
        evidence_md = ("\n## Evidence\n\n"
                       + ("\n".join(blocks) if blocks else "_No raw exchange captured._\n")
                       + ("\nReproduce with your own role tokens "
                          "(`$TOKEN_A` = owner account, `$TOKEN_B` = second account):\n\n"
                          f"```bash\n{curls}\n```\n" if curls else ""))
    duplicate_md = f"\n## Duplicate check\n\n{novelty}\n" if novelty else ""
    return f"""# {f.title}

**Severity:** {SEV_LABEL.get(f.severity, f.severity)}
**Bug class:** {f.bug_class}
**Asset:** `{f.url}`
**Confidence:** {f.confidence}
**Exposed data:** {data_classes(f)}
**Reported:** {now_iso()}

## Summary

{summary}

## Steps to reproduce

""" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)) + f"""

{evidence_md}
## Impact

{impact}

## Remediation

{remediation}

## Scope and authorisation

{scope_block or "- Scope attestation unavailable (run inside a scope-loaded program)."}
- Contact: `{f.meta.get('contact', 'researcher')}`
{duplicate_md}
_Generated by bountybot from captured exchanges; review every line before submitting._
"""


def render_cbh_finding(f: Finding, novelty: str = "") -> str:
    """Finding markdown in the format `cbh triage` / `cbh report` expect."""
    blocks = "\n".join(_http_block(e.exchange, e.summary)
                       for e in f.evidence[:2] if e.exchange)
    return f"""---
title: {f.title}
severity: {SEV_LABEL.get(f.severity, f.severity)}
asset: {f.url}
endpoint: {urlsplit(f.url).path}
bug_class: {f.bug_class}
confidence: {f.confidence}
---

## Summary
{f.summary}

## Steps to reproduce
""" + "\n".join(f"{i}. {s}" for i, s in enumerate(f.steps, 1)) + f"""

## Data exposed
Exposed data: {data_classes(f)}

## Reproduction command
```bash
""" + "\n".join(c for c in (_curl(f, e, "A" if i == 0 else "B")
                            for i, e in enumerate(f.evidence)) if c) + f"""
```

## Impact
{f.impact}

## Suggested remediation
{f.remediation}

## Evidence
{blocks or "_No raw exchange captured._"}

## Novelty
{novelty or "Not checked. Search H1 Hacktivity before submitting."}
"""


LINT_RULES = [
    (lambda t: len(t.splitlines()[0]) <= 140, "title is longer than 140 characters"),
    (lambda t: not re.search(r"\bI (found|think|believe|noticed)\b", t), "first person in the report"),
    (lambda t: "## Steps to reproduce" in t, "missing Steps to reproduce section"),
    (lambda t: "## Impact" in t, "missing Impact section"),
    (lambda t: "## Remediation" in t, "missing Remediation section"),
    (lambda t: not re.search(r"\b(TBD|TODO|FIXME|\[insert)", t, re.I), "unfinished placeholder text"),
    (lambda t: "curl " in t.lower() or "HTTP/1.1" in t, "no reproducible HTTP request"),
    (lambda t: "```http" in t or "```bash" in t, "no evidence code block"),
]


def lint(report: str) -> list[str]:
    return [msg for rule, msg in LINT_RULES if not rule(report)]


def write_report(f: Finding, *, scope=None, polished: dict | None = None,
                 cbh_finding: bool = True, novelty: str = "") -> tuple[Path, Path | None]:
    out_dir = REPORTS / f.id
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "report.md"
    report_path.write_text(render_h1(f, scope=scope, polished=polished, novelty=novelty),
                           encoding="utf-8")
    cbh_path = None
    if cbh_finding:
        cbh_path = out_dir / "finding.md"
        cbh_path.write_text(render_cbh_finding(f, novelty=novelty), encoding="utf-8")
    return report_path, cbh_path
