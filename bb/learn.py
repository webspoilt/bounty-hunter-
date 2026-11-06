"""Continuous learning: read outcomes back, then export a QLoRA-ready dataset.

Two honest halves:

  1. **Live readback** (no GPU): the ``feedback`` module turns recorded outcomes into
     class priors that reorder reporting. ``learning_report`` adds the other useful
     readback: which *bug classes* and *evidence patterns* actually pay on a program,
     and which checks keep producing duplicates or rejections.

  2. **Dataset export for fine-tuning**: ``export_dataset`` writes JSONL in the
     chat-messages format every trainer understands (Unsloth, LLaMA-Factory,
     Axolotl). Each row is a redacted finding + the human's verdict. That is the
     input a QLoRA run needs; the training itself stays outside this tool so the
     agent never pretends a model was improved when it was not.

Nothing here sends traffic, changes a finding, or calls a model.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from bb import feedback
from bb.config import DATA, now_iso
from bb.metrics import DECIDED, collect

OUTCOME_TO_VERDICT = {
    "accepted": "likely-real",
    "duplicate": "likely-duplicate",
    "informative": "informative-only",
    "rejected": "likely-false-positive",
    "unknown": "inconclusive",
}

SYSTEM_PROMPT = (
    "You are a bug-bounty triage assistant. Given one finding and its redacted "
    "evidence, decide whether the claim is likely real, likely a duplicate, "
    "informative-only, or likely false-positive. Then name the missing evidence and "
    "one read-only next test. Answer with JSON only: "
    '{"verdict": "...", "reasons": ["..."], "missing_evidence": ["..."], '
    '"next_test": {"method": "...", "path": "...", "why": "..."}}'
)


def learning_report(store, program: str | None = None) -> dict:
    """What the recorded outcomes teach us, per program and bug class."""
    data = collect(store, program=program)
    priors = feedback.class_priors(store, program=program)
    classes = []
    for name, stats in data["by_class"].items():
        decided = sum(stats.get(k, 0) for k in DECIDED)
        classes.append({
            "bug_class": name,
            "findings": stats.get("findings", 0),
            "decided": decided,
            "accepted": stats.get("accepted", 0),
            "duplicates": stats.get("duplicate", 0),
            "rejected": stats.get("rejected", 0),
            "weight": priors.get(name, {}).get("weight", 0.5),
            "note": priors.get(name, {}).get("note", ""),
        })
    classes.sort(key=lambda c: (-c["weight"], -c["decided"]))
    totals = data.get("totals", {})
    decided_total = sum(totals.get(k, 0) for k in DECIDED)
    return {
        "program": program or "(all)",
        "generated_at": now_iso(),
        "totals": totals,
        "decided": decided_total,
        "classes": classes,
        "ready_to_train": decided_total >= 30,
        "recommendations": _recommendations(classes, decided_total),
    }


def _recommendations(classes: list[dict], decided: int) -> list[str]:
    out = []
    if decided < 30:
        out.append(f"only {decided} decided outcome(s); keep recording `bb outcome` before "
                   "trusting learned priors (30+ is a useful floor)")
    losers = [c for c in classes if c["decided"] >= 3 and c["weight"] < 0.34]
    for c in losers[:3]:
        out.append(f"{c['bug_class']}: {c['weight']:.2f} weight — deprioritise on this "
                   "program and read the duplicates before spending more time")
    winners = [c for c in classes if c["decided"] >= 3 and c["weight"] >= 0.6]
    for c in winners[:3]:
        out.append(f"{c['bug_class']}: {c['weight']:.2f} weight — this class pays here; "
                   "spend budget on adjacent endpoints")
    if not out:
        out.append("no strong signal yet; priors stay neutral until 3 decided outcomes "
                   "per class")
    return out


def _redact(text: str) -> str:
    text = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,}\"']+", r"\1[REDACTED]", text or "")
    text = re.sub(r"(?i)((?:api[_-]?key|token|secret|password)\"?\s*[:=]\s*\")[^\"]+",
                  r"\1[REDACTED]", text)
    return text


def _evidence_snippet(finding, limit: int = 1800) -> str:
    chunks = []
    for ev in finding.evidence[:3]:
        ex = ev.exchange
        if ex is None:
            continue
        headers = {k: v for k, v in ex.response_headers.items()
                   if k.lower() in ("content-type", "location",
                                    "access-control-allow-origin",
                                    "access-control-allow-credentials")}
        chunks.append(
            f"[{ev.summary}] {ex.method} {ex.url} -> {ex.status}\n"
            f"response headers: {json.dumps(headers)}\n"
            f"body: {_redact((ex.response_body or '')[:900])}")
    return "\n---\n".join(chunks)[:limit] or "_no exchange captured_"


def _messages_for(finding, outcome: str) -> dict:
    ctx = {
        "title": finding.title,
        "bug_class": finding.bug_class,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "url": finding.url,
        "host": finding.host,
        "summary": _redact(finding.summary or ""),
        "impact": _redact(finding.impact or ""),
        "steps": finding.steps[:8],
        "evidence": _evidence_snippet(finding),
    }
    verdict = OUTCOME_TO_VERDICT.get(outcome, "inconclusive")
    answer = {
        "verdict": verdict,
        "reasons": [
            f"human outcome recorded as {outcome}",
            f"final finding status: {finding.status}",
        ],
        "missing_evidence": [] if verdict == "likely-real" else [
            "confirm ownership and reproduction before reporting"],
        "next_test": {"method": "GET", "path": finding.url or "/",
                      "why": "replay with fresh two-role sessions"},
    }
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "FINDING:\n" + json.dumps(ctx, indent=2)},
            {"role": "assistant", "content": json.dumps(answer)},
        ],
        "meta": {"finding_id": finding.id, "outcome": outcome,
                 "bug_class": finding.bug_class, "program": finding.meta.get("program", "")},
    }


def export_dataset(store, path: str | Path | None = None, program: str | None = None,
                   *, include_unknown: bool = False) -> dict:
    """Write one JSONL row per decided finding. Returns stats, never trains."""
    out = Path(path).expanduser().resolve() if path else (
        DATA / "training" / f"findings-{now_iso()[:10]}.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = store.outcome_rows(program=program)
    written, skipped = 0, 0
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            outcome = row.get("status") or "unknown"
            if outcome == "unknown" and not include_unknown:
                skipped += 1
                continue
            finding = store.get_finding(row["id"])
            if finding is None or not finding.evidence:
                skipped += 1
                continue
            record = _messages_for(finding, outcome)
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            written += 1
    return {"path": str(out), "rows": written, "skipped": skipped,
            "ready": written >= 30,
            "note": ("ready for a QLoRA run" if written >= 30 else
                     "collect at least 30 decided findings before fine-tuning")}


def format_report(report: dict) -> str:
    lines = [f"learning report — {report['program']}  ({report['generated_at']})",
             f"decided outcomes: {report['decided']}   "
             f"ready to train: {'yes' if report['ready_to_train'] else 'not yet'}",
             "", f"{'class':26} {'decided':>7} {'accept':>6} {'dup':>5} {'weight':>7}  note"]
    for c in report["classes"]:
        lines.append(f"{c['bug_class'][:26]:26} {c['decided']:>7} {c['accepted']:>6} "
                     f"{c['duplicates']:>5} {c['weight']:>7}  {c['note']}")
    lines += ["", "what to do next:"]
    lines += [f"  - {r}" for r in report["recommendations"]]
    return "\n".join(lines)


def training_hint(path: str) -> str:
    """Printed after export so the QLoRA step is concrete, not hand-wavy."""
    return (
        f"dataset: {path}\n"
        "QLoRA is external on purpose (this tool never claims a model improved):\n"
        "  pip install unsloth\n"
        "  # then in a notebook/script, load the base coder model and point the trainer at\n"
        f"  # this JSONL ({path}); the rows already use the chat-messages schema.\n"
        "Re-run `bb learn export` after every batch of outcomes so the next run learns "
        "from the last one."
    )
