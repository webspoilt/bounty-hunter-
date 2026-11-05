"""Feedback readback: turn recorded outcomes into weights that change behavior.

The `outcomes` table was write-only: you recorded accepted/duplicate/... and `bb metrics`
printed a scoreboard, but nothing ever read the results back into decisions. This module
closes the loop (the adaptive-learning thread from the ChatGPT blueprint, without any
magic):

    weight(class) = (accepted + 1) / (decided + 2)

A Laplace-smoothed acceptance ratio: a class that went 0-for-3 scores ~0.2, an untested
class scores 0.5, a class 3-for-3 scores 0.8. Weights are advisory and bounded:

  * they reorder report/priority work (e.g. which reports get LLM polish first),
  * they annotate findings with a class prior for the human reviewer,
  * they NEVER drop a finding — a low prior adds a warning, not a silent skip.

Sample sizes matter: any class with fewer than MIN_DECIDED decided outcomes stays
neutral, so early noise cannot dominate.
"""
from __future__ import annotations

from bb.metrics import DECIDED, collect

MIN_DECIDED = 3


def class_priors(store, program: str | None = None) -> dict[str, dict]:
    """Per-bug-class prior weight and history. Empty/neutral when not enough data."""
    data = collect(store, program=program)
    out: dict[str, dict] = {}
    for name, s in data["by_class"].items():
        decided = sum(s.get(k, 0) for k in DECIDED)
        accepted = s.get("accepted", 0)
        duplicates = s.get("duplicate", 0)
        rejected = s.get("rejected", 0)
        if decided < MIN_DECIDED:
            out[name] = {"weight": 0.5, "decided": decided, "accepted": accepted,
                         "duplicates": duplicates, "rejected": rejected,
                         "neutral": True, "note": "not enough decided outcomes yet"}
            continue
        weight = (accepted + 1) / (decided + 2)
        dup_rate = duplicates / decided
        notes = []
        if accepted == 0:
            notes.append("never accepted on this program")
        if dup_rate >= 0.5:
            notes.append(f"{dup_rate:.0%} duplicate rate")
        if rejected >= 2:
            notes.append(f"{rejected} rejected")
        out[name] = {
            "weight": round(weight, 3),
            "decided": decided,
            "accepted": accepted,
            "duplicates": duplicates,
            "rejected": rejected,
            "neutral": False,
            "note": "; ".join(notes) if notes else "earning its keep",
        }
    return out


def prior_for(store, program: str | None, bug_class: str) -> dict:
    priors = class_priors(store, program=program)
    return priors.get(bug_class or "unknown") or {
        "weight": 0.5, "decided": 0, "accepted": 0, "duplicates": 0, "rejected": 0,
        "neutral": True, "note": "no outcome history"}


def annotate(findings: list, store, program: str | None = None) -> list[dict]:
    """Attach the class prior to each finding's meta and return the advisory list.

    Readback effect #1: reports carry their class's bounty history into review, so the
    human sees "this class is 0-for-4 on this program" before they submit.
    """
    priors = class_priors(store, program=program)
    advisories: list[dict] = []
    for f in findings:
        prior = priors.get(f.bug_class or "unknown")
        if not prior:
            continue
        f.meta["feedback_prior"] = prior["weight"]
        f.meta["feedback_note"] = prior["note"]
        if not prior.get("neutral") and prior["weight"] < 0.34:
            advisories.append({"finding_id": f.id, "bug_class": f.bug_class,
                               "weight": prior["weight"], "note": prior["note"]})
    return advisories


def rank_priority(findings: list, store, program: str | None = None) -> list:
    """Readback effect #2: strongest classes first (severity, then prior weight)."""
    from bb.models import sev_rank
    priors = class_priors(store, program=program)
    return sorted(findings,
                  key=lambda f: (-sev_rank(f.severity),
                                 -priors.get(f.bug_class or "unknown", {}).get("weight", 0.5),
                                 f.url))


def format_priors(priors: dict) -> str:
    lines = [
        f"{'class':26} {'decided':>7} {'accepted':>8} {'dupes':>6} {'weight':>7}  note"]
    for name, p in sorted(priors.items(), key=lambda kv: -kv[1]["weight"]):
        lines.append(f"{name[:26]:26} {p['decided']:>7} {p['accepted']:>8} "
                     f"{p['duplicates']:>6} {p['weight']:>7}  {p['note']}")
    return "\n".join(lines)
