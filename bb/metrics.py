"""Outcome metrics: the scoreboard that ties engineering work to bounty results.

Every finding can carry an outcome (accepted / duplicate / informative / rejected /
unknown), a bounty, minutes invested, and dates. Unknown stays unknown: it is counted
as "no decision yet", never as a failure.
"""
from __future__ import annotations

from collections import defaultdict

from bb.store import Store

DECIDED = ("accepted", "duplicate", "informative", "rejected")


def collect(store: Store, program: str | None = None) -> dict:
    rows = store.outcome_rows(program=program)
    class_stats: dict[str, dict] = defaultdict(
        lambda: {"findings": 0, "accepted": 0, "duplicate": 0, "informative": 0,
                 "rejected": 0, "unknown": 0, "minutes": 0.0, "bounty": 0.0})
    program_stats: dict[str, dict] = defaultdict(
        lambda: {"findings": 0, "accepted": 0, "duplicate": 0, "minutes": 0.0, "bounty": 0.0})
    currencies: dict[str, float] = defaultdict(float)

    totals = {"findings": len(rows), "accepted": 0, "duplicate": 0, "informative": 0,
              "rejected": 0, "unknown": 0, "submitted": 0, "bounty": 0.0, "minutes": 0.0}
    for row in rows:
        status = row.get("status") or "unknown"
        totals[status] = totals.get(status, 0) + 1
        if row.get("submitted_at"):
            totals["submitted"] += 1
        bounty = row.get("bounty")
        minutes = row.get("minutes")
        cls = class_stats[row.get("bug_class") or "unknown"]
        cls["findings"] += 1
        cls[status] = cls.get(status, 0) + 1
        prog = program_stats[row.get("program") or "unknown"]
        prog["findings"] += 1
        prog[status] = prog.get(status, 0) + 1
        if bounty:
            totals["bounty"] += float(bounty)
            cls["bounty"] += float(bounty)
            prog["bounty"] += float(bounty)
            currencies[row.get("currency") or "?"] += float(bounty)
        if minutes:
            totals["minutes"] += float(minutes)
            cls["minutes"] += float(minutes)
            prog["minutes"] += float(minutes)

    decided = sum(totals[s] for s in DECIDED)
    totals["decided"] = decided
    totals["acceptance_rate"] = round(totals["accepted"] / decided, 3) if decided else None
    totals["duplicate_rate"] = round(totals["duplicate"] / decided, 3) if decided else None
    totals["bounty_per_hour"] = (round(totals["bounty"] / (totals["minutes"] / 60), 2)
                                 if totals["minutes"] else None)
    totals["currencies"] = dict(currencies)

    for group in (class_stats, program_stats):
        for value in group.values():
            dec = sum(value.get(s, 0) for s in DECIDED)
            value["acceptance_rate"] = round(value["accepted"] / dec, 3) if dec else None
            value["bounty_per_hour"] = (round(value["bounty"] / (value["minutes"] / 60), 2)
                                        if value["minutes"] else None)

    return {"totals": totals, "by_class": dict(class_stats),
            "by_program": dict(program_stats)}


def format_metrics(data: dict) -> str:
    t = data["totals"]
    lines = [
        f"findings: {t['findings']}   submitted: {t['submitted']}   decided: {t['decided']}",
        f"accepted: {t['accepted']}   duplicate: {t['duplicate']}   "
        f"informative: {t['informative']}   rejected: {t['rejected']}   "
        f"unknown: {t['unknown']}",
    ]
    if t["acceptance_rate"] is not None:
        lines.append(f"acceptance rate: {t['acceptance_rate']:.0%}   "
                     f"duplicate rate: {t['duplicate_rate']:.0%}")
    if t["currencies"]:
        money = ", ".join(f"{amount:,.0f} {cur}" for cur, amount in t["currencies"].items())
        lines.append(f"bounty: {money}")
    if t["minutes"]:
        lines.append(f"minutes invested: {t['minutes']:.0f}")
    if t["bounty_per_hour"] is not None:
        lines.append(f"bounty per hour: {t['bounty_per_hour']:,.2f}")

    if data["by_class"]:
        lines.append("\nby class:")
        lines.append(f"  {'class':24} {'n':>4} {'acc':>4} {'dup':>4} {'bounty':>10} {'acc%':>6}")
        for name, s in sorted(data["by_class"].items(), key=lambda kv: -kv[1]["findings"]):
            rate = f"{s['acceptance_rate'] * 100:.0f}%" if s["acceptance_rate"] is not None else "-"
            lines.append(f"  {name[:24]:24} {s['findings']:>4} {s['accepted']:>4} "
                         f"{s['duplicate']:>4} {s['bounty']:>10,.0f} {rate:>6}")

    if data["by_program"]:
        lines.append("\nby program:")
        for name, s in sorted(data["by_program"].items(), key=lambda kv: -kv[1]["findings"]):
            rate = f"{s['acceptance_rate'] * 100:.0f}%" if s["acceptance_rate"] is not None else "-"
            lines.append(f"  {name:24} n={s['findings']:<4} accepted={s['accepted']:<3} "
                         f"dupes={s['duplicate']:<3} bounty={s['bounty']:,.0f}  acc={rate}")
    return "\n".join(lines)
