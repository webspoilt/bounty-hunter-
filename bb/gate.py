"""Approval gate: findings queue, humans decide, nothing auto-submits.

Identity, not position: queue items are UUIDs, decisions are idempotent, and a second
decision on the same item is refused (the v1 bug let `decide(0)` approve the last item and
let a stale Telegram tap decide a different candidate).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from bb.config import DATA
from bb.store import Store

DECIDED_DIR = DATA / "decided"


class ApprovalGate:
    def __init__(self, store: Store):
        self.store = store

    def submit(self, finding_id: str, channel: str = "cli") -> tuple[str, bool]:
        return self.store.queue_add(finding_id, channel=channel)

    def pending(self) -> list[dict]:
        return self.store.queue("pending")

    def decide(self, queue_id: str, approved: bool) -> dict:
        item = self.store.decide(queue_id, approved)
        if approved:
            self._export(item)
        return item

    def _export(self, item: dict) -> Path:
        DECIDED_DIR.mkdir(parents=True, exist_ok=True)
        finding = self.store.get_finding(item["finding_id"])
        dest = DECIDED_DIR / f"{item['finding_id']}.md"
        src = None
        if finding and finding.meta.get("report_path"):
            src = Path(finding.meta["report_path"])
        if src and src.exists():
            shutil.copy(src, dest)
        elif finding:
            from bb.report import render_h1
            dest.write_text(render_h1(finding), encoding="utf-8")
        return dest

    def summary(self) -> str:
        pending = self.pending()
        if not pending:
            return "queue empty — nothing waiting for a human."
        lines = [f"{len(pending)} item(s) awaiting your decision:"]
        for item in pending:
            lines.append(f"  {item['id']}  [{item['severity']:8}] {item['title'][:90]}")
        lines.append("\napprove: bb decide <id> --approve    reject: bb decide <id> --reject")
        lines.append("nothing is submitted to HackerOne by this tool.")
        return "\n".join(lines)
