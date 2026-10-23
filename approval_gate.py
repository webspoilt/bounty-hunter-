"""
Approval Gate — nothing leaves the box without YOUR yes.
A candidate goes here → lands in pending.jsonl → you review → you decide.
No auto-submission path exists in this module. That's the whole point.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


class ApprovalGate:
    def __init__(self, pending_path: str | Path = "data/pending.jsonl",
                 decided_path: str | Path = "data/decided.jsonl"):
        self.pending = Path(pending_path)
        self.decided = Path(decided_path)
        self.pending.parent.mkdir(parents=True, exist_ok=True)

    def submit(self, *, obs_row_id: int, target: str, title: str,
               evidence: list[dict], draft_report: str) -> int:
        """Queue a candidate for human review. Returns pending seq number."""
        item = {
            "queued_at": time.time(),
            "obs_row_id": obs_row_id,
            "target": target,
            "title": title,
            "evidence": evidence,
            "draft_report": draft_report,
        }
        with self.pending.open("a", encoding="utf-8") as f:
            f.write(json.dumps(item, sort_keys=True) + "\n")
        self._notify(target, title)
        seq = len(self.pending_list())
        return seq

    def pending_list(self) -> list[dict]:
        if not self.pending.exists():
            return []
        return [json.loads(l) for l in self.pending.read_text(encoding="utf-8").splitlines() if l.strip()]

    def decide(self, seq: int, approved: bool) -> None:
        """seq = 1-based position in pending_list at the time you reviewed."""
        items = self.pending_list()
        item = items[seq - 1]
        item["approved"] = approved
        item["decided_at"] = time.time()
        with self.decided.open("a", encoding="utf-8") as f:
            f.write(json.dumps(item) + "\n")
        rest = items[: seq - 1] + items[seq:]
        with self.pending.open("w", encoding="utf-8") as f:
            for it in rest:
                f.write(json.dumps(it) + "\n")

    def _notify(self, target: str, title: str) -> None:
        print(f"\n[APPROVAL NEEDED] ({target}: {title})\n"
              f"    -> review data/pending.jsonl then call gate.decide(seq, approved=True/False)\n")
