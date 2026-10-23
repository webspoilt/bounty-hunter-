"""Approval gate tests."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from approval_gate import ApprovalGate


def run() -> int:
    failures = 0

    def check(cond, label):
        nonlocal failures
        if not cond:
            failures += 1
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    with tempfile.TemporaryDirectory() as tmp:
        gate = ApprovalGate(Path(tmp) / "pending.jsonl", Path(tmp) / "decided.jsonl")

        seq = gate.submit(
            obs_row_id=1, target="app.example.com",
            title="IDOR on /api/v1/invoices/<id>",
            evidence=[{"role": "A", "code": 200, "len": 456}, {"role": "B", "code": 200, "len": 456}],
            draft_report="## Summary\nAttacker user B retired invoice data of user A ...",
        )
        check(seq == 1, "first pending item")

        check(len(gate.pending_list()) == 1, "pending list holds item")

        # decide seq 1 approved=False
        gate.decide(1, approved=False)
        check(len(gate.pending_list()) == 0, "decided item removed from pending")
        decided = [json.loads(l) for l in (Path(tmp) / "decided.jsonl").read_text(encoding="utf-8").splitlines()]
        check(len(decided) == 1 and decided[0]["approved"] is False, "decision recorded")

        # second item, approve=True with multiple queued to verify shift
        gate.submit(obs_row_id=2, target="app.example.com", title="Test2", evidence=[], draft_report="x")
        gate.submit(obs_row_id=3, target="app.example.com", title="Test3", evidence=[], draft_report="y")
        gate.decide(1, approved=True)
        remaining = gate.pending_list()
        check(len(remaining) == 1 and remaining[0]["obs_row_id"] == 3,
              "queue shifts correctly after decision")

        decided = [json.loads(l) for l in (Path(tmp) / "decided.jsonl").read_text(encoding="utf-8").splitlines()]
        check(len(decided) == 2 and decided[1]["approved"] is True, "second decision recorded")

    print(f"\n{'ALL PASS' if failures == 0 else f'{failures} FAILURES'}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
