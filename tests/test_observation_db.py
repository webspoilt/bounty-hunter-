"""Observation DB tests."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from observation_db import ObservationDB


def run() -> int:
    failures = 0

    def check(cond, label):
        nonlocal failures
        if not cond:
            failures += 1
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    with tempfile.TemporaryDirectory() as tmp:
        db = ObservationDB(Path(tmp) / "obs.db")

        # 1. insert
        rid, new = db.insert(
            tool="nuclei", command="nuclei -l subs.txt",
            target="app.example.com",
            verdict="candidate",
            payload={"PatternMatched": "[jenkins]", "status": 200},
        )
        check(new and rid == 1, "first insert -> new row")

        # 2. dedup: identical observation returns same id, was_new=False
        rid2, new2 = db.insert(
            tool="nuclei", command="nuclei -l subs.txt",
            target="app.example.com", verdict="candidate",
            payload={"PatternMatched": "[jenkins]", "status": 200},
        )
        check((not new2) and rid2 == rid, "exact duplicate deduped")

        # 3. different payload -> new row
        rid3, new3 = db.insert(
            tool="httpx", command="httpx -l subs.txt",
            target="app.example.com", verdict="informational",
            payload={"status": 200, "title": "Dashboard"},
        )
        check(new3 and rid3 != rid, "different tool/payload -> separate row")

        # 4. scope refusal
        try:
            db.insert(tool="nuclei", command="x", target="evilnotexample.com",
                      verdict="informational", payload={}, scope_allowed=False)
            check(False, "out-of-scope insert refused")
        except ValueError:
            check(True, "out-of-scope insert refused")

        # 5. bad verdict rejected
        try:
            db.insert(tool="nuclei", command="x", target="app.example.com",
                      verdict="hilarious", payload={})
            check(False, "bad verdict rejected")
        except ValueError:
            check(True, "bad verdict rejected")

        # 6. candidates + promote
        cands = db.candidates()
        check(len(cands) == 1 and cands[0]["target"] == "app.example.com",
              "candidates() returns pending")
        db.promote(rid, "finding")
        check(len(db.candidates()) == 0, "promoted finding leaves candidate list")
        s = db.stats()
        check(s.get("finding") == 1 and s.get("informational") == 1, "stats correct")

        # 7. evidence trail
        ev = db.evidence_for("app.example.com")
        check(len(ev) == 2 and ev[0]["tool"] == "nuclei",
              "evidence_for returns ordered provenance")

        # 8. persistence: reopen file, data still there
        db.close()
        db2 = ObservationDB(Path(tmp) / "obs.db")
        check(db2.stats().get("finding") == 1, "data persists across reopen")
        db2.close()

    print(f"\n{'ALL PASS' if failures == 0 else f'{failures} FAILURES'}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
