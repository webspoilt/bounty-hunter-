"""Decision Evaluation System — records and benchmarks Tev1 vs deterministic baselines.

Records:
  - Tev1 selected choice vs. alternative candidates.
  - Deterministic baseline choice (e.g. priority + path ordering).
  - Actual task execution result (findings, requests, duration).
  - Technical verification result (confirmed, rejected, inconclusive).
  - Request cost & latency overhead.
  - Triage outcome when available.

Provides clear comparative evaluation reports to verify if Tev1 improves research yield
or introduces false positive / latency overhead.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from bb.config import DATA, now_iso


@dataclass
class DecisionRecord:
    decision_id: str
    run_id: str
    decision_point: str
    timestamp: str
    options: list[str]
    tev1_choice: str | None
    tev1_source: str
    tev1_confidence: float | None
    tev1_reason: str
    baseline_choice: str | None
    agreed: bool
    # Execution follow-up
    task_fingerprint: str | None = None
    execution_status: str | None = None  # done, failed, skipped
    findings_count: int = 0
    requests_cost: int = 0
    duration_ms: float = 0.0
    verification_status: str | None = None  # confirmed, rejected, inconclusive
    triage_verdict: str | None = None


class DecisionEvaluator:
    """Manages the decision evaluation ledger and generates comparative reports."""

    def __init__(self, ledger_path: str | Path | None = None):
        if ledger_path:
            self.ledger_path = Path(ledger_path)
        else:
            self.ledger_path = DATA / "decision_eval" / "decisions.jsonl"
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self._pending_records: dict[str, DecisionRecord] = {}

    def record_decision(
        self,
        decision_id: str,
        run_id: str,
        decision_point: str,
        options: list[str],
        tev1_result: dict[str, Any],
        baseline_choice: str | None,
        task_fingerprint: str | None = None,
    ) -> DecisionRecord:
        """Record the initial decision recommendation and baseline."""
        tev1_choice = tev1_result.get("choice")
        tev1_source = tev1_result.get("source", "unknown")
        tev1_conf = tev1_result.get("confidence")
        tev1_reason = tev1_result.get("reason", "")
        agreed = (tev1_choice == baseline_choice)

        rec = DecisionRecord(
            decision_id=decision_id,
            run_id=run_id,
            decision_point=decision_point,
            timestamp=now_iso(),
            options=options,
            tev1_choice=tev1_choice,
            tev1_source=tev1_source,
            tev1_confidence=tev1_conf,
            tev1_reason=tev1_reason,
            baseline_choice=baseline_choice,
            agreed=agreed,
            task_fingerprint=task_fingerprint,
        )
        self._pending_records[decision_id] = rec
        return rec

    def attach_execution_result(
        self,
        decision_id: str,
        status: str,
        findings_count: int = 0,
        requests_cost: int = 0,
        duration_ms: float = 0.0,
    ) -> None:
        """Attach actual task execution metrics to the decision record."""
        rec = self._pending_records.get(decision_id)
        if rec:
            rec.execution_status = status
            rec.findings_count = findings_count
            rec.requests_cost = requests_cost
            rec.duration_ms = duration_ms

    def attach_verification_result(
        self,
        decision_id: str,
        verification_status: str,
        triage_verdict: str | None = None,
    ) -> None:
        """Attach verification and triage results and commit record to disk."""
        rec = self._pending_records.pop(decision_id, None)
        if rec:
            rec.verification_status = verification_status
            rec.triage_verdict = triage_verdict
            self._save(rec)

    def flush(self) -> None:
        """Save any remaining uncommitted pending records."""
        for rec in list(self._pending_records.values()):
            self._save(rec)
        self._pending_records.clear()

    def _save(self, record: DecisionRecord) -> None:
        line = json.dumps(asdict(record), ensure_ascii=False)
        with self.ledger_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def load_records(self, run_id: str | None = None) -> list[DecisionRecord]:
        if not self.ledger_path.exists():
            return []
        records = []
        with self.ledger_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if run_id and data.get("run_id") != run_id:
                        continue
                    records.append(DecisionRecord(**data))
                except Exception:
                    pass
        return records

    def generate_report(self, run_id: str | None = None) -> dict[str, Any]:
        """Generate comparative performance evaluation between Tev1 and baseline."""
        self.flush()
        records = self.load_records(run_id=run_id)
        total = len(records)
        if total == 0:
            return {
                "total_decisions": 0,
                "note": "no decision evaluation records collected yet",
            }

        tev1_active = sum(1 for r in records if r.tev1_source == "tev1")
        fallbacks = sum(1 for r in records if r.tev1_source != "tev1")
        agreement_count = sum(1 for r in records if r.agreed)
        disagreement_count = total - agreement_count

        total_findings = sum(r.findings_count for r in records)
        confirmed_findings = sum(1 for r in records if r.verification_status == "confirmed")
        rejected_findings = sum(1 for r in records if r.verification_status == "rejected")
        total_requests = sum(r.requests_cost for r in records)
        avg_duration_ms = (sum(r.duration_ms for r in records) / total) if total > 0 else 0.0

        # Disagreement breakdown: did Tev1 choices yield findings when differing from baseline?
        disagreed_records = [r for r in records if not r.agreed]
        disagreed_findings = sum(r.findings_count for r in disagreed_records)
        disagreed_confirmed = sum(1 for r in disagreed_records if r.verification_status == "confirmed")

        return {
            "total_decisions": total,
            "tev1_model_decisions": tev1_active,
            "fallback_decisions": fallbacks,
            "agreement_rate": round(agreement_count / total, 3) if total > 0 else 0.0,
            "disagreement_count": disagreement_count,
            "total_findings_yielded": total_findings,
            "confirmed_findings": confirmed_findings,
            "rejected_findings": rejected_findings,
            "total_requests_cost": total_requests,
            "avg_task_duration_ms": round(avg_duration_ms, 2),
            "disagreed_yield": {
                "count": len(disagreed_records),
                "findings": disagreed_findings,
                "confirmed": disagreed_confirmed,
            },
            "eval_summary": (
                f"{tev1_active}/{total} decisions made by Tev1 ({fallbacks} fallback). "
                f"Agreement with deterministic baseline: {agreement_count / total:.1%}. "
                f"Confirmed findings: {confirmed_findings}."
            ),
        }
