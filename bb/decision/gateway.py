"""Tev1 Decision Gateway — bounded, validated advisory decision client.

Authority Boundaries:
Tev1 may recommend:
  - Which task to prioritize.
  - Which registered specialist to use.
  - Which configured reasoning model to use.
  - Which hypothesis deserves review.
  - Whether to defer or gather more evidence.

Tev1 cannot:
  - Modify scope.
  - Change exclusions.
  - Override the kill switch.
  - Increase request budgets.
  - Create arbitrary executable tasks.
  - Register arbitrary agents.
  - Approve state-changing tests.
  - Submit reports.

Every choice is validated against the exact caller-supplied option list.
If Tev1 is unavailable or invalid, deterministic fallback is returned with
an explicit explaining reason.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from bb import tev1

if TYPE_CHECKING:
    from bb.models import Finding
    from bb.swarm import Task


class DecisionGateway:
    """Bounded, validated decision gateway interface to local Tev1."""

    def __init__(self, client: tev1.Tev1Client | None = None):
        self._client = client

    def _decide(self, point: str, options: list[str], context: dict[str, Any] | None = None,
                *, question: str = "", default: str | None = None) -> dict:
        try:
            return tev1.decide(
                decision_point=point,
                options=options,
                context=context or {},
                question=question,
                allow_none=True,
                default=default,
                client=self._client,
            )
        except Exception as exc:
            return {
                "decision_point": point,
                "source": tev1.FALLBACK_SOURCE,
                "choice": default if default in options else tev1.NONE,
                "reason": f"decision gateway error: {exc}",
                "model": tev1.MODEL_TAG,
                "contract": tev1.CONTRACT,
                "options": list(options),
                "confidence": None,
            }

    def select_task(self, candidate_tasks: list[Task], context: dict[str, Any] | None = None) -> dict:
        """Ask Tev1 to prioritize or select one task from eligible candidates."""
        if not candidate_tasks:
            return {
                "decision_point": "task-selection",
                "source": tev1.FALLBACK_SOURCE,
                "choice": "none",
                "reason": "no eligible candidate tasks supplied",
                "model": tev1.MODEL_TAG,
                "contract": tev1.CONTRACT,
                "options": ["none"],
                "confidence": None,
            }

        task_ids = [t.fingerprint for t in candidate_tasks]
        options = task_ids + ["defer", "none"]
        # Default fallback is deterministic: pick the first (highest priority) task
        default_choice = candidate_tasks[0].fingerprint

        ctx = dict(context or {})
        ctx["candidate_count"] = len(candidate_tasks)
        ctx["candidates"] = [
            {"id": t.fingerprint, "kind": t.kind, "target": t.target[:120], "priority": t.priority}
            for t in candidate_tasks[:10]
        ]

        dec = self._decide(
            "task-selection",
            options,
            ctx,
            question="select the highest yield eligible investigation task",
            default=default_choice,
        )

        # Validate selected ID against candidate tasks
        choice = dec.get("choice")
        if choice not in options:
            dec["source"] = tev1.FALLBACK_SOURCE
            dec["choice"] = default_choice
            dec["reason"] = f"invalid choice {choice!r} outside candidate set; fallback applied"

        return dec

    def recommend_specialist(self, task: Task, available_specialists: list[str],
                             context: dict[str, Any] | None = None) -> dict:
        """Ask Tev1 to recommend which registered specialist should investigate the task."""
        if not available_specialists:
            return {
                "decision_point": "specialist-selection",
                "source": tev1.FALLBACK_SOURCE,
                "choice": "none",
                "reason": "no registered specialists available",
                "model": tev1.MODEL_TAG,
                "contract": tev1.CONTRACT,
                "options": ["none"],
                "confidence": None,
            }

        options = list(available_specialists) + ["default", "none"]
        default_choice = available_specialists[0] if available_specialists else "default"

        ctx = dict(context or {})
        ctx.update({
            "task_kind": task.kind,
            "target": task.target[:120],
            "priority": task.priority,
            "specialists": available_specialists,
        })

        dec = self._decide(
            "specialist-selection",
            options,
            ctx,
            question=f"recommend a specialist agent to investigate task kind '{task.kind}'",
            default=default_choice,
        )

        choice = dec.get("choice")
        if choice not in options:
            dec["source"] = tev1.FALLBACK_SOURCE
            dec["choice"] = default_choice
            dec["reason"] = f"invalid specialist choice {choice!r}; fallback applied"

        return dec

    def recommend_reasoning_model(self, available_models: list[str],
                                  context: dict[str, Any] | None = None) -> dict:
        """Ask Tev1 to recommend which configured local reasoning model to use."""
        options = list(available_models) + ["default", "none"]
        default_choice = available_models[0] if available_models else "default"

        dec = self._decide(
            "model-selection",
            options,
            context or {},
            question="recommend a reasoning model for deep analysis",
            default=default_choice,
        )

        choice = dec.get("choice")
        if choice not in options:
            dec["source"] = tev1.FALLBACK_SOURCE
            dec["choice"] = default_choice
            dec["reason"] = f"invalid model choice {choice!r}; fallback applied"

        return dec

    def triage_finding(self, finding: Finding, context: dict[str, Any] | None = None) -> dict:
        """Structured advisory triage recommendation for a candidate finding."""
        from urllib.parse import urlsplit
        from bb import analyze

        ctx = {
            "bug_class": finding.bug_class,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "path": (urlsplit(finding.url or "").path or "/"),
            "evidence_count": len(finding.evidence),
            "similarity": finding.meta.get("similarity"),
            "verified": bool(finding.meta.get("verified")),
        }
        if context:
            ctx.update(context)

        options = list(analyze.VERDICTS) + ["defer", "none"]
        return self._decide(
            "auto-triage",
            options,
            ctx,
            question="recommend a triage verdict for this finding",
            default="none",
        )

    def select_hypothesis(
        self,
        candidate_hypotheses: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> dict:
        """Ask Tev1 to select or prioritize a test hypothesis from candidates."""
        if not candidate_hypotheses:
            return {
                "decision_point": "hypothesis-selection",
                "source": tev1.FALLBACK_SOURCE,
                "choice": None,
                "reason": "no candidate hypotheses provided",
                "model": tev1.MODEL_TAG,
                "contract": tev1.CONTRACT,
                "options": [],
                "confidence": None,
            }

        hypo_ids = [h.get("hypothesis_id") or f"hypo-{i}" for i, h in enumerate(candidate_hypotheses)]
        options = list(hypo_ids) + [tev1.NONE]
        default_choice = hypo_ids[0]

        ctx = {
            "candidate_count": len(candidate_hypotheses),
            "candidates": [
                {
                    "id": h.get("hypothesis_id") or f"hypo-{i}",
                    "vuln_class": h.get("vuln_class"),
                    "severity": h.get("severity"),
                    "endpoint": h.get("endpoint"),
                    "prior_weight": h.get("meta", {}).get("feedback_prior"),
                    "intel_score": h.get("meta", {}).get("intel_rank_score"),
                }
                for i, h in enumerate(candidate_hypotheses[:8])
            ],
        }
        if context:
            ctx.update(context)

        dec = self._decide(
            "hypothesis-selection",
            options,
            ctx,
            question="select the most promising test hypothesis based on evidence and priors",
            default=default_choice,
        )

        choice = dec.get("choice")
        if choice not in options:
            dec["source"] = tev1.FALLBACK_SOURCE
            dec["choice"] = default_choice
            dec["reason"] = f"invalid hypothesis choice {choice!r}; fallback applied"

        return dec
