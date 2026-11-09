"""Persistent lifecycle state machine for Bounty Hunter research controller.

Supported States:
  - DISCOVERING: Initial entrypoint discovery and passive surface exploration.
  - MAPPING: Route normalization, parameter schema classification.
  - ANALYZING: Technology fingerprinting, CVE matching, hypothesis formulation.
  - PLANNING: Identifying eligible tasks, candidate formulation, Tev1 ranking.
  - POLICY_REVIEW: Enforcing deterministic safety, scope, budget, and approval gates.
  - EXECUTING: Atomic task dispatch to registered specialists.
  - VERIFYING: Independent offline auditing and online reproduction replay.
  - LEARNING: Updating class priors, empirical feedback, outcome data.
  - COMPLETED: All eligible work done or bounds met cleanly.
  - PAUSED: Execution temporarily halted; state preserved for resumption.
  - ABORTED: Emergency stop, kill switch activated, or operator aborted.

All transitions must be explicit, strictly validated, and persisted to SQLite.
"""
from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

from bb.config import now_iso

if TYPE_CHECKING:
    from bb.store import Store


class State(str, Enum):
    DISCOVERING = "DISCOVERING"
    MAPPING = "MAPPING"
    ANALYZING = "ANALYZING"
    PLANNING = "PLANNING"
    POLICY_REVIEW = "POLICY_REVIEW"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    LEARNING = "LEARNING"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    ABORTED = "ABORTED"


ALLOWED_TRANSITIONS: dict[State, set[State]] = {
    State.DISCOVERING: {State.MAPPING, State.PAUSED, State.ABORTED},
    State.MAPPING: {State.ANALYZING, State.PLANNING, State.PAUSED, State.ABORTED},
    State.ANALYZING: {State.PLANNING, State.PAUSED, State.ABORTED},
    State.PLANNING: {State.POLICY_REVIEW, State.COMPLETED, State.PAUSED, State.ABORTED},
    State.POLICY_REVIEW: {State.EXECUTING, State.PLANNING, State.PAUSED, State.ABORTED},
    State.EXECUTING: {State.VERIFYING, State.PLANNING, State.PAUSED, State.ABORTED},
    State.VERIFYING: {State.LEARNING, State.PLANNING, State.PAUSED, State.ABORTED},
    State.LEARNING: {State.PLANNING, State.COMPLETED, State.PAUSED, State.ABORTED},
    State.PAUSED: {
        State.DISCOVERING,
        State.MAPPING,
        State.ANALYZING,
        State.PLANNING,
        State.POLICY_REVIEW,
        State.EXECUTING,
        State.VERIFYING,
        State.LEARNING,
        State.ABORTED,
    },
    State.COMPLETED: set(),
    State.ABORTED: set(),
}


class InvalidTransitionError(RuntimeError):
    """Raised when an illegal state transition is attempted."""


class LifecycleManager:
    """Manages explicit, validated, and persisted lifecycle state transitions."""

    def __init__(self, store: Store, run_id: str, initial_state: State = State.DISCOVERING):
        self.store = store
        self.run_id = run_id
        self._state: State = initial_state
        self._previous_state: State | None = None
        self._history: list[dict[str, Any]] = []

        # Load persisted state from existing run if available
        existing_run = self.store.run(self.run_id)
        if existing_run and existing_run.get("meta"):
            meta = existing_run.get("meta")
            if isinstance(meta, str):
                import json
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            if isinstance(meta, dict):
                saved_state = meta.get("state")
                if saved_state and saved_state in State.__members__:
                    self._state = State(saved_state)
                prev = meta.get("previous_state")
                if prev and prev in State.__members__:
                    self._previous_state = State(prev)
                self._history = list(meta.get("state_history") or [])

        if not self._history:
            self._record_transition(None, self._state, "initial state")

    @property
    def state(self) -> State:
        return self._state

    @property
    def previous_state(self) -> State | None:
        return self._previous_state

    @property
    def history(self) -> list[dict[str, Any]]:
        return list(self._history)

    def is_terminal(self) -> bool:
        return self._state in (State.COMPLETED, State.ABORTED)

    def is_paused(self) -> bool:
        return self._state == State.PAUSED

    def can_transition_to(self, target: State | str) -> bool:
        tgt = State(target) if isinstance(target, str) else target
        return tgt in ALLOWED_TRANSITIONS.get(self._state, set())

    def transition_to(self, target: State | str, reason: str = "",
                      meta: dict[str, Any] | None = None) -> State:
        """Explicitly validate and execute a state transition, persisting to store."""
        tgt = State(target) if isinstance(target, str) else target
        if tgt == self._state:
            return self._state

        allowed = ALLOWED_TRANSITIONS.get(self._state, set())
        if tgt not in allowed:
            raise InvalidTransitionError(
                f"illegal state transition from {self._state.value} to {tgt.value} "
                f"(allowed: {[s.value for s in allowed]})"
            )

        prev = self._state
        if tgt == State.PAUSED:
            self._previous_state = prev

        self._state = tgt
        self._record_transition(prev, tgt, reason=reason, extra=meta)
        return self._state

    def pause(self, reason: str = "manual pause") -> State:
        """Transition into PAUSED state, recording resume point."""
        return self.transition_to(State.PAUSED, reason=reason)

    def resume(self, reason: str = "manual resume") -> State:
        """Resume from PAUSED state back into the previously active state."""
        if self._state != State.PAUSED:
            return self._state
        target = self._previous_state or State.PLANNING
        self._previous_state = None
        return self.transition_to(target, reason=reason)

    def abort(self, reason: str = "aborted") -> State:
        """Halt execution permanently into ABORTED state."""
        return self.transition_to(State.ABORTED, reason=reason)

    def complete(self, reason: str = "all tasks finished") -> State:
        """Mark research run cleanly as COMPLETED."""
        return self.transition_to(State.COMPLETED, reason=reason)

    def _record_transition(self, from_state: State | None, to_state: State,
                           reason: str = "", extra: dict[str, Any] | None = None) -> None:
        entry = {
            "from": from_state.value if from_state else None,
            "to": to_state.value,
            "at": now_iso(),
            "reason": reason,
        }
        if extra:
            entry["meta"] = extra
        self._history.append(entry)

        # Persist to run record
        self.store.update_run(
            self.run_id,
            state=to_state.value,
            previous_state=self._previous_state.value if self._previous_state else None,
            state_history=self._history[-50:],  # preserve recent audit log
        )
