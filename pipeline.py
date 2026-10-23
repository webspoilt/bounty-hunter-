"""
Recon Orchestrator — nightly loop that ties modules together in the safe order.

FOLOW: scope gate -> (SAFE tool) -> observation DB -> hypothesis (local LLM)
                        -> authz differ -> approval gate -> YOU.

This file currently implements the WIRING, with tool invocation behind a
Single dispatch so Docker tools (nuclei / subfinder / httpx) plug in without
changing the safety rails.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from scope_engine import Program, ScopeEngine
from observation_db import ObservationDB
from approval_gate import ApprovalGate


@dataclass
class ReconTool:
    name: str
    command_builder: callable   # (target: str) -> list[str]  (argv, not shell string)
    expected_verdict: str = "informational"


SAFE_HEADERS_NOTE = "Never fetch outside program scope; scope engine runs FIRST."


class Pipeline:
    def __init__(self, program: Program, db: ObservationDB, gate: ApprovalGate,
                 tools: list[ReconTool] | None = None):
        self.scope = ScopeEngine(program)
        self.db = db
        self.gate = gate
        self.tools = tools or []

    def register(self, tool: ReconTool) -> None:
        self.tools.append(tool)

    def run_tool(self, target: str, tool: ReconTool) -> list[tuple[int, bool]]:
        """Run one registered tool against one in-scope target."""
        if not self.scope.is_in_scope(target):
            print(f"[DENIED by scope engine] {tool.name} on {target}")
            return []
        argv = tool.command_builder(target)
        print(f"[run] {tool.name}: {' '.join(argv)}")
        out = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
        rows = []
        for line in (out.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(self.db.insert(
                tool=tool.name, command=" ".join(argv), target=target,
                verdict=tool.expected_verdict, payload={"output": line[:4096]},
                scope_allowed=True,   # scope engine already blessed this target above
            ))
        return rows

    def queue_candidate(self, *, obs_row_id: int, target: str, title: str,
                        evidence: list[dict], draft_report: str) -> None:
        """Only path into the approval gate. Verify target scope again here (defense in depth)."""
        if not self.scope.is_in_scope(target):
            raise ValueError(f"refusing queue for out-of-scope {target!r}")
        self.gate.submit(obs_row_id=obs_row_id, target=target, title=title,
                         evidence=evidence, draft_report=draft_report)


if __name__ == "__main__":
    # self-test of the wiring without any tool: dry-run against example scope
    example = Program(name="demo",
                      in_scope=["*.example.com"],
                      out_of_scope=["staging.example.com"])
    db = ObservationDB("data/observations.db")
    gate = ApprovalGate("data/pending.jsonl", "data/decided.jsonl")
    pipe = Pipeline(example, db, gate)
    print(pipe.scope.explain("app.example.com"))
    print(pipe.scope.explain("staging.example.com"))
    print("db stats:", db.stats())
