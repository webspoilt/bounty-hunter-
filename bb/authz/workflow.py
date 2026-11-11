"""Autonomous two-account authorization investigation workflow.

Coordinates the end-to-end 20-step investigation:
1. Load authorized program & validate scope.
2. Ingest HAR traffic and redact sensitive values.
3. Build typed application model & inventory.
4. Associate researcher-controlled accounts A and B.
5. Generate authorization hypotheses (unauthorized read/write/tenant-crossing).
6. Prioritize candidates via Tev1 structured choices with deterministic fallback.
7. Produce structured investigation plan (plannable without execution).
8. Enforce deterministic scope, method, budget, and kill-switch policies.
9. Enforce strict human approval gate for state-changing write operations.
10. Execute permitted scenarios through scoped infrastructure.
11. Record exchanges and evidence with full provenance in Store.
12. Independently verify suspicious findings against adversarial controls.
13. Generate reproducible reports and place in human approval queue.
14. Support full checkpoint persistence and crash recovery.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from bb.authz.hypothesis import (
    build_inventory_from_har,
    generate_hypotheses,
    prioritize_hypotheses_with_tev1,
)
from bb.authz.model import (
    ApplicationModel,
    EvidenceRef,
    Hypothesis,
    Identity,
    Role,
)
from bb.authz.verifier import AuthorizationVerifier, VerificationResult
from bb.config import DATA, now_iso
from bb.decision.gateway import DecisionGateway
from bb.gate import ApprovalGate
from bb.har import HarEntry
from bb.http import RequestBudget, ScopedClient
from bb.orchestrator.resource_manager import ResourceManager, SecurityPolicy
from bb.propose import load_har
from bb.report import write_report
from bb.scenario import Role as ScenarioRole
from bb.scenario import run_scenario
from bb.scope import Scope
from bb.store import Finding, Store

AUTHZ_CHECKPOINTS_DIR = DATA / "authz_checkpoints"


@dataclass
class InvestigationState:
    investigation_id: str
    program: str
    created_at: str
    updated_at: str
    status: str  # "planned", "running", "paused", "completed", "aborted"
    role_a: str
    role_b: str
    har_path: str
    hypotheses_count: int = 0
    executed_hypotheses: list[str] = field(default_factory=list)
    approved_operations: dict[str, str] = field(default_factory=dict)  # op_token -> approval_timestamp
    verified_findings: list[str] = field(default_factory=list)
    rejected_findings: list[str] = field(default_factory=list)
    inconclusive_findings: list[str] = field(default_factory=list)
    requests_consumed: int = 0
    approval_ttl_seconds: float = 3600.0  # Approvals expire after 1 hour (3600s)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InvestigationState:
        # Handle backward compatibility if approved_operations was a list
        if isinstance(data.get("approved_operations"), list):
            data["approved_operations"] = {op: data.get("updated_at", now_iso()) for op in data["approved_operations"]}
        return cls(**data)


class AuthzInvestigationWorkflow:
    """Orchestrator for autonomous two-account authorization investigations."""

    def __init__(
        self,
        program: str,
        scope: Scope,
        accounts: dict[str, Any],
        store: Store,
        har_path: str | Path,
        budget: RequestBudget | None = None,
        gateway: DecisionGateway | None = None,
        investigation_id: str | None = None,
        log: Callable[[str], None] = print,
    ):
        self.program = program
        self.scope = scope
        self.accounts = accounts
        self.store = store
        self.har_path = str(Path(har_path).resolve())
        self.budget = budget or RequestBudget(rate=3.0, max_requests=100)
        self.gateway = gateway or DecisionGateway()
        self.log = log

        self.investigation_id = investigation_id or f"AUTHZ-{program}-{now_iso()[:10].replace('-', '')}-{hash(self.har_path) & 0xFFFF:04x}"
        self.checkpoint_path = AUTHZ_CHECKPOINTS_DIR / f"{self.investigation_id}.json"

        self.model = ApplicationModel(program=program)
        self.resource_mgr = ResourceManager(scope=scope, budget=self.budget, store=store)
        self.gate = ApprovalGate(store)

        self.state = self._load_or_init_state()

    def _load_or_init_state(self) -> InvestigationState:
        AUTHZ_CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
        if self.checkpoint_path.exists():
            try:
                data = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
                self.log(f"Resumed existing investigation state from {self.checkpoint_path}")
                return InvestigationState.from_dict(data)
            except Exception as exc:
                self.log(f"Warning: could not parse checkpoint ({exc}); starting fresh.")

        role_a_name = self.accounts.get("accounts", [{}])[0].get("label", "A") if self.accounts.get("accounts") else "A"
        role_b_name = self.accounts.get("accounts", [{}])[1].get("label", "B") if len(self.accounts.get("accounts", [])) > 1 else "B"

        state = InvestigationState(
            investigation_id=self.investigation_id,
            program=self.program,
            created_at=now_iso(),
            updated_at=now_iso(),
            status="planned",
            role_a=role_a_name,
            role_b=role_b_name,
            har_path=self.har_path,
        )
        self._save_state(state)
        return state

    def _save_state(self, state: InvestigationState) -> None:
        state.updated_at = now_iso()
        AUTHZ_CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")

    def build_plan(self) -> dict[str, Any]:
        """Produce a complete, structured investigation plan without executing requests."""
        self.log(f"Building investigation plan for program '{self.program}'...")

        # 1. Parse and validate HAR traffic within scope
        entries = load_har(self.har_path)
        scoped_entries = [e for e in entries if self.scope.is_in_scope(e.url)]
        self.log(f"Ingested {len(entries)} HAR entries ({len(scoped_entries)} within authorized scope).")

        # 2. Build application model and inventories
        build_inventory_from_har(self.model, scoped_entries, self.scope)

        # 3. Associate roles and identities from configured accounts
        acc_list = self.accounts.get("accounts", [])
        for acc in acc_list:
            lbl = acc.get("label", "unknown")
            ident = acc.get("email") or acc.get("username") or lbl
            self.model.add_role(Role(name=lbl, label=lbl, provenance="operator-confirmed"))
            self.model.add_identity(Identity(role=lbl, identifier=ident, provenance="operator-confirmed"))

        # 4. Generate hypotheses
        hypotheses = generate_hypotheses(
            self.model,
            self.har_path,
            scope=self.scope,
            role_a=self.state.role_a,
            role_b=self.state.role_b,
        )
        self.state.hypotheses_count = len(hypotheses)
        self.log(f"Generated {len(hypotheses)} authorization hypotheses.")

        # 5. Prioritize via Tev1
        prioritized = prioritize_hypotheses_with_tev1(self.gateway, hypotheses)

        # 6. Build plan summary
        plan = {
            "investigation_id": self.investigation_id,
            "program": self.program,
            "roles": [r.to_dict() for r in self.model.roles.values()],
            "endpoints_observed": len(self.model.endpoints),
            "parameters_observed": len(self.model.parameters),
            "objects_observed": len(self.model.objects),
            "hypotheses": [h.to_dict() for h in prioritized],
            "state_changing_count": sum(1 for h in prioritized if h.is_state_changing),
            "safe_read_count": sum(1 for h in prioritized if not h.is_state_changing),
        }
        self.state.status = "planned"
        self._save_state(self.state)
        return plan

    def run_investigation(
        self,
        allow_write: bool = False,
        approved_operations: list[str] | None = None,
        client: ScopedClient | None = None,
        transport: Any = None,
    ) -> dict[str, Any]:
        """Execute the full authorization investigation under strict policy controls."""
        # Check kill switch before starting investigation
        from bb import killswitch
        if killswitch.active():
            raise RuntimeError(f"kill switch active: {killswitch.reason() or 'armed'}")

        self.state.status = "running"
        self._save_state(self.state)

        # Build / refresh plan and hypotheses
        plan = self.build_plan()
        prioritized: list[Hypothesis] = [self.model.hypotheses[h["id"]] for h in plan["hypotheses"]]

        if approved_operations:
            current_time = now_iso()
            for op in approved_operations:
                self.state.approved_operations[op] = current_time

        # Set up ScopedClient with shared request budget
        active_client = client or ScopedClient(
            scope=self.scope,
            shared=self.budget,
            store=self.store,
            transport=transport,
            writes_approved=allow_write,
        )
        verifier = AuthorizationVerifier(active_client)

        results_summary: list[dict[str, Any]] = []

        for hypo in prioritized:
            # Check kill switch before each candidate
            self.resource_mgr.check_killswitch()

            # Prevent duplicate executions on resumption
            if hypo.id in self.state.executed_hypotheses:
                self.log(f"Skipping already executed hypothesis {hypo.id}")
                continue

            self.log(f"\nEvaluating candidate {hypo.id}: {hypo.title}")

            # Safety and policy check: verify state-changing operations
            if hypo.is_state_changing:
                # Require explicit operator approval bound to method, endpoint, object_id, role, scenario and investigation
                op_token = (
                    f"{self.investigation_id}:{hypo.id}:{hypo.target_method}:"
                    f"{hypo.target_endpoint}:{hypo.object_id}:{hypo.attacker_role}:{hypo.scenario.name}"
                )
                approval_time_str = self.state.approved_operations.get(op_token)
                is_expired = False
                if approval_time_str:
                    try:
                        from datetime import datetime, timezone
                        app_dt = datetime.fromisoformat(approval_time_str)
                        age_sec = (datetime.now(timezone.utc) - app_dt).total_seconds()
                        if age_sec > self.state.approval_ttl_seconds:
                            is_expired = True
                    except Exception:
                        is_expired = True

                is_approved = allow_write or (bool(approval_time_str) and not is_expired)

                if is_expired:
                    self.log(f"  [GATE] Approval for {hypo.id} ({op_token}) expired; requires re-authorization.")
                    results_summary.append({
                        "hypothesis_id": hypo.id,
                        "status": "skipped",
                        "op_token": op_token,
                        "reason": "state-changing approval expired; renewed operator approval required",
                    })
                    continue

                if not is_approved:
                    self.log(f"  [GATE] State-changing operation {hypo.id} ({op_token}) requires operator approval; skipping.")
                    hypo.status = "awaiting_approval"
                    results_summary.append({
                        "hypothesis_id": hypo.id,
                        "status": "skipped",
                        "op_token": op_token,
                        "reason": "state-changing operation requires operator approval",
                    })
                    continue

            # Execute scenario via existing scoped infrastructure (queue=False so Authz workflow manages verified finding)
            scenario_data = hypo.scenario.to_dict()
            try:
                run_res = run_scenario(
                    scenario=scenario_data,
                    scope=self.scope,
                    accounts=self.accounts,
                    program=self.program,
                    store=self.store,
                    allow_write=hypo.is_state_changing,
                    transport=transport,
                    queue=False,
                    log=self.log,
                )
            except Exception as exc:
                self.log(f"  [ERROR] Execution of {hypo.id} failed: {exc}")
                results_summary.append({
                    "hypothesis_id": hypo.id,
                    "status": "error",
                    "error": str(exc),
                })
                continue

            self.state.executed_hypotheses.append(hypo.id)
            claim_verdict = run_res.get("verdict", "inconclusive")
            self.log(f"  [SCENARIO EXECUTION] Claim verdict: {claim_verdict}")

            # Independent Adversarial Verification
            roles_map = {
                acc.get("label", "A"): ScenarioRole(
                    label=acc.get("label", "A"),
                    identity=acc.get("email") or acc.get("username") or acc.get("label", "A"),
                )
                for acc in self.accounts.get("accounts", [])
            }

            v_result = verifier.verify_hypothesis_result(
                hypothesis=hypo,
                execution_results=run_res,
                roles=roles_map,
                variables=scenario_data.get("variables", {}),
            )
            self.log(f"  [VERIFIER] Status: {v_result.status} ({v_result.verdict}) - {v_result.reason}")

            if v_result.status == "verified":
                hypo.status = "verified"
                self.state.verified_findings.append(hypo.id)

                # Persist reproducible Finding in Store and generate report if not already recorded by scenario
                scenario_finding = run_res.get("finding")
                finding_id = getattr(scenario_finding, "id", None) or f"BH-{self.program.upper()}-{hypo.id}"
                finding = self.store.get_finding(finding_id)

                if not finding:
                    finding = Finding(
                        id=finding_id,
                        title=hypo.title,
                        bug_class="Broken Object-Level Authorization (IDOR)",
                        severity="high" if hypo.is_state_changing else "medium",
                        confidence="high",
                        status="verified",
                        host=urlsplit(hypo.scenario.base_url).netloc,
                        url=hypo.target_endpoint,
                        summary=hypo.description,
                        impact="Unauthorized access allows cross-account interaction without proper access control checks.",
                        remediation="Enforce server-side authorization checks verifying user ownership or tenant tenancy before processing.",
                        steps=[f"1. Run scenario {hypo.scenario.name}", "2. Verify cross-account data leakage across roles."],
                        evidence=[],
                        meta={
                            "hypothesis": hypo.to_dict(),
                            "verification": v_result.to_dict(),
                            "investigation_id": self.investigation_id,
                        },
                    )
                    self.store.add_finding(finding, run_id=self.investigation_id)

                    try:
                        rep_path, _ = write_report(finding, scope=self.scope)
                        if rep_path:
                            self.store.set_report_path(finding_id, str(rep_path))
                    except Exception as r_err:
                        self.log(f"  [REPORT] Could not write report: {r_err}")

                    self.gate.submit(finding_id, channel="cli")
                    self.log(f"  [QUEUE] Finding {finding_id} placed in human approval queue.")
                else:
                    self.store.set_status(finding.id, "verified")
                    self.store.update_meta(finding.id, verification=v_result.to_dict())
                    # Ensure finding is in human approval queue
                    self.gate.submit(finding.id, channel="cli")
                    self.log(f"  [VERIFIED] Finding {finding_id} updated with verification evidence and queued.")

            elif v_result.status == "rejected":
                hypo.status = "rejected"
                self.state.rejected_findings.append(hypo.id)
            else:
                hypo.status = "inconclusive"
                self.state.inconclusive_findings.append(hypo.id)

            results_summary.append({
                "hypothesis_id": hypo.id,
                "status": v_result.status,
                "verdict": v_result.verdict,
                "reason": v_result.reason,
            })

            # Checkpoint progress after each candidate
            self._save_state(self.state)

        self.state.status = "completed"
        self._save_state(self.state)

        return {
            "investigation_id": self.investigation_id,
            "status": self.state.status,
            "total_hypotheses": len(prioritized),
            "verified": len(self.state.verified_findings),
            "rejected": len(self.state.rejected_findings),
            "inconclusive": len(self.state.inconclusive_findings),
            "results": results_summary,
        }
