"""Persistent Research Controller (TASK P2).

Integrates the Tev1 decision gateway into the existing Bounty Hunter execution path.
Reuses existing modules (Store, Scope, ScopedClient, Checker, Swarm, Scenarios, Verifier, Gate).
Does not create a parallel application or duplicate task store.

Explicit 18-Step Controller Loop:
  1. Validate selected program and scope.
  2. Load persisted research state.
  3. Discover eligible work if needed.
  4. Build candidates using existing endpoint, scenario and finding records.
  5. Create compact decision state.
  6. Ask local Tev1 to rank or select from supplied eligible candidates.
  7. Validate the selected ID.
  8. Check task eligibility again.
  9. Resolve the registered agent and its capabilities.
  10. Build a bounded investigation plan.
  11. Apply deterministic policy validation.
  12. Apply human approval requirements.
  13. Atomically claim the task.
  14. Execute only through existing controlled components.
  15. Store evidence and execution results.
  16. Queue independent verification.
  17. Update outcome and learning data.
  18. Continue, pause or complete.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from bb import analyze, cve, feedback, learn, normalize, waf
from bb.checks import CheckOptions, Checker, dedupe_findings
from bb.config import DEFAULT_MAX_REQUESTS, DEFAULT_RATE, DEFAULT_TIMEOUT, now_iso
from bb.decision.evaluator import DecisionEvaluator
from bb.decision.gateway import DecisionGateway
from bb.gate import ApprovalGate
from bb.http import BudgetExceeded, RequestBudget, ScopedClient
from bb.killswitch import AbortRequested, active as kill_active
from bb.models import Finding
from bb.orchestrator.adaptive import SwarmMetrics
from bb.orchestrator.agent_registry import AgentRegistry, AgentSpec
from bb.orchestrator.specialists import SpecialistWorkerRegistry, SpecialistRole, SPECIALIST_ROLES
from bb.orchestrator.lifecycle import LifecycleManager, State
from bb.orchestrator.planner import Planner
from bb.orchestrator.resource_manager import ResourceManager, SecurityPolicy
from bb.orchestrator.scheduler import Scheduler
from bb.orchestrator.swarm_runner import ControllerSwarmRunner
from bb.recon import Recon
from bb.scope import Scope
from bb.session import Role, login_roles
from bb.store import Store
from bb.swarm import Task
from bb.verify import verify_candidates


@dataclass
class ControllerConfig:
    program: str
    scope: Scope
    entry_urls: list[str]
    run_id: str | None = None
    accounts: dict | None = None
    rate: float = DEFAULT_RATE
    max_requests: int = DEFAULT_MAX_REQUESTS
    timeout: float = DEFAULT_TIMEOUT
    proxy: str | None = None
    dry_run: bool = False
    cbh: bool = False
    llm: bool = False
    workers: int = 4
    allow_write: bool = False
    require_human_approval: bool = True
    run_waf_probe: bool = True
    cve_match: bool = True
    ai_analysis: bool = True
    queue: bool = True
    tev1: bool = True
    adaptive_swarm: bool = True
    max_iterations: int = 200
    lease_seconds: float = 300.0
    check_options: CheckOptions = field(default_factory=CheckOptions)
    scenario_paths: list[str] = field(default_factory=list)


class Controller:
    """Persistent, state-machine-driven Bounty Hunter controller."""

    def __init__(self, cfg: ControllerConfig, store: Store | None = None,
                 log: Callable[[str], None] = print):
        self.cfg = cfg
        self.store = store or Store()
        self.log = log

        # 1. Initialize or load run ID
        if self.cfg.run_id:
            self.run_id = self.cfg.run_id
            existing = self.store.run(self.run_id)
            if not existing:
                self.run_id = self.store.start_run(
                    self.cfg.program,
                    target=",".join(self.cfg.entry_urls),
                    scope_fingerprint=self.cfg.scope.fingerprint,
                    meta={"controller": True, "created_at": now_iso()}
                )
        else:
            self.run_id = self.store.start_run(
                self.cfg.program,
                target=",".join(self.cfg.entry_urls),
                scope_fingerprint=self.cfg.scope.fingerprint,
                meta={"controller": True, "created_at": now_iso()}
            )

        # 2. Wire subsystems
        self.lifecycle = LifecycleManager(self.store, self.run_id, initial_state=State.DISCOVERING)
        self.policy = SecurityPolicy(
            allow_write=self.cfg.allow_write,
            require_human_approval_for_write=self.cfg.require_human_approval,
            rate=self.cfg.rate,
            max_requests=self.cfg.max_requests,
        )
        self.resource_mgr = ResourceManager(
            scope=self.cfg.scope,
            policy=self.policy,
            store=self.store,
            run_id=self.run_id,
        )
        self.roles: list[Role] = []
        self._endpoints: list[dict] = []
        self._findings: list[Finding] = []
        self._paused: bool = False
        self._aborted: bool = False
        self._iterations: int = 0
        self._metrics = SwarmMetrics()

        self.agent_registry = AgentRegistry()
        self.specialist_registry = SpecialistWorkerRegistry()
        self.scheduler = Scheduler(self.store, self.run_id, lease_seconds=self.cfg.lease_seconds)
        self.planner = Planner(self.cfg.scope, self.store, self.cfg.program)
        self.decision_gateway = DecisionGateway()
        self.decision_evaluator = DecisionEvaluator()
        self.swarm_runner = ControllerSwarmRunner(
            scope=self.cfg.scope,
            store=self.store,
            run_id=self.run_id,
            resource_mgr=self.resource_mgr,
            scheduler=self.scheduler,
            roles=self.roles,
            options=self.cfg.check_options,
            proxy=self.cfg.proxy,
            timeout=self.cfg.timeout,
            dry_run=self.cfg.dry_run,
            log=self.log,
        )

    # ---------- lifecycle control ----------

    def pause(self, reason: str = "operator pause") -> None:
        """Pause the controller cleanly."""
        self._paused = True
        self.lifecycle.pause(reason=reason)
        self.log(f"[*] Controller paused: {reason}")

    def resume(self, reason: str = "operator resume") -> None:
        """Resume execution from paused state."""
        self._paused = False
        self.lifecycle.resume(reason=reason)
        self.log(f"[*] Controller resumed: {reason}")

    def abort(self, reason: str = "operator abort") -> None:
        """Halt execution permanently."""
        self._aborted = True
        self.lifecycle.abort(reason=reason)
        self.log(f"[!] Controller aborted: {reason}")

    def status(self) -> dict[str, Any]:
        """Return full operational status for CLI or dashboard."""
        run_data = self.store.run(self.run_id) or {}
        return {
            "run_id": self.run_id,
            "program": self.cfg.program,
            "state": self.lifecycle.state.value,
            "is_paused": self.lifecycle.is_paused(),
            "is_terminal": self.lifecycle.is_terminal(),
            "budget_used": self.resource_mgr.budget.used,
            "max_requests": self.cfg.max_requests,
            "tasks": self.store.task_counts(self.run_id),
            "findings_count": len(self.store.findings(run_id=self.run_id)),
            "iterations": self._iterations,
            "history": self.lifecycle.history[-5:],
        }

    # ---------- client & tool factories ----------

    def _make_client(self, tool_name: str) -> ScopedClient:
        return ScopedClient(
            self.cfg.scope,
            proxy=self.cfg.proxy,
            timeout=self.cfg.timeout,
            rate=self.cfg.rate,
            max_requests=self.cfg.max_requests,
            dry_run=self.cfg.dry_run,
            store=self.store,
            run_id=self.run_id,
            tool=tool_name,
            shared=self.resource_mgr.budget,
        )

    # ---------- core 18-step controller loop ----------

    def step(self) -> dict[str, Any] | None:
        """Execute one complete cycle of the controller loop."""
        if self._paused or self.lifecycle.is_paused():
            return {"status": "paused", "state": self.lifecycle.state.value}
        if self._aborted or self.lifecycle.is_terminal():
            return {"status": "terminal", "state": self.lifecycle.state.value}

        # Step 1: Validate program and scope
        self.resource_mgr.check_killswitch()
        if not self.cfg.scope.in_rules:
            self.abort("scope has zero in-scope rules (deny-by-default)")
            return {"status": "aborted", "reason": "empty_scope"}

        # Step 2: Load persisted research state & recover leases
        recovered = self.scheduler.recover_expired_leases()
        if recovered > 0:
            self.log(f"[*] Recovered {recovered} orphaned running task lease(s)")

        # Step 3: Discover eligible work if needed (DISCOVERING & MAPPING)
        if self.lifecycle.state == State.DISCOVERING:
            self.log("[1/18] Surface discovery: crawling entrypoints and parsing JS bundles...")
            client = self._make_client("recon")
            recon = Recon(client, self.store, self.run_id, self.cfg.scope, log=self.log)
            for entry in self.cfg.entry_urls:
                eps = recon.passive(entry)
                self._endpoints.extend(eps)
            client.close()
            self.lifecycle.transition_to(State.MAPPING, reason="discovery finished")

        if self.lifecycle.state == State.MAPPING:
            self.log("[2/18] Normalizing routes and indexing dynamic parameter schemas...")
            for ep in self._endpoints:
                u = ep.get("url") if isinstance(ep, dict) else str(ep)
                m = ep.get("method", "GET") if isinstance(ep, dict) else "GET"
                if u:
                    self.store.record_route(self.run_id, u, method=m, source="discovery")
            self.lifecycle.transition_to(State.ANALYZING, reason="mapping finished")

        if self.lifecycle.state == State.ANALYZING:
            # Authenticate roles if needed
            if self.cfg.accounts and not self.roles:
                try:
                    self.roles = login_roles(
                        self.cfg.accounts, self.cfg.scope, proxy=self.cfg.proxy,
                        timeout=self.cfg.timeout, dry_run=self.cfg.dry_run,
                        store=self.store, run_id=self.run_id
                    )
                except Exception as exc:
                    self.log(f"[!] Authentication warning: {exc}")

            if self.cfg.cve_match:
                try:
                    idx = cve.CveIndex()
                    assets = self.store.assets(self.run_id)
                    for asset in assets:
                        server = asset.get("server") or ""
                        tech = asset.get("tech") or ""
                        q = f"{server} {tech}".strip()
                        if q:
                            hits = idx.query(q, k=3)
                            if hits:
                                self.log(f"      [CVE alert] {asset.get('host')}: {len(hits)} matching vulnerabilities")
                except Exception as exc:
                    self.log(f"      [CVE match skipped: {exc}]")

            self.lifecycle.transition_to(State.PLANNING, reason="analysis finished")

        # Step 4: Build candidates using existing endpoint, scenario and finding records
        if self.lifecycle.state == State.PLANNING:
            if not self.resource_mgr.check_budget_available():
                self.log("[!] Request budget exhausted. Finishing run.")
                self.lifecycle.transition_to(State.COMPLETED, reason="budget_exhausted")
                return {"status": "completed", "reason": "budget_exhausted"}

            candidates = self.planner.discover_candidates(
                self.cfg.entry_urls,
                endpoints=self._endpoints or self.store.endpoints(self.run_id),
                options=self.cfg.check_options,
                have_roles=bool(self.roles),
                scenario_paths=self.cfg.scenario_paths,
            )
            eligible = self.planner.filter_eligible(candidates, run_id=self.run_id, lease_seconds=self.cfg.lease_seconds)

            if not eligible:
                self.log("[*] No further eligible candidate tasks remain. Run complete.")
                self.lifecycle.transition_to(State.COMPLETED, reason="work_complete")
                return {"status": "completed", "reason": "work_complete"}

            # Step 5: Create compact decision state & evaluate scaling
            context = self.planner.build_decision_context(eligible)
            self._metrics.eligible_tasks = len(eligible)

            # Adaptive scaling evaluation
            tev1_worker_rec = None
            if self.cfg.tev1 and len(eligible) >= 5:
                # Optionally ask Tev1 for scale recommendation if many tasks exist
                pass

            allowed_workers, scale_reason = self.resource_mgr.evaluate_scaling(
                self._metrics, tev1_recommendation=tev1_worker_rec
            )

            # Step 6: Ask local Tev1 to rank or select from supplied eligible candidates
            selected_task = eligible[0]  # deterministic baseline default
            decision_id = f"dec-{self.run_id}-{self._iterations}"
            tev1_dec = {"choice": selected_task.fingerprint, "source": "deterministic-baseline"}

            if self.cfg.tev1:
                tev1_dec = self.decision_gateway.select_task(eligible, context)
                choice = tev1_dec.get("choice")
                if choice == "defer":
                    self.log("[*] Tev1 recommended deferral. Yielding step.")
                    return {"status": "deferred", "reason": "tev1_defer"}
                if choice and choice != "none":
                    for t in eligible:
                        if t.fingerprint == choice:
                            selected_task = t
                            break

            # Record decision evaluation record
            self.decision_evaluator.record_decision(
                decision_id=decision_id,
                run_id=self.run_id,
                decision_point="task-selection",
                options=[t.fingerprint for t in eligible[:10]],
                tev1_result=tev1_dec,
                baseline_choice=eligible[0].fingerprint,
                task_fingerprint=selected_task.fingerprint,
            )

            # Step 7: Validate the selected ID
            valid_ids = {t.fingerprint for t in eligible}
            if selected_task.fingerprint not in valid_ids:
                selected_task = eligible[0]  # fallback

            # Step 8: Check task eligibility again (concurrency check)
            rec = self.store.get_task(selected_task.fingerprint)
            if rec and rec.get("state") == "running":
                from datetime import datetime, timedelta, timezone
                try:
                    seen = datetime.fromisoformat(rec["updated_at"])
                    if seen.tzinfo is None:
                        seen = seen.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) - seen <= timedelta(seconds=self.cfg.lease_seconds):
                        # Still actively claimed by another worker
                        self.log(f"[*] Task {selected_task.fingerprint[:8]} claimed concurrently; re-planning.")
                        return {"status": "contended", "task": selected_task.fingerprint}
                except Exception:
                    pass

            # Step 9: Resolve the registered agent and its capabilities
            specialist = self.agent_registry.select_default_specialist(selected_task)
            if self.cfg.tev1:
                candidates_sp = [s.name for s in self.agent_registry.for_task_kind(selected_task.kind)]
                if candidates_sp:
                    sp_dec = self.decision_gateway.recommend_specialist(selected_task, candidates_sp)
                    chosen_sp = sp_dec.get("choice")
                    resolved = self.agent_registry.resolve(chosen_sp)
                    if resolved:
                        specialist = resolved

            # Step 10: Build a bounded investigation plan
            plan = self.planner.build_investigation_plan(selected_task, specialist)

            # Step 11: Apply deterministic policy validation
            self.lifecycle.transition_to(State.POLICY_REVIEW, reason="evaluating task policy")
            allowed, reason = self.resource_mgr.validate_task_policy(
                selected_task, specialist, has_roles=bool(self.roles)
            )
            if not allowed:
                self.log(f"[!] Task policy refused: {reason}")
                # Classify refusal: DNS/host resolution failures and scope denials are terminal
                # for this task, preventing infinite re-planning loops.
                is_terminal = "out of scope" in reason or "DNS resolution failed" in reason or "not in scope" in reason
                self.scheduler.record_policy_refusal(selected_task, reason, is_terminal=is_terminal)
                self.lifecycle.transition_to(State.PLANNING, reason="policy_refusal")
                return {"status": "refused", "reason": reason}

            # Step 12: Apply human approval requirements
            if self.resource_mgr.is_state_changing(selected_task):
                if not selected_task.payload.get("human_approved", False):
                    self.log(f"[!] Task {selected_task.fingerprint[:8]} requires human approval gate; holding.")
                    self.lifecycle.transition_to(State.PLANNING, reason="held_for_human_approval")
                    return {"status": "held_approval", "task": selected_task.fingerprint}

            # Step 13: Atomically claim the task
            if not self.scheduler.claim_task(selected_task):
                self.log(f"[*] Lost race claiming task {selected_task.fingerprint[:8]}; re-planning.")
                self.lifecycle.transition_to(State.PLANNING, reason="claim_race_lost")
                return {"status": "claim_failed", "task": selected_task.fingerprint}

            # Step 14: Execute only through existing controlled components
            self.lifecycle.transition_to(State.EXECUTING, reason=f"executing {selected_task.kind}")
            client = self._make_client("controller_worker")
            checker = Checker(
                client, self.store, self.run_id, self.cfg.scope,
                roles=self.roles, options=self.cfg.check_options, log=lambda *a, **k: None
            )

            discovered_findings: list[Finding] = []
            try:
                ep = selected_task.payload.get("endpoint") or {"url": selected_task.target, "method": "GET"}
                if selected_task.kind == "authz":
                    discovered_findings = checker.check_authz([ep])
                elif selected_task.kind == "unauth":
                    discovered_findings = checker.check_unauth([ep])
                elif selected_task.kind == "graphql":
                    discovered_findings = checker.check_graphql([ep])
                elif selected_task.kind == "open_redirect":
                    discovered_findings = checker.check_open_redirect([ep])
                elif selected_task.kind == "cors":
                    discovered_findings = checker.check_cors([selected_task.target])
                elif selected_task.kind == "exposed":
                    discovered_findings = checker.check_exposed([selected_task.target])
                elif selected_task.kind == "headers":
                    discovered_findings = checker.check_headers([selected_task.target])
                elif selected_task.kind == "waf_probe":
                    if self.cfg.run_waf_probe:
                        waf_rep = waf.probe_url(client, selected_task.target)
                        if waf_rep.get("bypasses"):
                            self.log(f"      [WAF Inconsistency] {selected_task.target}: {len(waf_rep['bypasses'])} bypasses")
                elif selected_task.kind == "scenario":
                    from bb import scenario
                    sc_data = scenario.load_scenario(selected_task.target)
                    res = scenario.run_scenario(
                        sc_data, scope=self.cfg.scope, accounts=self.cfg.accounts,
                        program=self.cfg.program, store=self.store, allow_write=self.cfg.allow_write,
                        dry_run=self.cfg.dry_run, proxy=self.cfg.proxy
                    )
                    if res.get("finding"):
                        discovered_findings.append(res["finding"])

                # Step 15: Store evidence and execution results
                for f in discovered_findings:
                    self.store.add_finding(f, run_id=self.run_id)
                self._findings.extend(discovered_findings)

                self.scheduler.finish_task(
                    selected_task.fingerprint, state="done",
                    result={"findings": [f.id for f in discovered_findings], "requests": client.sent}
                )
                self.decision_evaluator.attach_execution_result(
                    decision_id=decision_id,
                    status="done",
                    findings_count=len(discovered_findings),
                    requests_cost=client.sent,
                )
                self.log(f"  [controller] {selected_task.kind:12} {selected_task.target[:60]} -> {len(discovered_findings)} finding(s)")
            except Exception as exc:
                self.scheduler.finish_task(selected_task.fingerprint, state="failed", result={"error": str(exc)})
                self.decision_evaluator.attach_execution_result(
                    decision_id=decision_id,
                    status="failed",
                    findings_count=0,
                    requests_cost=client.sent if 'client' in locals() else 0,
                )
                self.log(f"  [controller] {selected_task.kind:12} {selected_task.target[:60]} FAILED: {exc}")
            finally:
                client.close()

            # Step 16: Queue independent verification
            self.lifecycle.transition_to(State.VERIFYING, reason="verifying findings")
            deduped = dedupe_findings(self._findings)
            v_client = self._make_client("controller_verify")
            verif_summary = {"confirmed": 0, "rejected": 0, "kept": 0}
            try:
                verif_summary = verify_candidates(
                    self.store, self.cfg.scope, self.cfg.program,
                    accounts=self.cfg.accounts, client=v_client, log=lambda *a, **k: None
                )
            finally:
                v_client.close()

            # Attach verification status to decision evaluation
            verif_stat = "confirmed" if verif_summary.get("confirmed", 0) > 0 else (
                "rejected" if verif_summary.get("rejected", 0) > 0 else "inconclusive"
            )
            self.decision_evaluator.attach_verification_result(
                decision_id=decision_id,
                verification_status=verif_stat,
            )

            # Step 17: Update outcome and learning data
            self.lifecycle.transition_to(State.LEARNING, reason="updating priors and triage")
            gate = ApprovalGate(self.store)
            priors = feedback.class_priors(self.store, program=self.cfg.program)
            for f in deduped:
                if self.cfg.tev1:
                    t_dec = self.decision_gateway.triage_finding(f)
                    f.meta["tev1_triage"] = t_dec
                    self.store.update_meta(f.id, tev1_triage=t_dec)
                if self.cfg.ai_analysis:
                    try:
                        an = analyze.analyze(f, use_llm=self.cfg.llm)
                        f.meta["ai_analysis"] = an
                        self.store.update_meta(f.id, ai_analysis=an)
                    except Exception:
                        pass
                if self.cfg.queue:
                    weight = priors.get(f.bug_class, {}).get("weight", 0.5)
                    f.meta["feedback_weight"] = weight
                    self.store.update_meta(f.id, feedback_weight=weight)
                    gate.submit(f.id, channel="controller")

            # Step 18: Continue, pause or complete
            self._iterations += 1
            if self._iterations >= self.cfg.max_iterations:
                self.lifecycle.transition_to(State.COMPLETED, reason="max_iterations_reached")
                return {"status": "completed", "reason": "max_iterations"}

            self.lifecycle.transition_to(State.PLANNING, reason="next_cycle")
            return {"status": "progress", "task": selected_task.fingerprint, "findings": len(discovered_findings)}

        return {"status": "noop", "state": self.lifecycle.state.value}

    def run(self) -> dict[str, Any]:
        """Execute the persistent controller loop until completion, pause, or abort."""
        if kill_active():
            self.log("[!] Kill switch is active. Aborting controller.")
            self.abort("kill switch is active")
            return {"status": "aborted", "reason": "kill_switch_active", "run_id": self.run_id}

        self.log(f"[*] Starting Persistent Controller run {self.run_id} for program '{self.cfg.program}'")
        while not self.lifecycle.is_terminal() and not self._paused:
            res = self.step()
            if not res or res.get("status") in ("completed", "aborted", "paused"):
                break

        self.decision_evaluator.flush()
        self.store.finish_run(self.run_id)
        findings = self.store.findings(run_id=self.run_id)
        verified = [f for f in findings if f.status == "confirmed"]

        return {
            "status": self.lifecycle.state.value.lower(),
            "run_id": self.run_id,
            "tasks_executed": self._iterations,
            "findings": len(findings),
            "verified": len(verified),
            "budget_used": self.resource_mgr.budget.used,
            "decision_evaluation": self.decision_evaluator.generate_report(run_id=self.run_id),
        }
