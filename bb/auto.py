"""Autonomous Hunter Orchestrator — stateful, feedback-driven bug hunting loop.

Coordinates the full autonomous investigation lifecycle:
  1. Scope verification & safety checks
  2. Passive & active surface discovery (endpoints, parameters, JS routes)
  3. Route normalization & state recording
  4. Technology detection & CVE intelligence matching
  5. Dual-role authorization & differential testing (IDOR/BOLA)
  6. Parameter WAF resilience probing (defensive encoding mapping)
  7. Verification pass (offline audit & online dual-role replay)
  8. AI response triage & next-test hypothesis suggestions
  9. Human approval gate queuing & continuous learning dataset sync
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from bb import analyze, cve, feedback, learn, normalize, swarm, waf
from bb.checks import CheckOptions, Checker, dedupe_findings
from bb.config import DEFAULT_MAX_REQUESTS, DEFAULT_RATE, DEFAULT_TIMEOUT, ensure_dirs, now_iso
from bb.gate import ApprovalGate
from bb.http import BudgetExceeded, RequestBudget, ScopedClient
from bb.killswitch import active as kill_active
from bb.models import Finding, sev_rank
from bb.recon import Recon
from bb.scope import Scope
from bb.session import Role, login_roles
from bb.store import Store
from bb import tev1
from bb.verify import verify_candidates


@dataclass
class AutoHunterConfig:
    program: str
    scope: Scope
    entry_urls: list[str]
    accounts: dict | None = None
    rate: float = DEFAULT_RATE
    max_requests: int = DEFAULT_MAX_REQUESTS
    timeout: float = DEFAULT_TIMEOUT
    proxy: str | None = None
    dry_run: bool = False
    cbh: bool = False
    llm: bool = False
    workers: int = 4
    run_waf_probe: bool = True
    cve_match: bool = True
    ai_analysis: bool = True
    queue: bool = True
    tev1: bool = True
    check_options: CheckOptions = field(default_factory=CheckOptions)


class AutoHunter:
    def __init__(self, cfg: AutoHunterConfig, store: Store | None = None, log: Callable[[str], None] = print):
        self.cfg = cfg
        self.store = store or Store()
        self.log = log
        self.run_id = f"auto-{now_iso().replace(':', '').replace('-', '')[:15]}"
        self.findings: list[Finding] = []

    def _tev1_triage(self, f: Finding) -> dict:
        """Structured triage recommendation. Validated choice, advisory only.

        The context is a compact structured summary — no response bodies, no
        evidence dumps, no credentials. Every option from the engine is
        validated; whatever Tev1 recommends, the human gate still decides.
        """
        from urllib.parse import urlsplit
        ctx = {
            "bug_class": f.bug_class,
            "severity": f.severity,
            "confidence": f.confidence,
            "status": f.status,
            "path": (urlsplit(f.url or "").path or "/"),
            "evidence_count": len(f.evidence),
            "similarity": f.meta.get("similarity"),
            "verified": bool(f.meta.get("verified")),
        }
        try:
            return tev1.decide(
                "auto-triage",
                list(analyze.VERDICTS) + ["defer", "none"],
                ctx,
                question="recommend a triage verdict for this finding",
                default="none",
            )
        except Exception as exc:
            return {"decision_point": "auto-triage", "source": "deterministic-fallback",
                    "choice": "none", "reason": f"decision client error: {exc}"}

    def run(self) -> dict:
        if kill_active():
            self.log("[!] Kill switch is active. Aborting autonomous hunter.")
            return {"status": "aborted", "reason": "kill_switch_active", "run_id": self.run_id}

        self.log(f"[*] Starting Autonomous Hunter run {self.run_id} for program '{self.cfg.program}'")
        self.run_id = self.store.start_run(
            self.cfg.program,
            target=",".join(self.cfg.entry_urls),
            scope_fingerprint=self.cfg.scope.fingerprint,
            meta={"autonomous": True, "llm": self.cfg.llm, "workers": self.cfg.workers}
        )

        # one shared budget for every phase-1..7 client: recon and investigation
        # together cannot exceed --max-requests or the global rate (audit F1)
        budget = RequestBudget(rate=self.cfg.rate, max_requests=self.cfg.max_requests)

        # Phase 1: Recon & Discovery
        self.log("[1/7] Surface discovery: crawling entrypoints, JS bundles, and OpenAPI schemas...")
        recon_client = ScopedClient(self.cfg.scope, proxy=self.cfg.proxy, timeout=self.cfg.timeout,
                                    rate=self.cfg.rate, max_requests=self.cfg.max_requests,
                                    dry_run=self.cfg.dry_run, store=self.store, run_id=self.run_id,
                                    tool="auto_recon", shared=budget)
        recon = Recon(recon_client, self.store, self.run_id, self.cfg.scope, log=self.log)
        endpoints = []
        for entry in self.cfg.entry_urls:
            eps = recon.passive(entry)
            endpoints.extend(eps)
        assets = self.store.assets(self.run_id)
        self.log(f"      Discovered {len(assets)} assets and {len(endpoints)} unique endpoints.")

        # Phase 2: Route Normalization & Parameter Inventory
        self.log("[2/7] Normalizing routes and indexing dynamic parameter schemas...")
        norm_count = 0
        for ep in endpoints:
            u = ep.get("url") if isinstance(ep, dict) else str(ep)
            m = ep.get("method", "GET") if isinstance(ep, dict) else "GET"
            if u:
                template = normalize.normalize_path(u)
                self.store.record_route(self.run_id, ep.get("host", ""), m, template, u, source="discovery")
                norm_count += 1
        self.log(f"      Indexed {norm_count} route templates in state store.")

        # Phase 3: Offline CVE Intelligence Matching
        if self.cfg.cve_match:
            self.log("[3/7] Correlating asset technologies with local CVE/KEV database...")
            try:
                idx = cve.CveIndex()
                for asset in assets:
                    server = asset.get("server") or ""
                    tech = asset.get("tech") or ""
                    query = f"{server} {tech}".strip()
                    if query:
                        hits = idx.query(query, k=5)
                        if hits:
                            self.log(f"      [CVE alert] {asset.get('host')}: {len(hits)} matching vulnerabilities")
            except Exception as e:
                self.log(f"      [CVE lookup skipped: {e}]")

        # Phase 4: Swarm / Deterministic Checks & Differential Testing
        self.log("[4/7] Running investigation engine: checks, access controls & authorization...")
        roles = []
        if self.cfg.accounts:
            try:
                roles = login_roles(self.cfg.accounts, self.cfg.scope, proxy=self.cfg.proxy,
                                    timeout=self.cfg.timeout, dry_run=self.cfg.dry_run,
                                    store=self.store, run_id=self.run_id)
                self.log(f"      Authenticated {len(roles)} role session(s) for differential testing.")
            except Exception as exc:
                self.log(f"      [!] Authentication warning: {exc}")

        client = ScopedClient(self.cfg.scope, proxy=self.cfg.proxy, timeout=self.cfg.timeout,
                              rate=self.cfg.rate, max_requests=self.cfg.max_requests,
                              dry_run=self.cfg.dry_run, store=self.store, run_id=self.run_id,
                              tool="auto_hunter", shared=budget)
        checker = Checker(client, self.store, self.run_id, self.cfg.scope, roles=roles,
                          options=self.cfg.check_options, log=self.log)
        discovered_findings = checker.run_all(self.cfg.entry_urls, endpoints)
        self.findings.extend(discovered_findings)
        self.log(f"      Investigation identified {len(discovered_findings)} candidate finding(s).")

        # Phase 5: WAF Resilience / Normalization Probing (Defensive)
        if self.cfg.run_waf_probe and endpoints:
            self.log("[5/7] Probing parameter normalization resilience (defensive WAF probe)...")
            target_eps = [ep for ep in endpoints if isinstance(ep, dict) and "?" in (ep.get("url") or "")][:3]
            for ep in target_eps:
                try:
                    probe_report = waf.probe_url(client, ep["url"])
                    if probe_report.get("bypasses"):
                        self.log(f"      [WAF Inconsistency] {ep['url']}: {len(probe_report['bypasses'])} encoding discrepancy")
                except Exception:
                    pass

        # Phase 6: Independent Verification
        self.log("[6/7] Independently verifying findings before queuing...")
        deduped = dedupe_findings(self.findings)
        for f in deduped:
            self.store.add_finding(f)
        report = verify_candidates(self.store, self.cfg.scope, self.cfg.program,
                                   accounts=self.cfg.accounts, client=client, log=self.log)
        verified_count = report.get("confirmed", 0)
        self.log(f"      Verified {len(deduped)} finding(s); {verified_count} confirmed.")

        # Phase 7: AI Response Analysis & Queueing
        self.log("[7/7] Synthesizing evidence, AI response analysis & queuing for human review...")
        gate = ApprovalGate(self.store)
        priors = feedback.class_priors(self.store, program=self.cfg.program)
        for f in deduped:
            if self.cfg.tev1:
                decision = self._tev1_triage(f)
                f.meta["tev1_triage"] = decision
                self.store.update_meta(f.id, tev1_triage=decision)
            if self.cfg.ai_analysis:
                try:
                    analysis = analyze.analyze(f, use_llm=self.cfg.llm)
                    f.meta["ai_analysis"] = analysis
                    self.store.update_meta(f.id, ai_analysis=analysis)
                except Exception:
                    pass
            if self.cfg.queue:
                weight = priors.get(f.bug_class, {}).get("weight", 0.5)
                f.meta["feedback_weight"] = weight
                self.store.update_meta(f.id, feedback_weight=weight)
                gate.submit(f.id, channel="autonomous")

        self.store.finish_run(self.run_id)
        self.log(f"[+] Autonomous run complete! {len(deduped)} finding(s) queued for review.")
        return {
            "status": "completed",
            "run_id": self.run_id,
            "assets": len(assets),
            "endpoints": len(endpoints),
            "findings": len(deduped),
            "verified": verified_count,
        }
