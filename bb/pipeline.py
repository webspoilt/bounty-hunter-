"""Pipeline: scope -> recon -> login -> checks -> report -> approval queue.

Everything is opt-in and bounded: a time budget, a request budget, and a polite rate.
The pipeline can run without accounts (infrastructure checks only) and without a model.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from bb.checks import CheckOptions, Checker, dedupe_findings
from bb.config import DEFAULT_MAX_REQUESTS, DEFAULT_RATE, DEFAULT_TIMEOUT, ensure_dirs
from bb.gate import ApprovalGate
from bb.http import BudgetExceeded, ScopedClient
from bb.models import Finding, sev_rank
from bb.recon import Recon
from bb.scope import Scope
from bb.session import Role, login_roles
from bb.store import Store


@dataclass
class HuntConfig:
    program: str
    scope: Scope
    entry_urls: list[str]
    accounts: dict | None = None
    endpoints: list[str] = field(default_factory=list)
    templates: list[str] = field(default_factory=list)
    budget_min: float = 20.0
    rate: float = DEFAULT_RATE
    max_requests: int = DEFAULT_MAX_REQUESTS
    timeout: float = DEFAULT_TIMEOUT
    proxy: str | None = None
    dry_run: bool = False
    cbh: bool = False
    llm: bool = False
    queue: bool = True
    check_options: CheckOptions = field(default_factory=CheckOptions)


def hunt(cfg: HuntConfig, store: Store | None = None, log=print) -> dict:
    ensure_dirs()
    store = store or Store()
    scope = cfg.scope
    if not cfg.entry_urls:
        raise SystemExit("no entry URLs — pass --entry https://app.example.com/")

    # every entry must be in scope before we even open a client
    for url in cfg.entry_urls:
        decision = scope.check(url)
        if not decision.allowed:
            raise SystemExit(f"REFUSED entry {url}: {decision.reason}\n"
                             f"current scope:\n{scope.describe()}")

    run_id = store.start_run(cfg.program, cfg.entry_urls[0], scope.fingerprint,
                             {"rate": cfg.rate, "budget_min": cfg.budget_min,
                              "dry_run": cfg.dry_run, "checks": sorted(cfg.check_options.enabled)})
    deadline = time.monotonic() + cfg.budget_min * 60
    client = ScopedClient(scope, base_url=cfg.entry_urls[0], proxy=cfg.proxy,
                          timeout=cfg.timeout, rate=cfg.rate,
                          max_requests=cfg.max_requests, deadline=deadline,
                          dry_run=cfg.dry_run, store=store, run_id=run_id, tool="hunt")
    log(f"run {run_id} | program {cfg.program} | scope {scope.fingerprint} | "
        f"budget {cfg.budget_min:g}m @ {cfg.rate:g} req/s"
        + (" | DRY RUN" if cfg.dry_run else ""))

    endpoints: list[dict] = []
    roles: list[Role] = []
    findings: list[Finding] = []
    try:
        # ---- recon ----
        recon = Recon(client, store, run_id, scope, log=log)
        for url in cfg.entry_urls:
            try:
                endpoints += recon.passive(url)
            except BudgetExceeded:
                log("  budget reached during recon")
                raise
        if cfg.cbh:
            domain = scope.check(cfg.entry_urls[0]).host
            recon.cbh_recon(domain)
            endpoints = list(recon.seen.values())

        # ---- explicit endpoints ----
        for raw in cfg.endpoints:
            url = client.resolve(raw)
            if scope.is_in_scope(url):
                recon._add(url, source="operator")
        endpoints = list(recon.seen.values())

        # ---- roles ----
        if cfg.accounts:
            if cfg.dry_run:
                from bb.session import Role
                roles = [Role(label=acc.get("label", f"role{i}"),
                              email=acc.get("email", ""),
                              identity=acc.get("identity") or acc.get("email", ""),
                              user_id=i + 1)
                         for i, acc in enumerate((cfg.accounts.get("accounts") or [])[:2])]
                log("  [auth] dry-run: login skipped, using placeholder role ids")
            else:
                log("  [auth] logging in two roles")
                roles = login_roles(client, cfg.accounts, log=log)
            for tmpl in cfg.templates:
                for role in roles[:2]:
                    url = client.resolve(tmpl.format(
                        a_id=_id(roles[0]), b_id=_id(roles[1]),
                        a_email=roles[0].email, b_email=roles[1].email))
                    if scope.is_in_scope(url):
                        recon._add(url, source="self-object")
        endpoints = list(recon.seen.values())
        log(f"  {len(endpoints)} endpoints under test, {len(roles)} role(s)")

        options = cfg.check_options
        if not roles:
            options.authz = False
            options.unauth = False
        checker = Checker(client, store, run_id, scope, roles=roles, options=options, log=log)
        if cfg.dry_run:
            checker.plan(cfg.entry_urls, endpoints)
        else:
            # ---- checks ----
            findings = dedupe_findings(checker.run_all(cfg.entry_urls, endpoints))
            log(f"  {len(findings)} finding(s) from {checker.stats.requests} request(s)")
            for note in checker.stats.notes:
                if not note.startswith("finding:"):
                    log(f"    · {note}")

            # ---- reports + queue ----
            gate = ApprovalGate(store)
            _report_and_queue(findings, cfg, scope, store, gate, log)
    except BudgetExceeded as exc:
        log(f"  budget exhausted: {exc}")
        findings = dedupe_findings(findings)
    except Exception as exc:
        store.finish_run(run_id, {"error": f"{type(exc).__name__}: {exc}"})
        raise
    finally:
        if cfg.dry_run:
            log(f"  planned {len(client.planned)} request(s):")
            for method, url in client.planned:
                log(f"    {method:6} {url}")
        client.close()

    stats = store.stats()
    store.finish_run(run_id, {"findings": len(findings), "stats": stats,
                              "requests": client.sent})
    return {"run_id": run_id, "findings": findings, "roles": roles,
            "endpoints": len(endpoints), "requests": client.sent,
            "audit": store.audit_counts(run_id), "stats": stats}


def _id(role: Role):
    return role.user_id if role.user_id is not None else 1


def _report_and_queue(findings: list[Finding], cfg: HuntConfig, scope: Scope, store: Store,
                      gate: ApprovalGate, log) -> None:
    from bb.report import lint, novelty_note, polish, render_h1, write_report

    candidates = [f for f in findings
                  if f.status == "candidate" and sev_rank(f.severity) >= sev_rank("low")]
    if not candidates:
        log("  no reportable candidates (informational findings stay in the store)")
        return

    kb = None
    try:
        from bb.config import KB_PATH
        if KB_PATH.exists():
            from bb.kb import KnowledgeBase
            kb = KnowledgeBase()
    except Exception as exc:
        log(f"  [kb] unavailable for duplicate check: {exc}")

    llm = None
    if cfg.llm:
        try:
            from bb.llm import Ollama
            llm = Ollama()
            if llm.available():
                log(f"  [llm] {llm.chat_model} available — polishing up to 6 reports")
            else:
                llm = None
                log("  [llm] Ollama not reachable — using deterministic reports")
        except Exception as exc:
            log(f"  [llm] unavailable ({exc}) — deterministic reports")

    polished_used = 0
    for f in candidates:
        polished = None
        if llm and polished_used < 6 and sev_rank(f.severity) >= sev_rank("medium"):
            polished = polish(f, kb=kb, llm=llm, log=log)
            if polished:
                polished_used += 1
        novelty = novelty_note(f, kb)
        path, cbh_path = write_report(f, scope=scope, polished=polished, novelty=novelty)
        store.set_report_path(f.id, str(path))
        store.update_meta(f.id, report_path=str(path),
                          cbh_finding_path=str(cbh_path) if cbh_path else "",
                          program=cfg.program, novelty=novelty)
        f.meta.update(report_path=str(path), cbh_finding_path=str(cbh_path) if cbh_path else "",
                      program=cfg.program, novelty=novelty)
        issues = lint(render_h1(f, scope=scope, polished=polished))
        if issues:
            log(f"  [lint] {f.id}: " + "; ".join(issues))
        if cfg.queue:
            qid, new = gate.submit(f.id)
            store.update_meta(f.id, queue_id=qid)
            log(f"  [queued] {qid}  [{f.severity}] {f.title[:70]}  -> {path}")
        else:
            log(f"  [report] {f.id}  [{f.severity}] {f.title[:70]}  -> {path}")
