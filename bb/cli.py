"""`bb` command line. Thin handlers; real work lives in the modules."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from bb import __version__
from bb.artex import Artex, ArtexError
from bb.checks import CheckOptions
from bb.config import (CBH, CBH_HOME, DATA, KB_PATH, accounts_path, ensure_dirs, scope_path)
from bb.gate import ApprovalGate
from bb.h1 import H1Client, H1Error, submit_curl, submit_payload
from bb.http import BudgetExceeded, ScopedClient
from bb.llm import Ollama
from bb.models import sev_rank
from bb.pipeline import HuntConfig, hunt
from bb.recon import Recon
from bb.report import lint, novelty_note, polish, render_h1, write_report
from bb.scope import Scope, ScopeViolation
from bb.session import load_accounts
from bb.store import Store

SAMPLE_SCOPE = {
    "program": "example-program",
    "in_scope": ["app.example.com", "*.example.com"],
    "out_of_scope": ["staging.example.com"],
}
SAMPLE_ACCOUNTS = {
    "base_url": "https://app.example.com",
    "login": {"path": "/api/login",
              "body_keys": {"email": "email", "password": "password"},
              "token_field": "token"},
    "accounts": [
        {"label": "A", "email": "you+alice@example.com", "password_env": "BB_PASS_A"},
        {"label": "B", "email": "you+bob@example.com", "password_env": "BB_PASS_B"},
    ],
}


def _scope_or_die(program: str) -> Scope:
    path = scope_path(program)
    if not path.exists():
        raise SystemExit(f"no scope for {program!r}. import it first:\n"
                         f"  bb scope import --program {program} --from h1\n"
                         f"  bb scope import --program {program} --from file --file scope.json")
    return Scope.load(path)


def _print_finding(f, show_report: bool = True) -> None:
    print(f"[{f.severity.upper():8}] {f.id}  {f.bug_class:22} {f.status:13} {f.url}")
    print(f"           {f.title}")
    if show_report and f.meta.get("report_path"):
        print(f"           report: {f.meta['report_path']}")


# ============================================================
# commands
# ============================================================

def cmd_init(args) -> int:
    ensure_dirs()
    sp = DATA / "example.scope.json"
    ap = DATA / "example.accounts.json"
    if not sp.exists():
        sp.write_text(json.dumps(SAMPLE_SCOPE, indent=2), encoding="utf-8")
    if not ap.exists():
        ap.write_text(json.dumps(SAMPLE_ACCOUNTS, indent=2), encoding="utf-8")
    print(f"data dir: {DATA}")
    print(f"wrote {sp} and {ap}")
    print("\nquickstart:")
    print("  1. bb integrations                      # check ollama / cbh / artex / lab")
    print("  2. bb demo                              # end-to-end against local Juice Shop")
    print("  3. bb scope import --program <handle> --from h1   # real program (needs H1_TOKEN)")
    print("  4. bb hunt --program <handle> --entry https://app.<handle>.com "
          "--accounts data/example.accounts.json")
    print("  5. bb queue && bb decide <id> --approve")
    return 0


def cmd_integrations(args) -> int:
    from bb.integrations import format_status, probe_all
    print(format_status(probe_all()))
    return 0


def cmd_scope_import(args) -> int:
    ensure_dirs()
    if args.source == "h1":
        scope = H1Client().scope(args.program)
    elif args.source == "file":
        if not args.file:
            raise SystemExit("--from file needs --file <scope.json>")
        data = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
        scope = Scope.from_json(data)
        scope.program = args.program
        scope.source = f"file:{args.file}"
    else:
        if not args.json:
            raise SystemExit("--from json needs --json '<scope json>'")
        scope = Scope.from_json(json.loads(args.json))
        scope.program = args.program
        scope.source = "inline-json"
    path = scope.save(scope_path(args.program))
    print(scope.describe())
    print(f"\nsaved {path}")
    if not scope.in_rules:
        print("WARNING: zero in-scope rules — every request will be refused.")
    return 0


def cmd_scope_show(args) -> int:
    print(_scope_or_die(args.program).describe())
    return 0


def cmd_scope_check(args) -> int:
    scope = _scope_or_die(args.program)
    bad = 0
    for target in args.urls:
        d = scope.check(target)
        print(f"{'ALLOW' if d.allowed else 'DENY '} {target}  — {d.reason}")
        bad += 0 if d.allowed else 1
    return 0 if not bad else 1


def _client_for(scope: Scope, entry: str, args) -> tuple[ScopedClient, Store, str]:
    store = Store()
    run_id = store.start_run(scope.program, entry, scope.fingerprint, {"cli": "recon"})
    client = ScopedClient(scope, base_url=entry, proxy=getattr(args, "proxy", None),
                          rate=getattr(args, "rate", 3.0), store=store, run_id=run_id,
                          tool="recon")
    return client, store, run_id


def cmd_recon(args) -> int:
    scope = _scope_or_die(args.program)
    for url in args.entry:
        d = scope.check(url)
        if not d.allowed:
            raise SystemExit(f"REFUSED {url}: {d.reason}")
    client, store, run_id = _client_for(scope, args.entry[0], args)
    log = print
    try:
        recon = Recon(client, store, run_id, scope, log=log)
        for url in args.entry:
            recon.passive(url)
        if args.cbh:
            recon.cbh_recon(scope.check(args.entry[0]).host)
    except BudgetExceeded as exc:
        print(f"budget exhausted: {exc}")
    finally:
        client.close()
    rows = store.endpoints(run_id)
    print(f"\n{len(rows)} endpoints, {len(store.assets(run_id))} assets "
          f"({client.sent} requests, run {run_id})")
    for ep in rows[:200]:
        print(f"  {ep['method']:6} {ep['url']}   [{ep['source']}]")
    return 0


def _hunt_config(args) -> tuple[HuntConfig, Scope, dict | None]:
    scope = _scope_or_die(args.program)
    accounts = load_accounts(args.accounts) if args.accounts else None
    names = {n.strip() for n in (args.checks or "").split(",") if n.strip()}
    opts = CheckOptions()
    if names:
        for n in opts.enabled - names:
            setattr(opts, n, False)
    cfg = HuntConfig(
        program=args.program, scope=scope, entry_urls=args.entry,
        accounts=accounts, endpoints=args.endpoint or [], templates=args.template or [],
        budget_min=args.budget, rate=args.rate, max_requests=args.max_requests,
        proxy=args.proxy, dry_run=args.dry_run, cbh=args.cbh, llm=args.llm,
        queue=not args.no_queue, check_options=opts,
    )
    return cfg, scope, accounts


def cmd_hunt(args) -> int:
    cfg, scope, _ = _hunt_config(args)
    store = Store()
    result = hunt(cfg, store=store)
    print("\n=== summary ===")
    print(f"run: {result['run_id']}  requests: {result['requests']}  "
          f"endpoints: {result['endpoints']}  audit: {result['audit']}")
    shown = [f for f in result["findings"] if f.status != "informational"]
    if not shown:
        print("no candidate findings. raise --budget, add --endpoint, or check the recon output.")
        return 0
    for f in sorted(shown, key=lambda x: -sev_rank(x.severity)):
        _print_finding(f)
    print("\nnext: bb queue   |   bb report --finding <id> --llm   |   bb decide <queue-id> --approve")
    return 0


def cmd_findings(args) -> int:
    store = Store()
    rows = store.findings(status=None if args.all else (args.status or "candidate"))
    if args.min_severity:
        rows = [f for f in rows if sev_rank(f.severity) >= sev_rank(args.min_severity)]
    if not rows:
        print("no findings yet. run: bb hunt ...")
        return 0
    for f in rows:
        _print_finding(f)
    return 0


def cmd_report(args) -> int:
    store = Store()
    finding = store.get_finding(args.finding)
    if not finding:
        raise SystemExit(f"no finding matching {args.finding!r}")
    scope = None
    run_id = store.finding_run(finding.id)
    run = store.run(run_id) if run_id else None
    program = (run or {}).get("program") or finding.meta.get("program")
    if program:
        try:
            scope = _scope_or_die(program)
        except SystemExit:
            scope = None
    polished = None
    kb = None
    try:
        from bb.config import KB_PATH
        if KB_PATH.exists():
            from bb.kb import KnowledgeBase
            kb = KnowledgeBase()
    except Exception:
        kb = None
    if args.llm:
        try:
            polished = polish(finding, kb=kb, llm=Ollama())
            print("[llm] polished" if polished else "[llm] skipped (model unavailable or output rejected)")
        except Exception as exc:
            print(f"[llm] {exc}")
    novelty = novelty_note(finding, kb)
    path, cbh_path = write_report(finding, scope=scope, polished=polished, novelty=novelty)
    store.set_report_path(finding.id, str(path))
    store.update_meta(finding.id, report_path=str(path),
                      cbh_finding_path=str(cbh_path) if cbh_path else "", novelty=novelty)
    issues = lint(render_h1(finding, scope=scope, polished=polished, novelty=novelty))
    print(f"report: {path}")
    if issues:
        print("lint issues: " + "; ".join(issues))
    else:
        print("lint: clean")
    if args.cbh and cbh_path and CBH.exists():
        print("\n--- cbh triage (7-Question Gate) ---")
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        try:
            proc = subprocess.run([sys.executable, str(CBH), "triage", str(cbh_path)],
                                  cwd=str(CBH_HOME), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", env=env, timeout=180)
            print((proc.stdout or proc.stderr or "").strip()[-4000:])
        except Exception as exc:
            print(f"cbh triage failed: {exc}")
    if args.print:
        print("\n" + Path(path).read_text(encoding="utf-8"))
    return 0


def cmd_queue(args) -> int:
    store = Store()
    gate = ApprovalGate(store)
    pending = store.queue(None if args.all else "pending")
    if not pending:
        print("queue is empty.")
        return 0
    for item in pending:
        print(f"{item['id']}  [{item['state']:8}] [{item['severity']:8}] "
              f"{item['finding_id']}  {item['title'][:80]}")
    print(f"\n{gate.summary()}")
    if args.push:
        from bb.telegram import gate_from_env
        gate_from_env(gate).push_pending()
        print("pushed to Telegram")
    return 0


def cmd_decide(args) -> int:
    store = Store()
    gate = ApprovalGate(store)
    item = gate.decide(args.queue_id, approved=args.approve)
    print(f"{item['id']} -> {item['state']}")
    if args.approve:
        print(f"report exported to {DATA / 'decided' / (item['finding_id'] + '.md')}")
    print("submission to HackerOne remains manual: bb submit --finding " + item["finding_id"])
    return 0


def cmd_hypothesize(args) -> int:
    from bb.kb import KnowledgeBase
    kb = KnowledgeBase()
    where = None if args.fuzzy else {"team": args.program}
    hits = kb.query(f"{args.program} IDOR authorization access control paid report", k=args.k, where=where)
    if not hits and not args.fuzzy:
        print(f"(no KB entries for team={args.program}; retry with --fuzzy)")
        hits = kb.query(f"{args.program} IDOR authorization", k=args.k)
    if not hits:
        print("knowledge base empty — run: bb kb ingest")
        return 1
    print(f"retrieved {len(hits)} precedent(s):")
    for h in hits:
        print(f"  {h['score']:.3f}  {h['title'][:90]}")
    block = "\n---\n".join(f"[{h['title']}] {h['text'][:500]}" for h in hits)
    llm = Ollama()
    if not llm.available():
        print("\n(Ollama unavailable; showing raw precedent only)")
        return 0
    print(f"\nasking {llm.chat_model} for hypotheses (temperature 0.3)…")
    out = llm.chat([
        {"role": "system", "content":
            "You are a bug-bounty hypothesis generator. Use ONLY the provided context. "
            "Output exactly 5 lines of the form ENDPOINT|REPLAY|WHY. ENDPOINT must be a real "
            "path that appears in the context (start it with /). REPLAY must be a concrete "
            "two-account test in under 25 words. WHY must name the precedent title it comes "
            "from. Never invent parameters, tokens, or program names. No preamble, no "
            "numbering, no duplicate ENDPOINT values."},
        {"role": "user", "content": f"PROGRAM: {args.program}\nCONTEXT:\n{block}"},
    ], temperature=0.3)
    rows = _valid_hypotheses(out)
    if not rows:
        print("\n[!] model output failed format validation — raw output below.\n")
        print(out.strip())
        print("\nTreat every line as unverified. Re-run with a larger model: "
              "BB_MODEL=qwen2.5-coder:7b bb hypothesize ...")
        return 0
    print(f"\n{len(rows)} grounded hypothesis line(s):")
    for endpoint, replay, why in rows:
        print(f"\n  ENDPOINT  {endpoint}")
        print(f"  REPLAY    {replay}")
        print(f"  WHY       {why}")
    print("\nEach line is a lead, not a finding: verify with `bb hunt --endpoint <path> --template ...`.")
    return 0


def _valid_hypotheses(out: str) -> list[tuple[str, str, str]]:
    """Accept only well-formed, unique, path-shaped hypotheses."""
    rows, seen = [], set()
    for raw in (out or "").splitlines():
        line = raw.strip().lstrip("-•* ").strip()
        if line.count("|") < 2:
            continue
        parts = [p.strip() for p in line.split("|")]
        endpoint, replay, why = parts[0], parts[1], "|".join(parts[2:]).strip()
        if not endpoint.startswith("/") or not replay or not why:
            continue
        endpoint = endpoint.split("?")[0].rstrip("/") or "/"
        if endpoint in seen:
            continue
        seen.add(endpoint)
        rows.append((endpoint, replay, why))
    return rows[:5]


def cmd_kb(args) -> int:
    from bb.kb import KnowledgeBase
    kb = KnowledgeBase()
    if args.action == "stats":
        st = kb.stats()
        print(f"{st['chunks']} chunks, {st['documents']} documents, dim {st['dim']}")
        print(f"path: {st['path']}")
        return 0
    if args.action == "query":
        if not args.text:
            raise SystemExit("kb query needs text")
        hits = kb.query(args.text, k=args.k, where={"team": args.team} if args.team else None)
        if not hits:
            print("no hits")
            return 0
        for h in hits:
            print(f"{h['score']:.3f}  {h['title']}")
            print("  " + h["text"][:400].replace("\n", " "))
        return 0
    if args.action == "ingest":
        from bb.config import ROOT
        paths = list((ROOT / "kb_docs").glob("*.md"))
        if CBH_HOME.exists():
            skills = ["hunt-idor", "hunt-auth-bypass", "triage-validation", "report-writing",
                      "bb-methodology", "security-arsenal", "hunt-graphql", "hunt-ato",
                      "hunt-session", "hunt-shadow-api", "evidence-hygiene",
                      "recon-scope-triage"]
            paths += [CBH_HOME / "skills" / s / "SKILL.md" for s in skills]
        added = kb.ingest_paths(paths, source="doc")
        print(f"added {added} new chunks; total {kb.stats()['chunks']}")
        return 0
    return 1


def cmd_audit(args) -> int:
    from bb import audit

    if args.action == "skill":
        info = audit.skill_info()
        if not info["exists"]:
            print(f"skill not found at {info['dir']}")
            print("re-vendor it from https://github.com/cloudflare/security-audit-skill")
            return 1
        print(f"skill dir: {info['dir']}")
        print(f"commit:    {info['commit'] or 'unknown'}")
        print(f"docs:      {len(info['docs'])} markdown files")
        print(f"validators:{' ok' if all(info['validators'].values()) else ' MISSING'}"
              f"   schema: {'ok' if info['schema'] else 'MISSING'}"
              f"   node: {'ok' if info['node'] else 'not installed'}")
        print("\nphases: reconnaissance -> coverage-led hunting -> candidate validation")
        print("        -> structured output -> independent verification -> reporting")
        print("\nuse it with a coding agent:")
        print("  npx skills add https://github.com/cloudflare/security-audit-skill "
              "--skill security-audit")
        print(f"  or point the agent at {info['dir'] / 'SKILL.md'}")
        print("  then ask: security audit <target> output to <dir>")
        print("\nvalidate the artifacts it wrote:")
        print("  bb audit validate --findings <dir>/findings.json "
              "--ledger <dir>/coverage-ledger.json")
        return 0

    if args.action == "init":
        result = audit.init_workspace(args.repo, out=args.out, profile=args.profile,
                                      scope=args.scope, budget=args.budget,
                                      allow_inside=args.allow_inside)
        out: Path = result["out"]
        meta = result["metadata"]
        print(f"audit workspace: {out}")
        print(f"profile: {meta['profile']}   source: {meta['source_ref']}")
        print("files: " + ", ".join(result["files"]))
        print("\nnext:")
        print("  1. bb audit skill                         # how to load the skill")
        print(f"  2. ask your agent: security audit {Path(args.repo).resolve()} "
              f"output to {out}")
        print(f"  3. bb audit validate --findings {out / 'findings.json'} "
              f"--ledger {out / 'coverage-ledger.json'}")
        return 0

    if args.action == "validate":
        if not args.findings and not args.ledger:
            raise SystemExit("give --findings and/or --ledger")
        failed = 0
        for kind, path in (("findings", args.findings), ("ledger", args.ledger)):
            if not path:
                continue
            try:
                code, output = audit.validate(kind, path)
            except Exception as exc:
                print(f"{kind}: ERROR — {exc}")
                failed += 1
                continue
            print(f"{kind}: {'PASS' if code == 0 else 'FAIL'} — {path}")
            if output:
                print(output)
            if code != 0:
                failed += 1
        return 0 if failed == 0 else 1

    if args.action == "ingest":
        from bb.kb import KnowledgeBase
        added = audit.ingest_skill(KnowledgeBase())
        print(f"added {added} chunks from the vendored security-audit skill")
        return 0

    return 1


def cmd_demo(args) -> int:
    from bb.demo import run
    run(llm=args.llm, budget=args.budget)
    return 0


def cmd_import(args) -> int:
    from bb import har
    scope = _scope_or_die(args.program)
    ensure_dirs()
    store = Store()
    run_id = store.start_run(scope.program, "", scope.fingerprint,
                             {"source": "har", "file": str(Path(args.file).resolve())})
    try:
        stats = har.import_har(args.file, scope, store, run_id)
    finally:
        store.finish_run(run_id, {"source": "har"})
    print(f"\nimported into run {run_id}: {stats['endpoints']} endpoints "
          f"({stats['id_endpoints']} id-bearing), {stats['exchanges']} exchanges")
    id_rows = [e for e in stats.get("endpoint_list", []) if e["id_bearing"]][:20]
    if id_rows:
        print("\nobject-shaped endpoints to test with a scenario:")
        for row in id_rows:
            print(f"  {row['method']:6} {row['url']}")
    print("\nnext: write a scenario against one of these, or run "
          "`bb hunt` to test the inventory statelessly.")
    return 0


def cmd_scenario(args) -> int:
    from bb import scenario

    if args.action == "propose":
        from bb import propose
        scope = _scope_or_die(args.program)
        result = propose.propose(args.har, scope, args.program, out_dir=args.out,
                                 limit=args.limit)
        print(f"\n{len(result['written'])} draft scenario(s) in {result['out']}")
        for item in result["written"]:
            print(f"  {item['kind']:10} {item['file']:40} {item['method']} {item['template']}")
        print(f"\nreview first: {result['out'] / 'REVIEW.md'}")
        print("nothing was executed, queued, or submitted.")
        return 0

    scope = _scope_or_die(args.program)
    accounts = load_accounts(args.accounts)
    data = scenario.load_scenario(args.file)
    store = Store()
    result = scenario.run_scenario(
        data, scope=scope, accounts=accounts, program=args.program, store=store,
        allow_write=args.allow_write, dry_run=args.dry_run, proxy=args.proxy,
        llm=args.llm, queue=not args.no_queue)
    print(f"\nverdict: {result['verdict'].upper()}   run: {result['run_id']}   "
          f"requests: {result.get('requests', 0)}")
    finding = result.get("finding")
    if finding:
        print(f"[{finding.severity.upper()}] {finding.id}  {finding.title}")
        meta = store.get_finding(finding.id).meta if store.get_finding(finding.id) else {}
        if meta.get("report_path"):
            print(f"report: {meta['report_path']}")
        if meta.get("queue_id"):
            print(f"queue:  {meta['queue_id']}   (bb decide {meta['queue_id']} --approve)")
    elif result["verdict"] == "enforced":
        print("the server enforced the boundary; this is coverage, not a finding.")
    return 0 if result["verdict"] not in ("inconclusive",) else 1


def cmd_outcome(args) -> int:
    store = Store()
    if args.list:
        rows = store.outcome_rows(program=args.program)
        if not rows:
            print("no findings yet")
            return 0
        print(f"{'finding':14} {'status':12} {'bounty':>8} {'min':>5}  {'class':20} program")
        for row in rows:
            bounty = "" if row.get("bounty") is None else f"{row['bounty']:,.0f}"
            print(f"{row['id']:14} {(row.get('status') or 'unknown'):12} {bounty:>8} "
                  f"{(row.get('minutes') or ''):>5}  {(row.get('bug_class') or '')[:20]:20} "
                  f"{row.get('program') or ''}")
        return 0
    if not args.finding_id:
        raise SystemExit("give a finding id or --list")
    if args.status is None and all(v is None for v in
                                  (args.bounty, args.currency, args.minutes,
                                   args.submitted, args.notes)):
        finding = store.get_finding(args.finding_id)
        if not finding:
            raise SystemExit(f"no finding matching {args.finding_id!r}")
        outcome = store.get_outcome(finding.id)
        print(f"{finding.id}  {finding.title}")
        print(json.dumps(outcome, indent=2))
        return 0
    outcome = store.set_outcome(
        args.finding_id, status=args.status, bounty=args.bounty, currency=args.currency,
        minutes=args.minutes, submitted_at=args.submitted, notes=args.notes)
    print(f"{outcome['finding_id']}: status={outcome['status']} "
          f"bounty={outcome.get('bounty')} currency={outcome.get('currency')} "
          f"minutes={outcome.get('minutes')} submitted={outcome.get('submitted_at')}")
    print("see the scoreboard: bb metrics")
    return 0


def cmd_metrics(args) -> int:
    from bb import metrics
    data = metrics.collect(Store(), program=args.program)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(metrics.format_metrics(data))
    return 0


def cmd_artex(args) -> int:
    artex = Artex()
    if args.action == "status":
        print(json.dumps(artex.health(), indent=2))
        return 0
    if args.action == "push":
        store = Store()
        run_id = args.run
        if not run_id:
            row = store.conn.execute(
                "SELECT run_id FROM exchanges GROUP BY run_id ORDER BY MAX(id) DESC LIMIT 1"
            ).fetchone() or store.conn.execute(
                "SELECT id AS run_id FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
            if not row:
                raise SystemExit("no runs yet")
            run_id = row["run_id"]
        exs = store.exchanges(run_id)
        print(f"pushing {len(exs)} exchanges from run {run_id} to ARTEX")
        print(json.dumps(artex.ingest_traffic(exs), indent=2))
        return 0
    if args.action == "task":
        if not args.goal:
            raise SystemExit("artex task needs --goal")
        print(json.dumps(artex.create_task(args.description or "bountybot task", args.goal),
                         indent=2))
        return 0
    return 1


def cmd_submit(args) -> int:
    store = Store()
    finding = store.get_finding(args.finding)
    if not finding:
        raise SystemExit(f"no finding matching {args.finding!r}")
    report_path = finding.meta.get("report_path")
    report_md = Path(report_path).read_text(encoding="utf-8") if report_path and \
        Path(report_path).exists() else render_h1(finding)
    payload = submit_payload(finding, report_md, args.team, weakness_id=args.weakness or 0,
                             structured_scope_id=args.scope_id or 0)
    out = Path(report_path).parent / "report.json" if report_path else DATA / "report.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"payload written: {out}")
    print("\n" + submit_curl(payload))
    print("\nNothing was sent. Copy the report into HackerOne yourself after review.")
    return 0


def cmd_telegram(args) -> int:
    from bb.telegram import gate_from_env
    gate = gate_from_env(ApprovalGate(Store()))
    print("telegram gate polling (allowed chats enforced). Ctrl+C to stop.")
    try:
        if args.push_only:
            print(f"pushed {gate.push_pending()} pending card(s)")
            return 0
        gate.serve()
    except KeyboardInterrupt:
        return 0
    return 0


# ============================================================
# parser
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bb", description=f"bountybot {__version__} — "
                               "scope-gated bug-bounty pipeline (nothing auto-submits)")
    p.add_argument("--version", action="version", version=f"bountybot {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create data dirs + example config").set_defaults(func=cmd_init)
    sub.add_parser("integrations", help="health-check ollama/cbh/artex/pentagi/lab").set_defaults(func=cmd_integrations)

    sp = sub.add_parser("scope", help="import / show / check scope")
    ssub = sp.add_subparsers(dest="action", required=True)
    imp = ssub.add_parser("import", help="import program scope")
    imp.add_argument("--program", required=True)
    imp.add_argument("--from", dest="source", choices=["h1", "file", "json"], default="h1")
    imp.add_argument("--file")
    imp.add_argument("--json")
    imp.set_defaults(func=cmd_scope_import)
    show = ssub.add_parser("show")
    show.add_argument("--program", required=True)
    show.set_defaults(func=cmd_scope_show)
    chk = ssub.add_parser("check")
    chk.add_argument("--program", required=True)
    chk.add_argument("urls", nargs="+")
    chk.set_defaults(func=cmd_scope_check)

    rc = sub.add_parser("recon", help="passive recon (+ optional cbh)")
    rc.add_argument("--program", required=True)
    rc.add_argument("--entry", action="append", required=True)
    rc.add_argument("--cbh", action="store_true", help="also run cbh recon (needs wildcard scope)")
    rc.add_argument("--rate", type=float, default=3.0)
    rc.add_argument("--proxy")
    rc.set_defaults(func=cmd_recon)

    h = sub.add_parser("hunt", help="full loop: recon -> checks -> report -> queue")
    h.add_argument("--program", required=True)
    h.add_argument("--entry", action="append", required=True)
    h.add_argument("--accounts", help="two-role accounts JSON")
    h.add_argument("--endpoint", action="append", help="explicit path/URL to test (repeatable)")
    h.add_argument("--template", action="append",
                   help="endpoint template using {a_id}/{b_id}, e.g. /api/Users/{a_id}")
    h.add_argument("--budget", type=float, default=20.0, help="minutes")
    h.add_argument("--rate", type=float, default=3.0)
    h.add_argument("--max-requests", type=int, default=400)
    h.add_argument("--proxy")
    h.add_argument("--cbh", action="store_true")
    h.add_argument("--llm", action="store_true", help="polish reports with local Ollama")
    h.add_argument("--no-queue", action="store_true", help="write reports without queueing")
    h.add_argument("--dry-run", action="store_true", help="plan requests; send nothing")
    h.add_argument("--checks", help="comma list: authz,unauth,cors,exposed,graphql,open_redirect,headers")
    h.set_defaults(func=cmd_hunt)

    f = sub.add_parser("findings", help="list stored findings")
    f.add_argument("--status")
    f.add_argument("--all", action="store_true")
    f.add_argument("--min-severity")
    f.set_defaults(func=cmd_findings)

    r = sub.add_parser("report", help="render the H1 report for a finding")
    r.add_argument("--finding", required=True)
    r.add_argument("--llm", action="store_true")
    r.add_argument("--cbh", action="store_true", help="run cbh triage on the finding")
    r.add_argument("--print", action="store_true")
    r.set_defaults(func=cmd_report)

    q = sub.add_parser("queue", help="show the human approval queue")
    q.add_argument("--all", action="store_true")
    q.add_argument("--push", action="store_true", help="push cards to Telegram")
    q.set_defaults(func=cmd_queue)

    d = sub.add_parser("decide", help="approve or reject a queued finding")
    d.add_argument("queue_id")
    g = d.add_mutually_exclusive_group(required=True)
    g.add_argument("--approve", action="store_true")
    g.add_argument("--reject", action="store_true")
    d.set_defaults(func=cmd_decide)

    hy = sub.add_parser("hypothesize", help="KB + Ollama hypotheses for a program")
    hy.add_argument("--program", required=True)
    hy.add_argument("--k", type=int, default=6)
    hy.add_argument("--fuzzy", action="store_true")
    hy.set_defaults(func=cmd_hypothesize)

    kb = sub.add_parser("kb", help="knowledge base")
    ksub = kb.add_subparsers(dest="action", required=True)
    ksub.add_parser("stats").set_defaults(func=cmd_kb)
    kq = ksub.add_parser("query"); kq.add_argument("text"); kq.add_argument("--k", type=int, default=5)
    kq.add_argument("--team"); kq.set_defaults(func=cmd_kb)
    ksub.add_parser("ingest").set_defaults(func=cmd_kb)

    dm = sub.add_parser("demo", help="end-to-end run against local Juice Shop")
    dm.add_argument("--llm", action="store_true")
    dm.add_argument("--budget", type=float, default=5.0)
    dm.set_defaults(func=cmd_demo)

    a = sub.add_parser("artex", help="ARTEX dashboard bridge")
    asub = a.add_subparsers(dest="action", required=True)
    asub.add_parser("status").set_defaults(func=cmd_artex)
    ap_ = asub.add_parser("push"); ap_.add_argument("--run"); ap_.set_defaults(func=cmd_artex)
    at = asub.add_parser("task"); at.add_argument("--goal"); at.add_argument("--description")
    at.set_defaults(func=cmd_artex)

    s = sub.add_parser("submit", help="print (never send) the HackerOne submission payload")
    s.add_argument("--finding", required=True)
    s.add_argument("--team", required=True)
    s.add_argument("--weakness", type=int)
    s.add_argument("--scope-id", type=int)
    s.set_defaults(func=cmd_submit)

    t = sub.add_parser("telegram", help="review queue from Telegram")
    t.add_argument("--push-only", action="store_true")
    t.set_defaults(func=cmd_telegram)

    au = sub.add_parser("audit", help="source-code audit skill (Cloudflare, vendored)")
    asub = au.add_subparsers(dest="action", required=True)
    ai = asub.add_parser("init", help="scaffold the skill's run directory")
    ai.add_argument("--repo", required=True, help="local source tree to audit")
    ai.add_argument("--out", help="output directory (default: ~/security-audit-skill/<repo>/run-N)")
    ai.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    ai.add_argument("--scope", action="append", help="scope path inside the repo (repeatable)")
    ai.add_argument("--budget", type=int, help="max agent invocations")
    ai.add_argument("--allow-inside", action="store_true",
                    help="permit an output directory inside the target (not recommended)")
    ai.set_defaults(func=cmd_audit)
    av = asub.add_parser("validate", help="run the vendored schema validators")
    av.add_argument("--findings")
    av.add_argument("--ledger")
    av.set_defaults(func=cmd_audit)
    asub.add_parser("skill", help="show the vendored skill and how to load it").set_defaults(
        func=cmd_audit)
    asub.add_parser("ingest", help="add the methodology to the knowledge base").set_defaults(
        func=cmd_audit)

    imp = sub.add_parser("import", help="import authenticated traffic (HAR export)")
    isub = imp.add_subparsers(dest="source", required=True)
    ihar = isub.add_parser("har", help="import a browser HAR export")
    ihar.add_argument("file")
    ihar.add_argument("--program", required=True)
    ihar.set_defaults(func=cmd_import)

    sc = sub.add_parser("scenario", help="stateful authorization scenarios")
    ssub = sc.add_subparsers(dest="action", required=True)
    sr = ssub.add_parser("run", help="run a scenario file (JSON; YAML if PyYAML is installed)")
    sr.add_argument("--file", required=True)
    sr.add_argument("--program", required=True)
    sr.add_argument("--accounts", required=True)
    sr.add_argument("--allow-write", action="store_true",
                    help="permit POST/PUT/PATCH/DELETE (disposable resources only)")
    sr.add_argument("--dry-run", action="store_true")
    sr.add_argument("--proxy")
    sr.add_argument("--llm", action="store_true")
    sr.add_argument("--no-queue", action="store_true")
    sr.set_defaults(func=cmd_scenario)
    sp = ssub.add_parser("propose", help="draft scenarios from an authenticated HAR")
    sp.add_argument("--har", required=True)
    sp.add_argument("--program", required=True)
    sp.add_argument("--out", help="output directory (default: data/proposed/<program>-<stamp>)")
    sp.add_argument("--limit", type=int, default=25)
    sp.set_defaults(func=cmd_scenario)

    oc = sub.add_parser("outcome", help="record the program's decision on a finding")
    oc.add_argument("finding_id", nargs="?")
    oc.add_argument("--status", choices=["accepted", "duplicate", "informative",
                                         "rejected", "unknown"])
    oc.add_argument("--bounty", type=float)
    oc.add_argument("--currency")
    oc.add_argument("--minutes", type=float)
    oc.add_argument("--submitted")
    oc.add_argument("--notes")
    oc.add_argument("--program")
    oc.add_argument("--list", action="store_true")
    oc.set_defaults(func=cmd_outcome)

    mt = sub.add_parser("metrics", help="acceptance, duplicates, bounty per hour")
    mt.add_argument("--program")
    mt.add_argument("--json", action="store_true")
    mt.set_defaults(func=cmd_metrics)
    return p


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252; cbh and our own output use unicode markers.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ScopeViolation, H1Error, ArtexError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyError as exc:
        print(f"error: not found: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        if os.environ.get("BB_DEBUG"):
            raise
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
