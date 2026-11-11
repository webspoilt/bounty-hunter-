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
from bb.h1 import (
    BriefGenerator,
    H1Client,
    H1Error,
    HackerOneReportGenerator,
    PolicyParser,
    ProgramDiscoveryRanker,
    ensure_h1_dirs,
    sanitize_handle,
    submit_curl,
    submit_payload,
)
from bb.http import BudgetExceeded, ScopedClient
from bb.killswitch import AbortRequested, active as kill_active
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


def _require_not_stopped() -> None:
    if kill_active():
        from bb import killswitch
        raise SystemExit("kill switch is armed — every request will be refused.\n"
                         f"reason: {killswitch.reason() or '(none)'}\n"
                         "clear it with: bb resume")


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
    _require_not_stopped()
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
    _require_not_stopped()
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


def cmd_stop(args) -> int:
    from bb import killswitch
    path = killswitch.activate(args.reason or "")
    print(f"STOPPED. kill switch armed at {path}")
    if killswitch.reason():
        print(f"reason: {killswitch.reason()}")
    print("every bb process will refuse to send another request. clear with: bb resume")
    return 0


def cmd_resume(args) -> int:
    from bb import killswitch
    if killswitch.clear():
        print("kill switch cleared — requests allowed again")
    else:
        print("kill switch was not armed")
    return 0


def cmd_verify(args) -> int:
    """Independent verification: audit evidence offline, optionally replay online."""
    _require_not_stopped()
    from bb import verify as verifier
    scope = _scope_or_die(args.program)
    store = Store()
    client = None
    accounts = load_accounts(args.accounts) if args.accounts else None
    if accounts and not args.dry_run:
        base_url = accounts.get("base_url")
        if not base_url:
            raise SystemExit("--accounts JSON needs a base_url for online verification")
        client = ScopedClient(scope, base_url=base_url, proxy=getattr(args, "proxy", None),
                              store=store, run_id=store.start_run(scope.program, base_url,
                              scope.fingerprint, {"cli": "verify"}), tool="verify")
    try:
        summary = verifier.verify_candidates(
            store, scope, args.program, accounts=accounts, client=client,
            finding_id=args.finding)
    finally:
        if client is not None:
            client.close()
    print(f"\nverified {summary['verified']} candidate(s): "
          f"{summary['confirmed']} confirmed, {summary['rejected']} rejected, "
          f"{summary['kept']} kept as candidates")
    print("rejected findings keep their evidence and notes in meta['verify']. "
          "Nothing was queued, reported, or submitted.")
    return 0


def cmd_demo(args) -> int:
    from bb.demo import run
    run(llm=args.llm, budget=args.budget)
    return 0


def cmd_import(args) -> int:
    ensure_dirs()
    scope = _scope_or_die(args.program)
    store = Store()
    if args.source == "har":
        from bb import har
        kind, loader = "har", har.import_har
    else:
        from bb import burp
        kind, loader = "burp", burp.import_burp
    run_id = store.start_run(scope.program, "", scope.fingerprint,
                             {"source": kind, "file": str(Path(args.file).resolve())})
    try:
        stats = loader(args.file, scope, store, run_id)
    finally:
        store.finish_run(run_id, {"source": kind})
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
    _require_not_stopped()
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


def cmd_feedback(args) -> int:
    from bb import feedback
    priors = feedback.class_priors(Store(), program=args.program)
    if args.json:
        print(json.dumps(priors, indent=2))
        return 0
    if args.program:
        print(f"class priors for program {args.program!r} "
              f"(weight = (accepted+1)/(decided+2); advisory only):\n")
    else:
        print("class priors across all programs "
              "(weight = (accepted+1)/(decided+2); advisory only):\n")
    print(feedback.format_priors(priors))
    print("\nhow it acts: high-weight classes are reported/polished first; "
          "classes scoring < 0.34 with enough history emit a warning, never a silent skip.")
    return 0


def cmd_duplicate(args) -> int:
    from bb import duplicate

    if args.action == "pull":
        duplicate.pull(args.dest or duplicate.H1_DATA, log=print)
        if args.ingest:
            duplicate.ingest_parquet(args.dest or duplicate.H1_DATA, log=print)
        return 0

    if args.action == "ingest":
        result = duplicate.ingest_parquet(args.dir or duplicate.H1_DATA, log=print)
        print(f"indexed {result['rows']} disclosed reports into {result['db']}")
        return 0

    if args.action == "stats":
        idx = duplicate.DupIndex()
        stats = idx.stats()
        idx.close()
        if not stats.get("rows"):
            print("duplicate index is empty — run: bb duplicate pull --ingest")
            return 1
        print(f"reports: {stats['rows']}   fingerprint: {stats.get('fingerprint', '?')}")
        print(f"dataset: {stats.get('dataset', '?')}   ingested: {stats.get('ingested_at', '?')}")
        print(f"db: {duplicate.H1_INDEX}")
        return 0

    if args.action == "search":
        idx = duplicate.DupIndex()
        try:
            rows = idx.search(args.query, team=args.team, asset=args.asset,
                              weakness=args.weakness, k=args.k)
        finally:
            idx.close()
        if not rows:
            print("no disclosed matches")
            return 0
        for row in rows:
            print(f"{row['score']:7.2f}  {row['team']:20} {row['weakness'][:28]:28} "
                  f"{row['asset'][:35]:35} {row['title'][:70]}")
            print(f"         {row['url']}")
        return 0

    if args.action == "check":
        result = duplicate.check_finding(args.finding, Store(), k=args.k, log=print)
        print(f"\nverdict: {result['verdict']}")
        print(f"evidence: {result['evidence_path']}")
        for row in result["matches"][:5]:
            print(f"  {row['match_kind']:32} {row['url']}  {row['title'][:70]}")
        return 0

    return 1


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


def cmd_h1(args) -> int:
    """HackerOne acquisition, ranking, guideline reading, and report preparation."""
    from dataclasses import asdict
    ensure_h1_dirs()
    action = args.action

    if action == "programs":
        print("[*] Fetching accessible HackerOne programs via API...")
        try:
            client = H1Client()
            progs = client.programs(page_size=args.limit or 50)
        except Exception as exc:
            print(f"[!] HackerOne API error: {exc}")
            return 1

        if not progs:
            print("[!] No programs returned. Check membership or API token permissions.")
            return 0

        ranked = ProgramDiscoveryRanker.rank_programs(progs)
        print(f"\nDiscovered {len(ranked)} program(s) ranked by research opportunity:")
        print("-" * 80)
        for r in ranked[:args.limit or 25]:
            print(r.summary())
        print("-" * 80)
        print("Run `bb h1 brief --program <handle>` to inspect full guidelines and asset inventory.")
        return 0

    if action == "brief":
        raw_handle = args.program
        handle = sanitize_handle(raw_handle)
        print(f"[*] Fetching complete guidelines and scope for '{handle}'...")
        try:
            client = H1Client()
            prog = client.program(handle)
            scopes = client.structured_scopes(handle)
            exclusions = client.scope_exclusions(handle)
        except Exception as exc:
            print(f"[!] Failed to fetch program details for '{handle}': {exc}")
            return 1

        policy_text = (prog.get("data", {}).get("attributes") or {}).get("policy") or ""
        policy_rec = PolicyParser.parse_policy(handle, policy_text)
        brief = BriefGenerator.generate_brief(prog, policy_rec, scopes, exclusions)

        # Check existing approval status
        from bb.h1 import H1_BRIEFS_DIR
        brief_file = H1_BRIEFS_DIR / f"{handle}_brief.json"
        if brief_file.exists():
            try:
                saved_data = json.loads(brief_file.read_text(encoding="utf-8"))
                brief.approval_status = saved_data.get("approval_status", brief.approval_status)
                brief.approved_by = saved_data.get("approved_by", brief.approved_by)
                brief.approved_at = saved_data.get("approved_at", brief.approved_at)
            except Exception:
                pass
        else:
            brief_file.write_text(json.dumps(asdict(brief), indent=2), encoding="utf-8")

        md_output = brief.render_markdown()
        print("\n" + md_output)

        brief_md = H1_BRIEFS_DIR / f"{handle}_brief.md"
        brief_md.write_text(md_output, encoding="utf-8")
        print(f"[+] Saved brief: {brief_md}")
        return 0

    if action == "approve":
        raw_handle = args.program
        handle = sanitize_handle(raw_handle)
        target = args.target
        from bb.h1 import H1_BRIEFS_DIR, H1_PROGRAMS_DIR
        brief_file = H1_BRIEFS_DIR / f"{handle}_brief.json"
        if not brief_file.exists():
            print(f"[!] Brief not found for '{handle}'. Run `bb h1 brief --program {handle}` first.")
            return 1

        data = json.loads(brief_file.read_text(encoding="utf-8"))
        in_assets = data.get("in_scope_assets", [])
        
        # Verify proposed target against in-scope rules
        try:
            client = H1Client()
            scope = client.scope(handle)
        except Exception as exc:
            print(f"[!] Could not verify program scope for '{handle}': {exc}")
            return 1

        if target:
            if not scope.is_in_scope(target):
                print(f"[!] PROPOSED TARGET REJECTED: '{target}' is NOT in-scope according to program policy rules.")
                print("[!] Target testing refused under deterministic safety invariant.")
                return 1
            print(f"[+] Verified target '{target}' matches program scope rules.")

        data["approval_status"] = "APPROVED"
        data["approved_by"] = os.environ.get("USERNAME") or os.environ.get("USER") or "researcher"
        data["approved_at"] = now_iso()
        if target:
            data["recommended_first_target"] = target
        brief_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

        # Save program profile for continuous research engine
        from bb.h1 import ProgramAuthorizationBrief
        brief_obj = ProgramAuthorizationBrief(**data)
        profile = BriefGenerator.create_program_profile(brief_obj)
        profile_path = H1_PROGRAMS_DIR / f"{handle}_profile.json"
        profile_path.write_text(json.dumps(asdict(profile), indent=2), encoding="utf-8")

        # Also save official scope file into data/scopes/
        scope_p = scope.save(scope_path(handle))
        print(f"[+] Program '{handle}' APPROVED for investigation.")
        print(f"[+] Program research profile written: {profile_path}")
        print(f"[+] Scope written: {scope_p}")
        print(f"[+] Target '{target or data.get('recommended_first_target')}' authorized for testing.")
        print(f"\nNext: launch investigation with `bb auto --program {handle} --target {target or data.get('recommended_first_target')}`")
        return 0

    if action == "report":
        store = Store()
        finding = store.get_finding(args.finding)
        if not finding:
            raise SystemExit(f"no finding matching {args.finding!r}")

        raw_handle = args.program or finding.meta.get("program") or "target_program"
        handle = sanitize_handle(raw_handle)
        from bb.h1 import H1_BRIEFS_DIR, H1_REPORTS_DIR, ProgramAuthorizationBrief
        brief_file = H1_BRIEFS_DIR / f"{handle}_brief.json"
        if brief_file.exists():
            brief_data = json.loads(brief_file.read_text(encoding="utf-8"))
            brief = ProgramAuthorizationBrief(**brief_data)
        else:
            brief = ProgramAuthorizationBrief(
                handle=handle, program_name=handle, offers_bounties=True,
                policy_hash="ad-hoc", retrieved_at=now_iso(),
                in_scope_assets=[finding.host or ""], out_of_scope_assets=[],
                scope_exclusions=[], testing_restrictions=[], rate_limit=3.0,
                custom_headers={}, human_review_notes=[],
                recommended_first_target=finding.url or "",
            )

        draft = HackerOneReportGenerator.prepare_draft(finding, brief)
        safe_id = sanitize_handle(finding.id[:12])
        out_json = H1_REPORTS_DIR / f"h1_report_{safe_id}.json"
        out_md = H1_REPORTS_DIR / f"h1_report_{safe_id}.md"
        out_json.write_text(json.dumps(draft, indent=2), encoding="utf-8")
        out_md.write_text(draft["vulnerability_information"], encoding="utf-8")

        print(f"[+] HackerOne Draft Report prepared for '{finding.title}':")
        print(f"    Markdown: {out_md}")
        print(f"    JSON Payload: {out_json}")
        print("\n" + draft["curl_command"])
        print("\n[!] HUMAN SUBMISSION REQUIRED: Review reproduction evidence, then submit manually via HackerOne web UI or curl.")
        return 0

    print(f"[!] Unknown h1 action: {action}")
    return 1


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


def cmd_auto(args) -> int:
    from bb.auto import AutoHunter, AutoHunterConfig
    _require_not_stopped()
    scope = _scope_or_die(args.program)
    accounts = load_accounts(accounts_path(args.accounts)) if args.accounts else None
    entries = args.entry or [f"https://{h}" for h in scope.apex_domains() if not h.startswith("*")]
    if not entries:
        raise SystemExit("no entry URLs found; supply via --entry https://target.com")

    cfg = AutoHunterConfig(
        program=args.program,
        scope=scope,
        entry_urls=entries,
        accounts=accounts,
        rate=args.rate,
        max_requests=args.max_requests,
        timeout=args.timeout,
        proxy=args.proxy,
        dry_run=args.dry_run,
        cbh=args.cbh,
        llm=args.llm,
        workers=args.workers,
        run_waf_probe=not args.no_waf,
        cve_match=not args.no_cve,
        ai_analysis=not args.no_ai,
        queue=not args.no_queue,
        tev1=not args.no_tev1,
        controller=getattr(args, "controller", True),
    )
    hunter = AutoHunter(cfg)
    res = hunter.run()
    print("\nAutonomous Run Summary:")
    print(json.dumps(res, indent=2))
    return 0


def cmd_controller(args) -> int:
    from bb.orchestrator.controller import Controller, ControllerConfig
    from bb.orchestrator.lifecycle import LifecycleManager, State
    store = Store()

    if args.action == "status":
        run_id = args.run
        if not run_id:
            latest = store.latest_run()
            if not latest:
                print("no runs found")
                return 1
            run_id = latest["id"]
        run_data = store.run(run_id)
        if not run_data:
            print(f"no run matching {run_id!r}")
            return 1
        meta = json.loads(run_data["meta"] or "{}") if isinstance(run_data.get("meta"), str) else (run_data.get("meta") or {})
        tasks = store.task_counts(run_id)
        findings = store.findings(run_id=run_id)
        print(f"run:        {run_id} ({run_data.get('program')})")
        print(f"state:      {meta.get('state', 'UNKNOWN')}")
        print(f"started:    {run_data.get('started_at')}")
        print(f"ended:      {run_data.get('ended_at') or 'in-flight'}")
        print(f"tasks:      {tasks}")
        print(f"findings:   {len(findings)}")
        if meta.get("state_history"):
            print("\nrecent state transitions:")
            for h in meta["state_history"][-5:]:
                print(f"  {h.get('at')}: {h.get('from')} -> {h.get('to')} ({h.get('reason')})")
        return 0

    if args.action == "pause":
        run_id = args.run
        if not run_id:
            latest = store.latest_run()
            if not latest:
                print("no runs found")
                return 1
            run_id = latest["id"]
        lm = LifecycleManager(store, run_id)
        lm.pause(reason=args.reason or "cli pause")
        print(f"run {run_id} paused. resume with: bb controller resume --run {run_id}")
        return 0

    if args.action == "resume":
        run_id = args.run
        if not run_id:
            latest = store.latest_run()
            if not latest:
                print("no runs found")
                return 1
            run_id = latest["id"]
        run_data = store.run(run_id)
        if not run_data:
            print(f"no run matching {run_id!r}")
            return 1
        lm = LifecycleManager(store, run_id)
        lm.resume(reason="cli resume")
        print(f"run {run_id} resumed into state {lm.state.value}.")
        return 0

    if args.action == "abort":
        run_id = args.run
        if not run_id:
            latest = store.latest_run()
            if not latest:
                print("no runs found")
                return 1
            run_id = latest["id"]
        lm = LifecycleManager(store, run_id)
        lm.abort(reason=args.reason or "cli abort")
        print(f"run {run_id} aborted.")
        return 0

    if args.action == "run":
        _require_not_stopped()
        scope = _scope_or_die(args.program)
        accounts = load_accounts(accounts_path(args.accounts)) if args.accounts else None
        entries = args.entry or [f"https://{h}" for h in scope.apex_domains() if not h.startswith("*")]
        if not entries:
            raise SystemExit("no entry URLs found; supply via --entry https://target.com")

        cfg = ControllerConfig(
            program=args.program,
            scope=scope,
            entry_urls=entries,
            accounts=accounts,
            rate=args.rate,
            max_requests=args.max_requests,
            timeout=args.timeout,
            proxy=args.proxy,
            dry_run=args.dry_run,
            cbh=args.cbh,
            llm=args.llm,
            workers=args.workers,
            allow_write=args.allow_write,
            run_waf_probe=not args.no_waf,
            cve_match=not args.no_cve,
            ai_analysis=not args.no_ai,
            queue=not args.no_queue,
            tev1=not args.no_tev1,
        )
        ctrl = Controller(cfg, store=store)
        res = ctrl.run()
        print("\nPersistent Controller Summary:")
        print(json.dumps(res, indent=2))
        return 0

    return 1


def cmd_handoff(args) -> int:
    from bb.coder.manifest import TaskManifest, DEFAULT_MANIFEST_PATH
    from bb.coder.provider import ProviderStateManager, WorktreeLock, LockConflictError

    mgr = ProviderStateManager()
    lock = mgr.lock

    if args.action == "status":
        manifest = None
        if DEFAULT_MANIFEST_PATH.exists():
            try:
                manifest = TaskManifest.load()
            except Exception:
                pass
        status_info = mgr.get_status(manifest)
        if getattr(args, "json", False):
            print(json.dumps(status_info, indent=2))
        else:
            print("=== CODING AGENT HANDOFF STATUS ===")
            print(f"Active Provider:   {status_info['active_provider']}")
            print(f"Primary Provider:  {status_info['primary_provider']}")
            print(f"Fallback Provider: {status_info['fallback_provider']}")
            print(f"Last Switch:       {status_info['last_switch_at']} ({status_info['last_switch_reason']})")
            lk = status_info["lock"]
            print(f"Worktree Lock:     {'LOCKED' if lk['locked'] else 'UNLOCKED'} (stale: {lk['stale']})")
            if lk["info"]:
                print(f"  Owner:           {lk['info'].get('owner')} (PID {lk['info'].get('pid')})")
                print(f"  Acquired:        {lk['info'].get('acquired_at')}")
            ms = status_info["manifest_summary"]
            if ms and ms["task_id"]:
                print(f"Active Task:       {ms['task_id']}")
                print(f"Objective:         {ms['objective']}")
                commit_abbr = ms['last_commit'][:10] if ms['last_commit'] else 'none'
                print(f"Branch / Commit:   {ms['branch']} @ {commit_abbr}")
                print(f"Dirty Files:       {ms['files_changed_count']}")
            else:
                print("Active Task:       None (no manifest found)")
        return 0

    if args.action == "create":
        manifest = TaskManifest(
            task_id=args.task_id,
            objective=args.objective,
            current_provider=mgr.active_provider,
            acceptance_criteria=args.criteria if args.criteria else [],
            unfinished_tasks=args.unfinished if args.unfinished else [],
        )
        manifest.refresh_git_status()
        p = manifest.save()
        print(f"Task manifest initialized at {p}")
        return 0

    if args.action == "switch":
        to_target = args.to.lower()
        reason = getattr(args, "reason", "") or f"switched via CLI to {to_target}"
        manifest = None
        if DEFAULT_MANIFEST_PATH.exists():
            try:
                manifest = TaskManifest.load()
            except Exception:
                pass
        if not manifest:
            manifest = TaskManifest(
                task_id=getattr(args, "task_id", "") or "untracked-task",
                objective="Coding task handoff",
            )

        force = getattr(args, "force", False)
        try:
            if to_target in ("fallback", "qwen"):
                res = mgr.switch_to_fallback(manifest, reason=reason, force_lock=force)
            elif to_target in ("primary", "antigravity", "codex"):
                p_name = to_target if to_target != "primary" else None
                res = mgr.switch_to_primary(manifest, primary_name=p_name, reason=reason, force_lock=force)
            else:
                print(f"Unknown target provider: {to_target}. Choose 'primary' or 'fallback'.", file=sys.stderr)
                return 1
            print("Successfully switched coding provider:")
            print(json.dumps(res, indent=2))
            return 0
        except LockConflictError as exc:
            print(f"Lock conflict error: {exc}", file=sys.stderr)
            return 1

    if args.action == "update":
        if not DEFAULT_MANIFEST_PATH.exists():
            print("No task manifest found. Run 'bb handoff create' first.", file=sys.stderr)
            return 1
        manifest = TaskManifest.load()
        manifest.refresh_git_status()
        if getattr(args, "next_action", None):
            manifest.next_action = args.next_action
        if getattr(args, "test_results", None):
            try:
                manifest.test_results = json.loads(args.test_results)
            except Exception:
                manifest.test_results = {"summary": args.test_results}
        if getattr(args, "criteria", None):
            manifest.acceptance_criteria.extend(args.criteria)
        if getattr(args, "issue", None):
            manifest.known_issues.append(args.issue)
        manifest.save()
        print("Task manifest updated with current git status and options.")
        return 0

    if args.action == "lock":
        sub_act = getattr(args, "lock_action", "status")
        if sub_act == "status":
            info = lock.get_info()
            print(f"Locked: {lock.is_locked()}, Stale: {lock.is_stale(info)}")
            print(json.dumps(info or {}, indent=2))
            return 0
        if sub_act == "acquire":
            owner = getattr(args, "owner", "") or mgr.active_provider
            force = getattr(args, "force", False)
            if lock.acquire(owner=owner, force=force):
                print(f"Acquired worktree lock for '{owner}'")
                return 0
            else:
                print("Failed to acquire lock (already held). Use --force to override.", file=sys.stderr)
                return 1
        if sub_act == "release":
            owner = getattr(args, "owner", "")
            force = getattr(args, "force", False)
            if lock.release(owner=owner, force=force):
                print("Worktree lock released.")
                return 0
            else:
                print("Failed to release lock (owner mismatch). Use --force to override.", file=sys.stderr)
                return 1

    if args.action == "plan":
        if not DEFAULT_MANIFEST_PATH.exists():
            print("No task manifest found. Run 'bb handoff create' first.", file=sys.stderr)
            return 1
        manifest = TaskManifest.load()
        print("=== LOCAL QWEN CODER TASK BRIEF ===")
        print(f"TASK ID:    {manifest.task_id}")
        print(f"OBJECTIVE:  {manifest.objective}")
        print(f"BRANCH:     {manifest.branch}")
        print(f"COMMIT:     {manifest.last_known_commit}")
        print("\nACCEPTANCE CRITERIA:")
        for ac in manifest.acceptance_criteria:
            print(f"  * {ac}")
        print("\nFILES DIRTY / CHANGED:")
        for fc in manifest.files_changed:
            print(f"  * {fc}")
        print("\nUNFINISHED TASKS:")
        for ut in manifest.unfinished_tasks:
            print(f"  * {ut}")
        print(f"\nNEXT RECOMMENDED ACTION:\n  {manifest.next_action}")
        return 0

    return 1


def cmd_dashboard(args) -> int:
    from bb.ui import run_dashboard
    run_dashboard(host=args.host, port=args.port, open_browser=args.open)
    return 0


def cmd_cve(args) -> int:
    from bb import cve
    if args.action == "import":
        res = cve.import_file(args.file)
        print(f"imported {res['records']} records ({res['added']} new, {res['total']} total in index)")
        return 0
    if args.action == "query":
        idx = cve.CveIndex()
        hits = idx.query(args.query, k=args.limit)
        print(cve.format_hits(hits))
        return 0
    if args.action == "stats":
        idx = cve.CveIndex()
        print(json.dumps(idx.stats(), indent=2))
        return 0
    return 1


def cmd_learn(args) -> int:
    from bb import learn
    store = Store()
    if args.action == "report":
        rep = learn.learning_report(store, program=args.program)
        if args.json:
            print(json.dumps(rep, indent=2))
        else:
            print(learn.format_report(rep))
        return 0
    if args.action == "export":
        res = learn.export_dataset(store, path=args.out, program=args.program)
        print(f"exported {res['rows']} SFT records to {res['path']}")
        print("\n" + learn.training_hint(res['path']))
        return 0
    return 1


def cmd_waf(args) -> int:
    from bb import waf
    _require_not_stopped()
    scope = _scope_or_die(args.program)
    client = ScopedClient(scope, proxy=args.proxy, dry_run=args.dry_run, tool="waf")
    print(f"[*] Probing parameter normalization resilience on {args.url} ...")
    res = waf.probe_url(client, args.url, param=args.param)
    print(waf.format_report(res))
    return 0


def cmd_analyze(args) -> int:
    from bb import analyze
    store = Store()
    finding = store.get_finding(args.finding)
    if not finding:
        raise SystemExit(f"no finding found matching {args.finding!r}")
    res = analyze.analyze(finding, use_llm=args.llm)
    print(analyze.format_analysis(res))
    return 0


def cmd_authz(args) -> int:
    from bb.authz import AuthzInvestigationWorkflow
    from bb.http import RequestBudget

    action = getattr(args, "authz_action", None)
    if not action:
        print("usage: bb authz {plan,run,status} ...")
        return 1

    if action == "status":
        from bb.authz.workflow import AUTHZ_CHECKPOINTS_DIR
        AUTHZ_CHECKPOINTS_DIR.mkdir(parents=True, exist_ok=True)
        checkpoints = list(AUTHZ_CHECKPOINTS_DIR.glob("*.json"))
        if not checkpoints:
            print("No authorization investigations found.")
            return 0
        print(f"=== AUTHORIZATION INVESTIGATIONS ({len(checkpoints)}) ===")
        for cp in checkpoints:
            try:
                data = json.loads(cp.read_text(encoding="utf-8"))
                print(f"[{data.get('status', 'unknown').upper():9}] {data.get('investigation_id')} | "
                      f"Program: {data.get('program')} | Hypotheses: {data.get('hypotheses_count')} | "
                      f"Verified: {len(data.get('verified_findings', []))} | "
                      f"Updated: {data.get('updated_at')}")
            except Exception:
                print(f"[CORRUPT] {cp.name}")
        return 0

    _require_not_stopped()
    scope = _scope_or_die(args.program)
    accounts = load_accounts(getattr(args, "accounts", None), args.program)
    store = Store()
    budget = RequestBudget(rate=args.rate, max_requests=args.max_requests)

    wf = AuthzInvestigationWorkflow(
        program=args.program,
        scope=scope,
        accounts=accounts,
        store=store,
        har_path=args.har,
        budget=budget,
        investigation_id=getattr(args, "id", None),
    )

    if action == "plan":
        plan = wf.build_plan()
        print(f"\n=== AUTHORIZATION INVESTIGATION PLAN: {plan['investigation_id']} ===")
        print(f"Program:            {plan['program']}")
        print(f"Endpoints observed: {plan['endpoints_observed']}")
        print(f"Parameters:         {plan['parameters_observed']}")
        print(f"Objects:            {plan['objects_observed']}")
        print(f"Safe Read Tests:    {plan['safe_read_count']}")
        print(f"Write Tests:        {plan['state_changing_count']} (Require human approval)")
        print(f"\nHypotheses ({len(plan['hypotheses'])}):")
        for h in plan["hypotheses"]:
            state_flag = "[WRITE-APPROVAL-REQ]" if h["is_state_changing"] else "[SAFE-READ]"
            print(f"  * {h['id']} {state_flag:20} {h['target_method']:6} {h['target_endpoint']}")
            print(f"    {h['title']}")
        print("\nTo execute this plan, run:")
        print(f"  bb authz run --program {args.program} --har \"{args.har}\"")
        return 0

    if action == "run":
        approved_ops = getattr(args, "approve_ops", None) or []
        res = wf.run_investigation(
            allow_write=getattr(args, "allow_write", False),
            approved_operations=approved_ops,
        )
        print(f"\n=== INVESTIGATION RUN FINISHED: {res['investigation_id']} ===")
        print(f"Status:             {res['status']}")
        print(f"Total Hypotheses:   {res['total_hypotheses']}")
        print(f"Verified Findings:  {res['verified']}")
        print(f"Rejected Findings:  {res['rejected']}")
        print(f"Inconclusive:       {res['inconclusive']}")
        if res["verified"] > 0:
            print("\nVerified findings placed into human approval queue:")
            print("  Run 'bb queue' to review and 'bb decide <id> --approve' to accept.")
        return 0

    return 1



# ============================================================
# parser
# ============================================================



def cmd_burp(args) -> int:
    from bb.burp_api import BurpApiClient
    from bb.burp_export import export_exchanges_to_burp_xml, export_finding_to_burp
    from bb.store import Store

    ensure_dirs()
    action = getattr(args, "burp_action", None)

    if action == "status":
        client = BurpApiClient(base_url=args.url or "http://127.0.0.1:1337", api_key=args.key)
        probe = client.probe()
        if args.json:
            print(json.dumps(probe, indent=2))
            return 0
        print("Burp Suite REST API Probe Status:")
        print(f"  Available:    {probe['available']}")
        print(f"  Edition:      {probe['edition']}")
        print(f"  Version:      {probe.get('version') or 'n/a'}")
        print(f"  Base URL:     {probe['base_url']}")
        print(f"  Capabilities: {', '.join(probe.get('supported_capabilities', [])) or '(none)'}")
        print(f"  Detail:       {probe['detail']}")
        return 0

    elif action == "export":
        store = Store()
        out_file = args.out or "bountybot_burp_export.xml"
        if args.finding:
            f = store.get_finding(args.finding)
            if not f:
                print(f"error: finding not found: {args.finding}", file=sys.stderr)
                return 1
            export_finding_to_burp(f, output_path=out_file)
            print(f"Exported finding {args.finding} evidence to {out_file} (Burp XML format).")
            return 0
        else:
            findings = store.findings()
            all_exchanges = []
            for f in findings:
                for ev in f.evidence:
                    if ev.exchange:
                        all_exchanges.append(ev.exchange)
            export_exchanges_to_burp_xml(all_exchanges, output_path=out_file)
            print(f"Exported {len(all_exchanges)} exchange(s) across {len(findings)} finding(s) to {out_file}.")
            return 0
    else:
        print("Use bb burp --help for subcommands.")
        return 0


def cmd_intel(args) -> int:
    from bb.intelligence import IntelligenceEngine
    ensure_dirs()
    engine = IntelligenceEngine()
    try:
        action = getattr(args, "intel_action", None)
        if action == "ingest":
            target_path = Path(args.file)
            if not target_path.exists():
                print(f"error: file not found: {args.file}", file=sys.stderr)
                return 1
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            kind = args.kind
            if kind == "cve":
                ids = engine.ingest_nvd_cve(data)
            elif kind == "cwe":
                ids = engine.ingest_cwe(data)
            elif kind == "capec":
                ids = engine.ingest_capec(data)
            elif kind == "advisory":
                ids = engine.ingest_advisory(data)
            elif kind == "disclosure":
                ids = engine.ingest_disclosure(data)
            else:
                print(f"unknown kind: {kind}", file=sys.stderr)
                return 1
            print(f"Successfully ingested {len(ids)} intelligence record(s) [{kind}].")
            for rid in ids[:5]:
                print(f"  - {rid}")
            if len(ids) > 5:
                print(f"  ... and {len(ids) - 5} more")
            return 0

        elif action == "query":
            records = engine.query(
                query=args.query,
                vuln_class=args.vuln_class,
                product=args.product,
                version=args.version,
                source=args.source,
                limit=args.limit,
            )
            if args.json:
                print(json.dumps([r.to_dict() for r in records], indent=2))
                return 0
            print(f"Found {len(records)} intelligence record(s):")
            for r in records:
                src = r.source.upper()
                print(f"[{src}] {r.id}: {r.title} (class={r.vuln_class}, product={r.affected_product})")
                print(f"    URL: {r.source_url} (freshness={r.data_freshness})")
            return 0

        elif action == "priors":
            priors = engine.get_program_priors(program=args.program)
            if args.json:
                print(json.dumps(priors, indent=2))
                return 0
            prog_label = args.program or "(all)"
            print(f"Hypothesis empirical priors for program={prog_label}:")
            for cls_name, s in priors.items():
                w = s['weight']
                dec = s['decided']
                conf = s['confirmed']
                rej = s['rejected']
                nt = s['note']
                print(f"  {cls_name:25} weight={w:.2f}  decided={dec}  confirmed={conf}  rejected={rej}  ({nt})")
            return 0
        else:
            print("Use bb intel --help for subcommands.")
            return 0
    finally:
        engine.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bb", description=f"bountybot {__version__} — "
                               "scope-gated bug-bounty pipeline (nothing auto-submits)")
    p.add_argument("--version", action="version", version=f"bountybot {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create data dirs + example config").set_defaults(func=cmd_init)
    sub.add_parser("integrations", help="health-check ollama/cbh/artex/pentagi/lab").set_defaults(func=cmd_integrations)

    st = sub.add_parser("stop", help="KILL SWITCH: stop every request, in every process")
    st.add_argument("reason", nargs="?", help="why (stored with the marker)")
    st.set_defaults(func=cmd_stop)
    rs = sub.add_parser("resume", help="clear the kill switch")
    rs.set_defaults(func=cmd_resume)

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

    dp = sub.add_parser("duplicate", help="local disclosed-report prior and checklist")
    dsub = dp.add_subparsers(dest="action", required=True)
    dpp = dsub.add_parser("pull", help="download the official HackerOne dataset")
    dpp.add_argument("--dest")
    dpp.add_argument("--ingest", action="store_true", help="index after downloading")
    dpp.set_defaults(func=cmd_duplicate)
    dpi = dsub.add_parser("ingest", help="index local parquet files")
    dpi.add_argument("--dir")
    dpi.set_defaults(func=cmd_duplicate)
    dsub.add_parser("stats", help="show the local index").set_defaults(func=cmd_duplicate)
    dse = dsub.add_parser("search", help="search disclosed reports")
    dse.add_argument("--query", required=True)
    dse.add_argument("--team")
    dse.add_argument("--asset")
    dse.add_argument("--weakness")
    dse.add_argument("--k", type=int, default=10)
    dse.set_defaults(func=cmd_duplicate)
    dch = dsub.add_parser("check", help="record a duplicate checklist for a finding")
    dch.add_argument("--finding", required=True)
    dch.add_argument("--k", type=int, default=8)
    dch.set_defaults(func=cmd_duplicate)

    s = sub.add_parser("submit", help="print (never send) the HackerOne submission payload")
    s.add_argument("--finding", required=True)
    s.add_argument("--team", required=True)
    s.add_argument("--weakness", type=int)
    s.add_argument("--scope-id", type=int)
    s.set_defaults(func=cmd_submit)

    h1_p = sub.add_parser("h1", help="HackerOne program discovery, guideline reading, authorization & reports")
    h1_sub = h1_p.add_subparsers(dest="action", required=True)

    h1_prog = h1_sub.add_parser("programs", help="discover and rank accessible bug bounty programs")
    h1_prog.add_argument("--limit", type=int, default=25, help="max programs to display")
    h1_prog.set_defaults(func=cmd_h1)

    h1_brief = h1_sub.add_parser("brief", help="generate human-readable program authorization brief")
    h1_brief.add_argument("--program", required=True, help="program handle")
    h1_brief.set_defaults(func=cmd_h1)

    h1_appr = h1_sub.add_parser("approve", help="operator approval of program and first target")
    h1_appr.add_argument("--program", required=True, help="program handle")
    h1_appr.add_argument("--target", help="specific in-scope target URL or host")
    h1_appr.set_defaults(func=cmd_h1)

    h1_rep = h1_sub.add_parser("report", help="prepare HackerOne submission report draft for verified finding")
    h1_rep.add_argument("--finding", required=True, help="finding ID or prefix")
    h1_rep.add_argument("--program", help="program handle")
    h1_rep.set_defaults(func=cmd_h1)

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

    imp = sub.add_parser("import", help="import authenticated traffic (HAR or Burp export)")
    isub = imp.add_subparsers(dest="source", required=True)
    ihar = isub.add_parser("har", help="import a browser HAR export")
    ihar.add_argument("file")
    ihar.add_argument("--program", required=True)
    ihar.set_defaults(func=cmd_import)
    iburp = isub.add_parser("burp", help='import a Burp "Save selected items" XML export')
    iburp.add_argument("file")
    iburp.add_argument("--program", required=True)
    iburp.set_defaults(func=cmd_import)

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
    oc.add_argument("--submitted",
                    help="date the report was actually submitted (required for "
                         "duplicate/informative/rejected to count as submitted)")
    oc.add_argument("--notes")
    oc.add_argument("--program")
    oc.add_argument("--list", action="store_true")
    oc.set_defaults(func=cmd_outcome)

    mt = sub.add_parser("metrics", help="acceptance, duplicates, bounty per hour")
    mt.add_argument("--program")
    mt.add_argument("--json", action="store_true")
    mt.set_defaults(func=cmd_metrics)

    fb = sub.add_parser("feedback", help="outcome history as class priors (the readback loop)")
    fb.add_argument("--program")
    fb.add_argument("--json", action="store_true")
    fb.set_defaults(func=cmd_feedback)

    vv = sub.add_parser("verify", help="independently verify candidate findings before reporting")
    vv.add_argument("--program", required=True)
    vv.add_argument("--accounts", help="accounts JSON — enables online replay verification")
    vv.add_argument("--finding", help="verify one finding instead of all candidates")
    vv.add_argument("--proxy")
    vv.add_argument("--dry-run", action="store_true", help="offline audit only, no login/replay")
    vv.set_defaults(func=cmd_verify)

    ui = sub.add_parser("dashboard", help="launch local web dashboard and triage UI")
    ui.add_argument("--host", default="127.0.0.1", help="dashboard bind host")
    ui.add_argument("--port", type=int, default=8888, help="dashboard port")
    ui.add_argument("--open", action="store_true", help="open web browser on start")
    ui.set_defaults(func=cmd_dashboard)

    au = sub.add_parser("auto", help="fully autonomous bug hunter loop (recon -> checks -> verify -> triage)")
    au.add_argument("--program", required=True)
    au.add_argument("--entry", action="append", help="entry URL (can be specified multiple times)")
    au.add_argument("--accounts", help="accounts JSON file for differential auth testing")
    au.add_argument("--rate", type=float, default=2.0, help="request rate limit (req/s)")
    au.add_argument("--max-requests", type=int, default=200, help="maximum request budget")
    au.add_argument("--timeout", type=float, default=15.0)
    au.add_argument("--proxy")
    au.add_argument("--dry-run", action="store_true")
    au.add_argument("--cbh", action="store_true")
    au.add_argument("--llm", action="store_true")
    au.add_argument("--workers", type=int, default=4)
    au.add_argument("--no-waf", action="store_true")
    au.add_argument("--no-cve", action="store_true")
    au.add_argument("--no-ai", action="store_true")
    au.add_argument("--no-tev1", action="store_true",
                    help="skip the structured decision model (Tev1)")
    au.add_argument("--no-queue", action="store_true")
    au.add_argument("--controller", dest="controller", action="store_true", default=True,
                    help="use persistent orchestrator controller (default)")
    au.add_argument("--legacy", dest="controller", action="store_false",
                    help="use legacy single-pass execution loop")
    au.set_defaults(func=cmd_auto)



    bp = sub.add_parser("burp", help="Burp Suite integration (status probe, XML export, API bridge)")
    bp_sub = bp.add_subparsers(dest="burp_action", required=True)

    bp_status = bp_sub.add_parser("status", help="probe Burp Suite REST API status and capabilities")
    bp_status.add_argument("--url", default="http://127.0.0.1:1337", help="Burp REST API endpoint")
    bp_status.add_argument("--key", help="Burp REST API key")
    bp_status.add_argument("--json", action="store_true")
    bp_status.set_defaults(func=cmd_burp)

    bp_export = bp_sub.add_parser("export", help="export evidence exchanges to Burp XML format")
    bp_export.add_argument("--finding", help="export specific finding ID evidence")
    bp_export.add_argument("--out", help="destination XML path (default: bountybot_burp_export.xml)")
    bp_export.set_defaults(func=cmd_burp)

    intel = sub.add_parser("intel", help="security intelligence engine (CVE, CWE, CAPEC, advisories, priors)")
    intel_sub = intel.add_subparsers(dest="intel_action", required=True)

    in_ingest = intel_sub.add_parser("ingest", help="ingest intelligence feed file")
    in_ingest.add_argument("--file", required=True, help="path to JSON intelligence feed")
    in_ingest.add_argument("--kind", choices=["cve", "cwe", "capec", "advisory", "disclosure"], required=True)
    in_ingest.set_defaults(func=cmd_intel)

    in_query = intel_sub.add_parser("query", help="search security intelligence records")
    in_query.add_argument("query", nargs="?", help="search terms")
    in_query.add_argument("--vuln-class", help="filter by vulnerability class")
    in_query.add_argument("--product", help="filter by affected product")
    in_query.add_argument("--version", help="filter and check against product version")
    in_query.add_argument("--source", choices=["nvd", "cwe", "capec", "advisory", "disclosure"])
    in_query.add_argument("--limit", type=int, default=20)
    in_query.add_argument("--json", action="store_true")
    in_query.set_defaults(func=cmd_intel)

    in_priors = intel_sub.add_parser("priors", help="view learned empirical priors from hypothesis outcomes")
    in_priors.add_argument("--program", help="filter by target program")
    in_priors.add_argument("--json", action="store_true")
    in_priors.set_defaults(func=cmd_intel)

    ctrl = sub.add_parser("controller", help="persistent research controller (status, pause, resume, run)")
    ctrl_sub = ctrl.add_subparsers(dest="action", required=True)
    c_status = ctrl_sub.add_parser("status", help="show controller state and task statistics")
    c_status.add_argument("--run", help="run ID (defaults to latest)")
    c_status.set_defaults(func=cmd_controller)
    c_pause = ctrl_sub.add_parser("pause", help="pause execution cleanly")
    c_pause.add_argument("--run", help="run ID (defaults to latest)")
    c_pause.add_argument("--reason", help="reason for pausing")
    c_pause.set_defaults(func=cmd_controller)
    c_resume = ctrl_sub.add_parser("resume", help="resume execution from paused state")
    c_resume.add_argument("--run", help="run ID (defaults to latest)")
    c_resume.set_defaults(func=cmd_controller)
    c_abort = ctrl_sub.add_parser("abort", help="abort controller run permanently")
    c_abort.add_argument("--run", help="run ID (defaults to latest)")
    c_abort.add_argument("--reason", help="reason for aborting")
    c_abort.set_defaults(func=cmd_controller)
    c_run = ctrl_sub.add_parser("run", help="run persistent controller directly")
    c_run.add_argument("--program", required=True)
    c_run.add_argument("--entry", action="append", help="entry URL (repeatable)")
    c_run.add_argument("--accounts", help="accounts JSON file")
    c_run.add_argument("--rate", type=float, default=2.0)
    c_run.add_argument("--max-requests", type=int, default=200)
    c_run.add_argument("--timeout", type=float, default=15.0)
    c_run.add_argument("--proxy")
    c_run.add_argument("--dry-run", action="store_true")
    c_run.add_argument("--cbh", action="store_true")
    c_run.add_argument("--llm", action="store_true")
    c_run.add_argument("--workers", type=int, default=4)
    c_run.add_argument("--allow-write", action="store_true")
    c_run.add_argument("--no-waf", action="store_true")
    c_run.add_argument("--no-cve", action="store_true")
    c_run.add_argument("--no-ai", action="store_true")
    c_run.add_argument("--no-tev1", action="store_true")
    c_run.add_argument("--no-queue", action="store_true")
    c_run.set_defaults(func=cmd_controller)

    cv = sub.add_parser("cve", help="local CVE knowledge base (query, import, stats)")
    csub = cv.add_subparsers(dest="action", required=True)
    ci = csub.add_parser("import", help="import NVD or CISA-KEV JSON into local index")
    ci.add_argument("--file", required=True)
    ci.set_defaults(func=cmd_cve)
    cq = csub.add_parser("query", help="query CVE index by product or tech stack")
    cq.add_argument("query")
    cq.add_argument("--limit", type=int, default=10)
    cq.set_defaults(func=cmd_cve)
    cs = csub.add_parser("stats", help="show CVE index statistics")
    cs.set_defaults(func=cmd_cve)

    ln = sub.add_parser("learn", help="continuous learning and QLoRA SFT dataset export")
    lsub = ln.add_subparsers(dest="action", required=True)
    lr = lsub.add_parser("report", help="show class priors and empirical learning report")
    lr.add_argument("--program")
    lr.add_argument("--json", action="store_true")
    lr.set_defaults(func=cmd_learn)
    le = lsub.add_parser("export", help="export human verdicts to QLoRA SFT JSONL format")
    le.add_argument("--out", help="destination JSONL file")
    le.add_argument("--program")
    le.set_defaults(func=cmd_learn)

    wf = sub.add_parser("waf", help="probe parameter normalization resilience (defensive canary)")
    wf.add_argument("--program", required=True)
    wf.add_argument("--url", required=True)
    wf.add_argument("--param", help="specific parameter name to test")
    wf.add_argument("--proxy")
    wf.add_argument("--dry-run", action="store_true")
    wf.set_defaults(func=cmd_waf)

    az = sub.add_parser("analyze", help="AI response analysis and next test suggestion")
    az.add_argument("finding", help="finding ID or prefix")
    az.add_argument("--llm", action="store_true", help="use local Ollama model for deep analysis")
    az.set_defaults(func=cmd_analyze)

    ho = sub.add_parser("handoff", help="coding agent handoff & worktree lock management")
    hsub = ho.add_subparsers(dest="action", required=True)

    hs = hsub.add_parser("status", help="show handoff status, active provider and worktree lock")
    hs.add_argument("--json", action="store_true")
    hs.set_defaults(func=cmd_handoff)

    hc = hsub.add_parser("create", help="create a new persistent task manifest")
    hc.add_argument("--task-id", required=True)
    hc.add_argument("--objective", required=True)
    hc.add_argument("--criteria", action="append", help="acceptance criterion (repeatable)")
    hc.add_argument("--unfinished", action="append", help="unfinished task (repeatable)")
    hc.set_defaults(func=cmd_handoff)

    hw = hsub.add_parser("switch", help="switch active coding provider (primary <-> fallback)")
    hw.add_argument("--to", required=True, choices=["primary", "fallback", "antigravity", "codex", "qwen"])
    hw.add_argument("--reason", default="", help="reason for handoff (e.g. 'token quota exhausted')")
    hw.add_argument("--task-id", default="", help="task ID if updating or creating manifest")
    hw.add_argument("--force", action="store_true", help="force override existing worktree lock")
    hw.set_defaults(func=cmd_handoff)

    hu = hsub.add_parser("update", help="refresh git status/diff and update manifest")
    hu.add_argument("--test-results", help="test results JSON or summary string")
    hu.add_argument("--next-action", help="next recommended action")
    hu.add_argument("--criteria", action="append", help="add acceptance criterion (repeatable)")
    hu.add_argument("--issue", help="record a known issue")
    hu.set_defaults(func=cmd_handoff)

    hl = hsub.add_parser("lock", help="manage worktree single-writer lock")
    hl.add_argument("lock_action", choices=["status", "acquire", "release"])
    hl.add_argument("--owner", help="lock owner name")
    hl.add_argument("--force", action="store_true", help="force lock acquire/release")
    hl.set_defaults(func=cmd_handoff)

    hp = hsub.add_parser("plan", help="format task brief for local Qwen Coder from manifest")
    hp.set_defaults(func=cmd_handoff)

    # Autonomous authorization investigation (Task P4)
    az = sub.add_parser("authz", help="autonomous two-account authorization investigation (Task P4)")
    az_sub = az.add_subparsers(dest="authz_action")

    az_plan = az_sub.add_parser("plan", help="build authorization investigation plan without executing requests")
    az_plan.add_argument("--program", required=True, help="target program name")
    az_plan.add_argument("--har", required=True, help="path to authenticated traffic HAR capture")
    az_plan.add_argument("--accounts", help="accounts JSON file (defaults to data/accounts/<program>.json)")
    az_plan.add_argument("--rate", type=float, default=3.0, help="request rate limit (req/sec)")
    az_plan.add_argument("--max-requests", type=int, default=100, help="max requests budget limit")
    az_plan.add_argument("--id", help="custom investigation ID")
    az_plan.set_defaults(func=cmd_authz)

    az_run = az_sub.add_parser("run", help="execute authorization investigation under scoped policy controls")
    az_run.add_argument("--program", required=True, help="target program name")
    az_run.add_argument("--har", required=True, help="path to authenticated traffic HAR capture")
    az_run.add_argument("--accounts", help="accounts JSON file (defaults to data/accounts/<program>.json)")
    az_run.add_argument("--allow-write", action="store_true", help="permit state-changing write operations")
    az_run.add_argument("--approve-ops", action="append", help="approve specific state-changing operation token (repeatable)")
    az_run.add_argument("--rate", type=float, default=3.0, help="request rate limit (req/sec)")
    az_run.add_argument("--max-requests", type=int, default=100, help="max requests budget limit")
    az_run.add_argument("--id", help="custom investigation ID to resume or execute")
    az_run.set_defaults(func=cmd_authz)

    az_status = az_sub.add_parser("status", help="show authorization investigation status and checkpoints")
    az_status.set_defaults(func=cmd_authz)

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
