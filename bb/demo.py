"""`bb demo` — end-to-end proof against the local Juice Shop container.

It creates two accounts, replays object endpoints under both roles, finds a real IDOR,
writes an H1 report, and queues it for human approval. Nothing leaves the machine.
"""
from __future__ import annotations

import json

import httpx

from bb.config import DATA, ensure_dirs, scope_path
from bb.checks import CheckOptions
from bb.models import sev_rank
from bb.pipeline import HuntConfig, hunt
from bb.scope import Scope
from bb.store import Store

JUICE = "http://localhost:3000"
PASSWORD = "SuperSafe!123"

ACCOUNTS = {
    "base_url": JUICE,
    "login": {
        "path": "/rest/user/login",
        "body_keys": {"email": "email", "password": "password"},
        "token_field": "authentication.token",
        "register_path": "/api/Users",
        "register_extra": {"passwordRepeat": "${password}",
                           "securityQuestion": {"id": 1},
                           "securityAnswer": "blue"},
    },
    "accounts": [
        {"label": "userA", "email": "bb-demo-a@test.local", "password": PASSWORD},
        {"label": "userB", "email": "bb-demo-b@test.local", "password": PASSWORD},
    ],
}


def juice_up() -> bool:
    try:
        return httpx.get(JUICE, timeout=3).status_code < 500
    except httpx.HTTPError:
        return False


def run(llm: bool = False, budget: float = 5.0, log=print) -> dict:
    ensure_dirs()
    if not juice_up():
        raise SystemExit(
            "Juice Shop is not reachable at http://localhost:3000\n"
            "start it with:  docker start juice-shop\n"
            "then rerun:     bb demo")

    accounts_file = DATA / "juice.accounts.json"
    accounts_file.write_text(json.dumps(ACCOUNTS, indent=2), encoding="utf-8")

    scope = Scope.from_entries("juice-shop-lab",
                              ["localhost", "127.0.0.1", "*.localhost"],
                              out_of_scope=[])
    scope.save(scope_path("juice-shop-lab"))
    cfg = HuntConfig(
        program="juice-shop-lab",
        scope=scope,
        entry_urls=[JUICE + "/"],
        accounts=ACCOUNTS,
        endpoints=["/rest/basket/1", "/api/Users/1", "/api/Users/2"],
        templates=["/api/Users/{a_id}", "/rest/basket/{a_id}"],
        budget_min=budget,
        rate=6.0,
        max_requests=120,
        llm=llm,
        queue=True,
        check_options=CheckOptions(unauth=True, cors=True, exposed=True, graphql=False,
                                   open_redirect=True, headers=False, max_endpoints=20),
    )
    store = Store()
    log("\n=== bountybot demo: two roles, one object, zero submissions ===\n")
    result = hunt(cfg, store=store, log=log)

    log("\n=== result ===")
    log(f"requests: {result['requests']}   endpoints: {result['endpoints']}   "
        f"scope audit: {result['audit']}")
    findings = [f for f in result["findings"] if f.status == "candidate"]
    if not findings:
        log("no candidate findings this run (all endpoints enforced?).")
        return result
    findings.sort(key=lambda f: -sev_rank(f.severity))
    for f in findings[:5]:
        log(f"\n[{f.severity.upper():8}] {f.bug_class:22} {f.url}")
        log(f"  {f.title}")
        report = f.meta.get("report_path", "")
        if report:
            log(f"  report: {report}")
    best = store.get_finding(findings[0].id)
    queue_id = (best.meta.get("queue_id") if best else "") or ""
    log("\nnext steps:")
    log("  bb queue                                    # list pending findings")
    log(f"  bb report --finding {findings[0].id} --llm          # polish with Ollama")
    if queue_id:
        log(f"  bb decide {queue_id} --approve              # human sign-off")
    log("  (# nothing is submitted to HackerOne by this tool)")
    return result
