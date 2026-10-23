"""
runner.py — the burst runner. The thin end of Scopekeeper that the user runs.

One command does an on-scope burst:
    python runner.py --config data/scope/juice_lab.json --budget 45

What it guarantees:
- scope: refuse to run unless every request passes ScopeEngine
- budget: hard wall-clock cap (minutes) — laptop-friendly, exits cleanly
- provenance: every request lands in the observation DB
- human gate: candidates queue in pending.jsonl (never auto-submitted)
- optional: TELEGRAM_BOT_TOKEN set -> pushes pending cards to your phone
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402

from approval_gate import ApprovalGate  # noqa: E402
from authz_differ import Credentials, decide  # noqa: E402
from observation_db import ObservationDB  # noqa: E402
from scope_engine import Program, ScopeEngine  # noqa: E402


def load_program(cfg_path: str) -> tuple[ScopeEngine, dict]:
    cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    prog = Program.from_json(cfg)
    return ScopeEngine(prog), cfg


def login_sessions(base: str, accounts: list[dict], se: ScopeEngine) -> list[Credentials]:
    """One login session per account. Config may include register_path; creds come
    from config env indirection ($ENV) so real words never sit on disk."""
    creds: list[Credentials] = []
    register_path = accounts[0].pop("register_path", None)
    login_path = accounts[0].get("login_path")
    body_keys = accounts[0].get("body_keys", {"email": "email", "password": "password"})
    token_field = accounts[0].get("token_field", "authentication.token")

    client = httpx.Client(base_url=base, timeout=15)
    for i, acc in enumerate(accounts):
        email, password = acc["email"], acc["password"]
        host = httpx.URL(base).host
        if register_path:
            if not se.is_in_scope(host):
                raise RuntimeError(f"register_path refused: host {host!r} out of scope")
            payload = {
                body_keys["email"]: email,
                body_keys["password"]: password,
                "passwordRepeat": password,
                "securityQuestion": {"id": 1},
                "securityAnswer": "sky",
            }
            client.post(register_path, json=payload)
        r = client.post(login_path,
                        json={body_keys["email"]: email, body_keys["password"]: password})
        token = ""
        try:
            token = r.json()
            for k in token_field.split("."):
                token = token[k]
        except Exception:
            pass
        if not token:
            raise RuntimeError(f"account[{i}] login failed: {r.text[:200]}")
        creds.append(Credentials(label=acc.get("label", f"acct{i}"),
                                 headers={"Authorization": f"Bearer {token}"}))
    return creds


def run_burst(cfg_path: str, budget_min: float) -> int:
    se, cfg = load_program(cfg_path)
    base = cfg["base_url"].rstrip("/")
    host = httpx.URL(base).host
    if not se.is_in_scope(host):
        print(f"REFUSED: host {host!r} out of scope for program {cfg.get('name')}")
        return 1
    deadline = time.time() + budget_min * 60

    accounts = cfg["accounts"]
    creds = login_sessions(base, accounts, se)
    print(f"program: {cfg.get('name')}  target: {base}  roles: {[c.label for c in creds]}")

    client = httpx.Client(base_url=base, timeout=15)
    db = ObservationDB()
    gate = ApprovalGate()
    candidates = []

    for item in cfg.get("endpoints", []):
        if time.time() > deadline:
            print(f"budget reached — stopping cleanly with {len(candidates)} candidates")
            break
        method, path = item["m"], item["path"]
        marker = item.get("marker", "")  # regex anchor belonging to role A only
        template = item.get("headers", {})
        body = item.get("body")

        d = decide(client, method=method, url=path, headers=template, body=body,
                   role_a=creds[0], role_b=creds[1])
        # marker probe: B's body must NOT contain role A's personal marker
        rb = httpx.request(method, base + path, headers=creds[1].headers, timeout=15)
        leaked = bool(marker) and marker in rb.text
        verdict = "candidate" if ((d.verdict == "IDENTICAL" and leaked) or
                                 (d.verdict == "DIFF_BODY" and marker in str(d.notes))) \
            else "informational"

        db.insert(
            tool="authz_differ",
            command=f"{method} {path} (marker={marker or 'none'})",
            target=host,
            verdict=verdict,
            payload={**d.as_payload(), "marker_leak": bool(leaked),
                     "scope_check": f"ALLOW program={cfg.get('name')}"},
        )
        print(f"{method:5} {path:42} {d.verdict:13} leak={leaked} -> {verdict}")
        if verdict == "candidate":
            candidates.append((path, d, rb.text[:600]))

    for path, d, sample in candidates:
        gate.submit(
            obs_row_id=0,
            target=base + path,
            title=f"authz: role B reached {path} (marker cross-access)",
            evidence=[
                {"summary": f"verdict={d.verdict} status={d.role_a_status}->{d.role_b_status}"},
                {"summary": f"role B response contains role A marker: {sample[:200]}"},
                {"summary": f"program={cfg.get('name')} scope=ALLOW"},
            ],
            draft_report=(
                f"Replay under role B returned role A's object at {path}.\n"
                f"{sample}\n[Draft — Scopekeeper burst, review before any submission]"
            ),
        )
    print(f"\n{len(candidates)} candidates queued. Review via pending.jsonl or Telegram gate.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="json program config (data/scope/<file>.json)")
    ap.add_argument("--budget", type=float, default=45.0, help="minutes, hard cap")
    args = ap.parse_args()
    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    for a in cfg["accounts"]:
        if a["password"] == "$ENV":
            a["password"] = os.getenv(a["email_env"], "")
    return run_burst(args.config, args.budget)


if __name__ == "__main__":
    raise SystemExit(main())
