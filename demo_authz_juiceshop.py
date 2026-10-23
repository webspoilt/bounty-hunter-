"""
demo_authz_juiceshop.py — end-to-end proof of the pipeline, lab-only.

Flow: scope gate -> register two low-priv accounts -> login -> replay
money-endpoint candidates under both roles (AuthzDiffer) -> ownership check
(foreign data visible?) -> ObservationDB with provenance -> ApprovalGate queue.

Nothing is submitted anywhere. Findings land in data/pending.jsonl for review.
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx

from approval_gate import ApprovalGate
from authz_differ import Credentials, decide
from observation_db import ObservationDB
from scope_engine import Program, ScopeEngine

BASE = "http://localhost:3000"
PASSWORD = "SuperSafe!123"


def register_login(client: httpx.Client, tag: str) -> tuple[str, int]:
    """Register once (idempotent on rerun) and login. Returns (token, user_id)."""
    email = f"sk_{tag}_{uuid.uuid4().hex[:6]}@test.local"
    reg = client.post("/api/Users", json={
        "email": email, "password": PASSWORD, "passwordRepeat": PASSWORD,
        "securityQuestion": {"id": 1}, "securityAnswer": "blue",
    })
    if reg.status_code not in (200, 201):
        # fallback: account may already exist from a previous demo run
        reg = client.post("/api/Users", json={
            "email": email, "password": PASSWORD,
        })
    r = client.post("/rest/user/login", json={"email": email, "password": PASSWORD})
    data = r.json().get("authentication") or {}
    token = data.get("token", "")
    if not token:
        raise RuntimeError(f"login failed for {email}: {r.text[:200]}")
    import base64
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    return token, claims.get("data", {}).get("id", -1)


def ownership_probe(client: httpx.Client, path: str, headers: dict) -> str:
    """Fetch as role B and summarize ownership fields found in the body."""
    try:
        body = client.get(path, headers=headers).json()
    except Exception:
        return "(non-json)"
    data = body.get("data") if isinstance(body, dict) else None
    if isinstance(data, dict):
        owner = data.get("UserId", data.get("id"))
        email = data.get("email", "")
        role = data.get("role", "")
        return f"UserId={owner} email={email!r} role={role!r}"
    if isinstance(data, list) and data:
        return f"list[{len(data)}] first_id={data[0].get('id') if isinstance(data[0], dict) else data[0]}"
    return "(no ownership fields)"


def main() -> int:
    # 1) hard gate — refuse to even start outside lab
    prog = Program.from_json({
        "name": "juice-shop-lab",
        "in_scope": ["localhost", "127.0.0.1"],
        "out_of_scope": ["*"],
    })
    se = ScopeEngine(prog)
    base_host = "localhost"
    if not se.is_in_scope(base_host):
        print("scope refused — not running outside the lab.")
        return 1

    client = httpx.Client(base_url=BASE, timeout=15)

    # 2) two low-priv roles
    tok_a, id_a = register_login(client, "a")
    tok_b, id_b = register_login(client, "b")
    role_a = Credentials(label=f"userA#{id_a}", headers={"Authorization": f"Bearer {tok_a}"})
    role_b = Credentials(label=f"userB#{id_b}", headers={"Authorization": f"Bearer {tok_b}"})
    print(f"roles: A={role_a.label}  B={role_b.label}")

    # 3) candidates: money endpoints with an object id in the path
    #    (targets are ids belonging to OTHER users: 1=admin, 2=jim)
    candidates = [
        ("GET", "/rest/basket/1"),
        ("GET", "/rest/basket/2"),
        ("GET", "/api/Users/1"),
        ("GET", "/api/Users/2"),
    ]

    db = ObservationDB()
    gate = ApprovalGate()
    stronger = None  # best IDOR evidence this run

    for method, path in candidates:
        d = decide(client, method=method, url=path, role_a=role_a, role_b=role_b)
        own = ownership_probe(client, path, role_b.headers)
        foreign = f"UserId=" in own and f"UserId={id_b}" not in own and role_b.label not in own
        is_admin = "/api/Users/1" in path and "role=admin" in own

        verdict = "candidate" if (d.verdict == "IDENTICAL" and (foreign or is_admin)) else "informational"
        if d.verdict == "ACCESS_CHECKED":
            verdict = "informational"

        row_id, _ = db.insert(
            tool="authz_differ",
            command=f"{method} {path} as {role_a.label} vs {role_b.label}",
            target=base_host,
            verdict=verdict,
            payload={
                **d.as_payload(),
                "role_b_view": own,
                "foreign_access": bool(foreign or is_admin),
                "scope_check": "ALLOW via scope_engine(program=juice-shop-lab)",
            },
            scope_allowed=True,
        )
        line = f"{method:4} {path:20} -> {d.verdict:13} | B sees: {own[:60]} | {verdict}"
        print(line)

        if verdict == "candidate" and stronger is None:
            stronger = (row_id, path, d, own)

    # 4) queue the strongest finding for human review (never auto-submitted)
    if stronger:
        row_id, path, d, own = stronger
        seq = gate.submit(
            obs_row_id=row_id,
            target=BASE + path,
            title=f"Authz bypass: object-id access without ownership check ({path})",
            evidence=[
                {"summary": f"{role_b.label} replayed {path}"},
                {"summary": f"verdict={d.verdict} status={d.role_a_status}->{d.role_b_status}"},
                {"summary": f"roleB sees foreign data: {own[:120]}"},
                {"summary": "scope: localhost lab (ALLOW)"},
            ],
            draft_report=(
                f"While testing locally, user B ({role_b.label}) could read object data "
                f"at {path} owned by another user. Server returned {d.role_b_status} "
                f"without an ownership check (B sees: {own}). Reproduction: login as "
                f"user B, request {path}. Impact: cross-user data disclosure. "
                f"[Draft — lab demo, rewrite against a live program before any submission]"
            ),
        )
        print(f"\nqueued for review: pending seq #{seq} (obs row {row_id})")
    else:
        print("\nno candidates this run (all endpoints enforced or identical-public)")

    print("\nreview:  data/pending.jsonl  |  decide: gate.decide(seq, True/False)  "
          "|  or Telegram: python telegram_gate.py --token <TOKEN>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
