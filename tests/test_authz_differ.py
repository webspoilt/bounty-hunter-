"""Authz differ tests — MockTransport, zero network."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from authz_differ import Credentials, decide


def make_transport(server_state: dict) -> httpx.MockTransport:
    """Fake server that reacts to whichever Authorization header it receives."""

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        server_state["last_seen_auth"] = auth
        if auth == "Bearer ROLE_A":
            return httpx.Response(200, json={"invoice": {"user_id": 111, "amount": 5000}})
        if auth == "Bearer ROLE_B":
            if server_state.get("mode") == "idor":
                # VULNERABLE: B receives A's data (IDOR simulation)
                return httpx.Response(200, json={"invoice": {"user_id": 111, "amount": 5000}})
            if server_state.get("mode") == "blocked":
                return httpx.Response(403, json={"error": "forbidden"})
            if server_state.get("mode") == "personal":
                return httpx.Response(200, json={"invoice": {"user_id": 222, "amount": 5}})
            if server_state.get("mode") == "different_status":
                return httpx.Response(503, json={"error": "down"})
            return httpx.Response(200, json={"invoice": {"user_id": 222, "amount": 5}})
        return httpx.Response(401, json={"error": "no auth"})

    return httpx.MockTransport(handler)


def run() -> int:
    failures = 0

    def check(cond, label):
        nonlocal failures
        if not cond:
            failures += 1
        print(f"[{'PASS' if cond else 'FAIL'}] {label}")

    A = Credentials(label="role A", headers={"Authorization": "Bearer ROLE_A"})
    B = Credentials(label="role B", headers={"Authorization": "Bearer ROLE_B"})

    # 1. properly enforced: A 200, B 403
    state = {"mode": "blocked"}
    d = decide(httpx.Client(transport=make_transport(state)), method="GET",
               url="http://lab/invoice/111", role_a=A, role_b=B)
    check(d.verdict == "ACCESS_CHECKED" and d.role_b_status == 403, "ACCESS_CHECKED on 403")

    # 2. IDOR: identical bytes both roles
    state = {"mode": "idor"}
    d = decide(httpx.Client(transport=make_transport(state)), method="GET",
               url="http://lab/invoice/111", role_a=A, role_b=B)
    check(d.verdict == "IDENTICAL" and d.role_b_status == 200,
          "IDENTICAL -> IDOR signal (B saw A's data)")

    # 3. personalized content
    state = {"mode": "personal"}
    d = decide(httpx.Client(transport=make_transport(state)), method="GET",
               url="http://lab/invoice/me", role_a=A, role_b=B)
    check(d.verdict == "DIFF_BODY" and d.body_a_len != d.body_b_len, "DIFF_BODY detected")

    # 4. role header used (server actually saw ROLE_A/ROLE_B tokens)
    check(state["last_seen_auth"] == "Bearer ROLE_B", "role creds reached the wire")

    # 5. error mode
    state = {"mode": "different_status"}
    d = decide(httpx.Client(transport=make_transport(state)), method="GET",
               url="http://lab/thing", role_a=A, role_b=B)
    check(d.verdict == "ERROR", "5xx -> ERROR, not evidence")

    # 6. template header overridden by role creds (collision handling)
    req_headers = {"Authorization": "Bearer TEMPLATE", "X-Trace": "t1"}
    state = {"mode": "icontains"}
    state = {"mode": "personal"}
    d = decide(httpx.Client(transport=make_transport(state)), method="GET",
               url="http://lab/x", headers=req_headers, role_a=A, role_b=B)
    # if template auth had been sent, server would 401; it didn't -> override worked
    check(d.role_a_status == 200, "role creds override template auth")
    check(state["last_seen_auth"] == "Bearer ROLE_B", "template header was replaced")

    # 7. cookie-based role auth
    def cookie_handler(request: httpx.Request) -> httpx.Response:
        sid = request.headers.get("cookie", "")
        if "admin_session=1" in sid:
            return httpx.Response(200, json={"items": [1, 2, 3]})
        if "user_session=2" in sid:
            return httpx.Response(200, json={"items": [1]})
        return httpx.Response(401)

    A2 = Credentials(label="admin", cookies={"admin_session": "1"})
    B2 = Credentials(label="user", cookies={"user_session": "2"})
    d = decide(httpx.Client(transport=httpx.MockTransport(cookie_handler)), method="GET",
               url="http://lab/items", role_a=A2, role_b=B2)
    check(d.verdict == "DIFF_BODY", "cookie-based roles diff correctly")

    print(f"\n{'ALL PASS' if failures == 0 else f'{failures} FAILURES'}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
