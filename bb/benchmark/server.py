"""Controlled multi-tenant local test server for Bounty Hunter benchmark (Strategic P10).

Simulates both vulnerable and secure endpoints matching the GroundTruthTestCase dataset:
- BOLA / IDOR (vulnerable profile endpoint vs secure document endpoint)
- BFLA (vulnerable admin delete vs secure admin export)
- Property / mass-assignment elevation
- Auth / session boundaries (unauthenticated internal telemetry vs protected dashboard)
- Multi-tenant isolation (cross-tenant billing leak vs isolated repos)
- Injection (vulnerable search reflecting SQL error vs parameterized catalog)
- Information exposure (vulnerable .env dotfile vs secure blocked dotfile)
- Misconfiguration (vulnerable reflective CORS vs secure strict allowlist)
- Ambiguous cases (public directory, generic stack trace, static image headers)

Runs in-process on localhost via standard library http.server on an ephemeral port.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


class BenchmarkAppHandler(BaseHTTPRequestHandler):
    """HTTP request handler simulating multi-tenant web application behavior."""

    def log_message(self, format, *args):
        # Silence default stderr logging during benchmark runs
        pass

    def _send_json(self, status: int, data: dict, headers: dict | None = None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str, headers: dict | None = None):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        auth_header = self.headers.get("Authorization", "")
        origin_header = self.headers.get("Origin", "")

        # 1. BOLA / IDOR
        if path == "/api/v1/users/user_alice_01/profile":
            # Vulnerable: returns Alice's profile even when requested with Bob's token
            self._send_json(200, {
                "user_id": "user_alice_01",
                "email": "alice@example.com",
                "name": "Alice Smith",
                "role": "member",
            })
            return

        if path == "/api/v1/documents/doc_alice_99":
            # Secure: checks ownership and returns 403 Forbidden for Bob
            if "role_b" in auth_header or "bob" in auth_header.lower():
                self._send_json(403, {"error": "Forbidden: Access Denied to document doc_alice_99"})
                return
            self._send_json(200, {"doc_id": "doc_alice_99", "title": "Alice Private Diary"})
            return

        # 2. BFLA secure control
        if path == "/api/v1/admin/export_audit_log":
            if "admin" not in auth_header.lower():
                self._send_json(403, {"error": "Admin privilege required"})
                return
            self._send_json(200, {"audit_log": ["event 1", "event 2"]})
            return

        # 4. Auth & session boundaries
        if path == "/api/v1/internal/telemetry/metrics":
            # Vulnerable: missing auth check on internal telemetry
            self._send_json(200, {
                "jvm_memory_used": "512MB",
                "internal_ip": "10.0.4.12",
                "status": "healthy",
            })
            return

        if path == "/api/v1/dashboard":
            # Secure: requires authentication
            if not auth_header:
                self._send_json(401, {"error": "Unauthorized: Authentication required"})
                return
            self._send_json(200, {"dashboard": "Welcome user"})
            return

        # 5. Multi-tenant
        if path == "/api/v1/organizations/tenant_a_corp/invoices":
            # Vulnerable: Tenant B reads Tenant A's invoices
            self._send_json(200, {
                "organization": "tenant_a_corp",
                "invoice_total": "$14,500.00",
                "status": "paid",
            })
            return

        if path == "/api/v1/organizations/tenant_a_corp/repos":
            # Secure: tenant isolation enforced
            if "tenant_b" in auth_header:
                self._send_json(403, {"error": "Not authorized for organization tenant_a_corp"})
                return
            self._send_json(200, {"repos": ["secret-app"]})
            return

        # 7. Injection
        if path == "/api/v1/search":
            qs = parse_qs(parts.query)
            q = qs.get("q", [""])[0]
            if "'" in q or "--" in q or "OR 1=1" in q:
                # Vulnerable SQL error reflection
                self._send_json(200, {
                    "error": "SQL syntax error near '' OR 1=1--': sqlite_master query failed",
                    "raw_query": f"SELECT * FROM items WHERE name LIKE '%{q}%'",
                })
                return
            self._send_json(200, {"items": ["item1", "item2"]})
            return

        if path == "/api/v1/catalog":
            # Secure parameterized query
            self._send_json(200, {"results": [], "message": "No items matching query"})
            return

        # 8. Sensitive Info Exposure
        if path == "/.env":
            # Vulnerable exposed environment dotfile
            self._send_text(200, "DB_PASSWORD=super_secret_db_pass_123\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")
            return

        if path == "/api/v1/secure/.env":
            self._send_text(404, "Not Found")
            return

        # 9. Misconfiguration / CORS
        if path == "/api/v1/user/account":
            if origin_header:
                # Vulnerable reflective CORS with credentials
                headers = {
                    "Access-Control-Allow-Origin": origin_header,
                    "Access-Control-Allow-Credentials": "true",
                }
                self._send_json(200, {"account_id": "acc-123", "balance": 450.0}, headers=headers)
                return
            self._send_json(200, {"account_id": "acc-123", "balance": 450.0})
            return

        if path == "/api/v1/secure_user/account":
            # Secure CORS: strict allowlist
            headers = {
                "Access-Control-Allow-Origin": "https://trusted-app.com",
            }
            self._send_json(200, {"account_id": "acc-123"}, headers=headers)
            return

        # 10. Vulnerable component
        if path == "/struts-action.action":
            headers = {
                "Server": "Apache-Coyote/1.1",
                "X-Powered-By": "Struts 2.5.10",
            }
            self._send_text(200, "Struts Welcome Page", headers=headers)
            return

        # Ambiguous cases
        if path == "/api/v1/directory/alice":
            self._send_json(200, {"name": "Alice Smith", "public_directory": True, "department": "Security"})
            return

        if path == "/api/v1/items/invalid_param":
            self._send_text(500, "Internal Server Error: ValueError: invalid literal for int() with base 10: 'invalid_param'")
            return

        if path == "/static/logo.png":
            self._send_text(200, "PNG_BINARY_BYTES", headers={"Content-Type": "image/png"})
            return

        # Default fallback
        self._send_json(404, {"error": f"Endpoint {path} not found"})

    def do_POST(self):
        parts = urlsplit(self.path)
        path = parts.path
        auth_header = self.headers.get("Authorization", "")
        content_len = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_len) if content_len > 0 else b""

        # BFLA delete
        if path == "/api/v1/admin/users/user_target_42/delete":
            # Vulnerable: member role can invoke admin deletion
            self._send_json(200, {
                "user_deleted": "user_target_42",
                "success": True,
                "executor": "role_member",
            })
            return

        # Property / Mass assignment
        if path == "/api/v1/account/update":
            try:
                payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except Exception:
                payload = {}
            # Vulnerable: binds role properties directly
            resp = {"updated": True, "name": payload.get("name", "User")}
            if "role" in payload:
                resp["role"] = payload["role"]
            if "is_admin" in payload:
                resp["is_admin"] = payload["is_admin"]
            self._send_json(200, resp)
            return

        # Business logic bypass
        if path == "/api/v1/subscription/activate_license":
            # Vulnerable: directly activates enterprise license
            self._send_json(200, {
                "status": "active",
                "tier": "enterprise",
                "license_key": "ENT-999-ACTIVE",
            })
            return

        self._send_json(404, {"error": "Not Found"})


class LocalBenchmarkServer:
    """Thread-safe runner for the controlled in-process local benchmark HTTP server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.server = HTTPServer((host, port), BenchmarkAppHandler)
        self.host, self.port = self.server.server_address
        self.base_url = f"http://{self.host}:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=2.0)
