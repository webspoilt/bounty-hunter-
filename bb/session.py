"""Two-role sessions: log in twice, keep the credentials, know who each role is.

Identity matters for authz proof: a finding is only real if role B is shown data that
belongs to role A (B's own email is absent, A's marker is present).
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from bb.http import ScopedClient


@dataclass
class Role:
    label: str
    email: str = ""
    identity: str = ""                 # marker used to prove ownership
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    claims: dict = field(default_factory=dict)
    user_id: str | int | None = None

    def as_dict(self) -> dict:
        return {"label": self.label, "email": self.email, "identity": self.identity,
                "user_id": self.user_id}


def load_accounts(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not data.get("accounts"):
        raise ValueError(f"{path}: no accounts[] — need at least two roles")
    return data


def _password(acc: dict) -> str:
    if acc.get("password"):
        return str(acc["password"])
    env = acc.get("password_env")
    if env:
        val = os.environ.get(env)
        if not val:
            raise RuntimeError(f"account {acc.get('label')!r}: env var {env} is empty")
        return val
    raise RuntimeError(f"account {acc.get('label')!r}: need 'password' or 'password_env'")


def _jwt_claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _dig(obj, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _expand(value, email: str, password: str):
    """Substitute ${email} / ${password} in register extras (e.g. passwordRepeat)."""
    if isinstance(value, str):
        return value.replace("${email}", email).replace("${password}", password)
    if isinstance(value, dict):
        return {k: _expand(v, email, password) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, email, password) for v in value]
    return value


def login_roles(client: ScopedClient, config: dict, log=print) -> list[Role]:
    """One login per account. Per-account overrides are respected (no shared login_path bug)."""
    roles: list[Role] = []
    base_cfg = config.get("login") or {}
    for i, acc in enumerate(config["accounts"]):
        login = {**base_cfg, **(acc.get("login") or {})}
        login_path = login.get("path") or "/login"
        body_keys = login.get("body_keys") or {"email": "email", "password": "password"}
        token_field = login.get("token_field") or "token"
        email = acc.get("email", "")

        register_path = login.get("register_path") or acc.get("register_path")
        if register_path:
            body = {body_keys["email"]: email, body_keys["password"]: _password(acc)}
            extra = login.get("register_extra") or {}
            body.update(_expand(extra, email, _password(acc)))
            try:
                reg = client.post(register_path, json=body)
                if reg.status_code >= 400 and reg.status_code not in (409, 422):
                    log(f"  [register] {email}: HTTP {reg.status_code} (continuing to login)")
            except Exception as exc:
                log(f"  [register] {email}: {exc} (continuing to login)")

        body = {body_keys["email"]: email, body_keys["password"]: _password(acc)}
        resp = client.post(login_path, json=body)
        token = ""
        if resp.status_code < 400:
            try:
                token = _dig(resp.json(), token_field) or ""
            except Exception:
                token = ""
        if not token:
            cookie_header = resp.headers.get("set-cookie", "")
            if resp.status_code < 400 and cookie_header:
                role = Role(label=acc.get("label", f"role{i}"), email=email,
                            identity=acc.get("identity") or email,
                            cookies=dict(resp.cookies))
                roles.append(role)
                log(f"  [login] {role.label} via cookies ({email})")
                continue
            raise RuntimeError(
                f"role {acc.get('label', f'role{i}')} login failed: HTTP {resp.status_code} "
                f"on {login_path} — {resp.text[:200]}")

        claims = _jwt_claims(token) if token.count(".") == 2 else {}
        data_claims = claims.get("data") if isinstance(claims.get("data"), dict) else claims
        identity = (acc.get("identity") or data_claims.get("email") or email)
        role = Role(
            label=acc.get("label", f"role{i}"),
            email=email,
            identity=identity,
            headers={"Authorization": f"Bearer {token}"},
            claims=claims,
            user_id=data_claims.get("id") or data_claims.get("sub") or data_claims.get("user_id"),
        )
        role.headers.update(acc.get("headers") or {})
        roles.append(role)
        log(f"  [login] {role.label} ({email}) id={role.user_id}")

    if len(roles) < 2:
        raise RuntimeError("need at least two roles for an authz test")
    return roles
