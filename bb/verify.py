"""Independent verification of candidate findings.

The pipeline reports; the verifier's only job is to try to DISPROVE a candidate before
a human wastes time on it (and before anything reaches HackerOne). Two layers:

  1. Offline evidence audit (always, deterministic): re-read the finding's own evidence
     and meta and check the claim is internally consistent — attacker responses must
     contain the owner's identity and not the attacker's, redirect evidence must contain
     the marker, a "2xx" evidence exchange must actually be 2xx. A high-confidence claim
     that contradicts its own evidence gets rejected outright.

  2. Online re-verification (opt-in, --accounts): log in fresh, replay the finding's URL
     with both roles, and check whether the behavior still reproduces. Confirmed
     reproductions append fresh evidence and raise the status to `confirmed`.
     Enforced boundaries (401/403 now) mark the finding `rejected`.

The verify step never queues, never reports, never submits: its output is a status
change plus notes in `finding.meta["verify"]`.
"""
from __future__ import annotations

from bb.checks import similarity
from bb.models import Evidence
from bb.scope import Scope


VERIFIER_BUG_CLASSES = ("IDOR", "Broken Authentication")


def audit_offline(finding) -> dict:
    """Rule-based audit of the finding's own evidence. No network, no model.

    Returns {"verdict": "consistent"|"contradicted"|"uncertain", "issues": [...]}.
    Only `contradicted` on a confidence=high finding flips the status.
    """
    issues: list[str] = []
    cls = finding.bug_class
    meta = finding.meta

    if cls == "IDOR":
        if len(finding.evidence) < 2:
            issues.append("IDOR claim without two-role evidence (owner + attacker exchanges)")
        else:
            owner = finding.evidence[-2].exchange
            attacker = finding.evidence[-1].exchange
            if attacker is None:
                issues.append("attacker evidence exchange is missing")
            else:
                body = attacker.response_body or ""
                if not (200 <= attacker.status < 300):
                    issues.append(f"attacker evidence is HTTP {attacker.status}, "
                                  "not a successful cross-role read")
                id_a, id_b = meta.get("identity_a"), meta.get("identity_b")
                if id_b and id_b in body:
                    issues.append("attacker response contains the attacker's own identity "
                                  "— ownership transfer not proven")
                if meta.get("confidence_marker") is None and id_a and id_a not in body:
                    issues.append(f"attacker response does not contain {id_a!r} "
                                  "(owner identity absent from evidence)")
                if len(body) < 32:
                    issues.append("attacker response body is nearly empty (generic page?)")
    elif cls == "Broken Authentication":
        ev = next((e for e in finding.evidence if e.exchange is not None), None)
        if ev is None:
            issues.append("no evidence exchange captured")
        else:
            body = ev.exchange.response_body or ""
            if not (200 <= ev.exchange.status < 300):
                issues.append(f"evidence is HTTP {ev.exchange.status}, not anonymous success")
            ident = meta.get("identity") or (meta.get("identity_a"))
            if not (_has_pii(body) or (ident and ident in body)):
                issues.append("anonymous response contains neither PII nor the "
                              "authenticated identity — likely a public page")
    elif cls == "Open Redirect":
        if meta.get("location") and "bb-oob.invalid" not in (meta.get("location") or ""):
            issues.append("recorded Location does not contain the probe marker")
    elif cls == "CORS":
        acao = meta.get("acao") or ""
        probe = meta.get("probe") or ""
        if acao and probe and acao != probe and not (acao == "*" and meta.get("acac")):
            issues.append("recorded ACAO neither reflects the probe nor *+credentials")
    elif cls in ("Information Disclosure", "GraphQL", "Security Misconfiguration"):
        for ev in finding.evidence:
            if ev.exchange is not None and not (200 <= ev.exchange.status < 300):
                issues.append(f"evidence exchange is HTTP {ev.exchange.status}")
                break

    # a finding that moved programs (scope changed between import and report)
    if meta.get("scope_fingerprint") and finding.meta.get("_current_scope_fingerprint"):
        if meta["scope_fingerprint"] != meta["_current_scope_fingerprint"]:
            issues.append("scope fingerprint changed since the finding was recorded — "
                          "confirm the host is still in scope")

    if issues and (finding.confidence == "high"):
        return {"verdict": "contradicted", "issues": issues}
    if issues:
        return {"verdict": "uncertain", "issues": issues}
    return {"verdict": "consistent", "issues": []}


def _role_lookup(roles, identity: str):
    for r in roles:
        if identity and r.identity and r.identity == identity:
            return r
    return None


def verify_online(finding, client, roles: list) -> dict:
    """Replay the finding against a live target with fresh sessions.

    Returns {"verdict": "reproduced"|"enforced"|"inconclusive", "note": str}.
    Appends new evidence on a reproduction; never mutates status here.
    """
    url = finding.url
    if not url or "{" in url:
        return {"verdict": "inconclusive", "note": "no concrete URL to replay"}

    try:
        if finding.bug_class == "Broken Authentication":
            return _reverify_unauth(finding, client, roles)
        return _reverify_idor(finding, client, roles)
    except Exception as exc:                     # noqa: BLE001 — verify must not explode runs
        return {"verdict": "inconclusive", "note": f"verification error: {exc}"}


def _reverify_idor(finding, client, roles) -> dict:
    if len(roles) < 2:
        return {"verdict": "inconclusive", "note": "need two roles for IDOR re-verification"}
    id_a = finding.meta.get("identity_a")
    id_b = finding.meta.get("identity_b")
    role_a = _role_lookup(roles, id_a) or roles[0]
    role_b = _role_lookup(roles, id_b) or (roles[1] if role_a is not roles[1] else roles[0])
    try:
        r_owner = client.get(finding.url, headers=role_a.headers)
        r_atk = client.get(finding.url, headers=role_b.headers)
    except Exception as exc:                     # noqa: BLE001
        return {"verdict": "inconclusive", "note": f"requests failed: {exc}"}
    a_text, b_text = _text(r_owner), _text(r_atk)
    sim = similarity(a_text, b_text)
    note = (f"{role_b.label} -> HTTP {r_atk.status_code}, similarity {sim:.0%}, "
            f"owner identity present: {bool(id_a and id_a in b_text)}")
    if 200 <= r_atk.status_code < 300 and sim >= 0.8 and id_a and id_a in b_text \
            and not (id_b and id_b in b_text):
        ex = client.last_exchange
        finding.evidence.append(Evidence(
            f"re-verification: {role_b.label} replay reproduced {r_atk.status_code}", ex))
        return {"verdict": "reproduced", "note": note}
    if r_atk.status_code in (401, 403):
        finding.meta["verify_note"] = "boundary now enforced on replay"
        return {"verdict": "enforced", "note": note}
    return {"verdict": "inconclusive", "note": note}


def _reverify_unauth(finding, client, roles) -> dict:
    ident = finding.meta.get("identity") or finding.meta.get("identity_a")
    role_a = None
    if ident:
        role_a = _role_lookup(roles, ident)
    try:
        r_anon = client.get(finding.url)
    except Exception as exc:                     # noqa: BLE001
        return {"verdict": "inconclusive", "note": f"anonymous request failed: {exc}"}
    n_text = _text(r_anon)
    note = f"anonymous replay -> HTTP {r_anon.status_code}"
    if 200 <= r_anon.status_code < 300 and (_has_pii(n_text) or (ident and ident in n_text)):
        ex = client.last_exchange
        finding.evidence.append(Evidence("re-verification: anonymous replay reproduced", ex))
        return {"verdict": "reproduced", "note": note}
    if r_anon.status_code in (401, 403):
        finding.meta["verify_note"] = "endpoint now requires authentication"
        return {"verdict": "enforced", "note": note}
    return {"verdict": "inconclusive", "note": note}


def run_verification(finding, scope: Scope, client=None, roles: list | None = None) -> dict:
    """Audit + (optionally) replay one finding. Applies the status change and notes."""
    audit = audit_offline(finding)
    result = {"offline": audit["verdict"], "issues": audit["issues"],
              "online": None, "status_before": finding.status}
    if finding.meta.get("_current_scope_fingerprint") is None and scope is not None:
        # audit_offline compares live scope vs recorded scope when we can
        finding.meta["_current_scope_fingerprint"] = scope.fingerprint
        recheck = audit_offline(finding)
        if recheck["issues"] and "scope fingerprint" in recheck["issues"][-1]:
            audit = recheck
            result["offline"], result["issues"] = recheck["verdict"], recheck["issues"]

    online_verdict = None
    if client is not None and roles and finding.bug_class in VERIFIER_BUG_CLASSES:
        online = verify_online(finding, client, roles)
        online_verdict = online["verdict"]
        result["online"] = online["verdict"]
        result["online_note"] = online["note"]

    notes = []
    if online_verdict == "reproduced":
        finding.status = "confirmed"
        finding.confidence = "high"
        notes.append("online re-verification reproduced the finding")
    elif online_verdict == "enforced" or (online_verdict is None
                                          and audit["verdict"] == "contradicted"):
        finding.status = "rejected"
        notes.append("verification could not reproduce the claim")
    if audit["issues"]:
        notes.extend(f"evidence: {i}" for i in audit["issues"])
    result["status_after"] = finding.status
    finding.meta["verify"] = {
        "offline": audit["verdict"], "issues": audit["issues"],
        "online": online_verdict, "notes": notes}
    return result


# ---------- batch driver ----------

def verify_candidates(store, scope: Scope, program: str, *, accounts: dict | None = None,
                      client=None, finding_id: str | None = None,
                      log=print) -> dict:
    """Verify candidate findings for a program (one finding or every candidate)."""
    candidates = _program_candidates(store, program)
    if finding_id:
        target = store.get_finding(finding_id)
        if target is None:
            raise KeyError(f"no finding matching {finding_id!r}")
        candidates = [f for f in candidates if f.id == target.id] or [target]
    if not candidates:
        log("no candidate findings to verify")
        return {"verified": 0, "confirmed": 0, "rejected": 0, "kept": 0}

    roles: list = []
    if accounts and client is not None:
        from bb.session import login_roles
        roles = login_roles(client, accounts, log=log)
        log(f"  [verify] logged in {len(roles)} role(s) for online re-verification")

    summary = {"verified": 0, "confirmed": 0, "rejected": 0, "kept": 0}
    for finding in candidates:
        result = run_verification(finding, scope,
                                  client=client if roles and accounts else None,
                                  roles=roles)
        summary["verified"] += 1
        store.add_finding(finding)
        status = finding.status
        if status == "confirmed":
            summary["confirmed"] += 1
        elif status == "rejected":
            summary["rejected"] += 1
        else:
            summary["kept"] += 1
        detail = result.get("online_note") or "; ".join(result["issues"][:2]) or "consistent"
        log(f"  [verify] {finding.id} [{finding.bug_class}] -> {status} ({detail})")
    return summary


def _program_candidates(store, program: str) -> list:
    run_ids = [r["id"] for r in store.conn.execute(
        "SELECT id FROM runs WHERE program=?", (program,)).fetchall()]
    out = []
    for run_id in run_ids:
        out += store.findings(status="candidate", run_id=run_id)
    # also candidates recorded before runs existed (meta carries the program)
    out += [f for f in store.findings(status="candidate")
            if f.meta.get("program") == program and f not in out]
    # deterministic order: newest first, like findings()
    out.sort(key=lambda f: f.created_at, reverse=True)
    return out


# ---------- small helpers (avoid importing privates twice) ----------

def _text(resp) -> str:
    try:
        return resp.text or ""
    except Exception:
        return ""


def _has_pii(text: str) -> bool:
    from bb.checks import PII_RE, TOKEN_KEYS
    if PII_RE.search(text or ""):
        return True
    low = (text or "").lower()
    return any(f'"{k.lower()}"' in low for k in TOKEN_KEYS)
