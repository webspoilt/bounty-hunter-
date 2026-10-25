"""Stateful authorization scenarios: a sequence of dependent requests, not one replay.

A scenario creates or selects an object as the owner (role A), then has the attacker
(role B) read or mutate it, then verifies the observable result. Every step is an
explicit request through `ScopedClient`; every verdict is deterministic.

Safety:
  * any non-GET/HEAD step requires `--allow-write` (creation, mutation, cleanup);
  * the scenario's base URL and every step are scope-checked by the client;
  * cleanup runs only when writes are allowed and only against resources the scenario
    created itself; use disposable test accounts.

Supported claims:
  idor_read   step returns 2xx, contains the owner's identity, not the attacker's
  idor_write  mutate step returns 2xx and the owner's verify step observes the marker
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from bb.config import now_iso
from bb.http import ScopedClient
from bb.models import Evidence, Exchange, Finding
from bb.scope import Scope
from bb.session import Role, login_roles
from bb.store import Store

PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CLAIM_TYPES = {"idor_read", "idor_write"}


class ScenarioError(RuntimeError):
    pass


@dataclass
class StepResult:
    step: dict
    role: str
    response: object | None = None
    exchange: Exchange | None = None
    ok: bool = True
    failures: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def status(self) -> int:
        return getattr(self.response, "status_code", 0) or 0

    @property
    def body(self) -> str:
        try:
            return self.response.text or ""  # type: ignore[union-attr]
        except Exception:
            return ""


def load_scenario(path: str | Path) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise ScenarioError(f"scenario not found: {p}")
    text = p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise ScenarioError("YAML scenario needs PyYAML; use JSON or "
                                "`pip install pyyaml`") from exc
        data = yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ScenarioError(f"invalid scenario JSON: {exc}") from exc
    validate_scenario(data)
    return data


def validate_scenario(data: dict) -> None:
    if not isinstance(data, dict):
        raise ScenarioError("scenario must be a JSON object")
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ScenarioError("scenario needs a non-empty steps[] list")
    ids = set()
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ScenarioError(f"steps[{i}] must be an object")
        if step.get("role") not in ("A", "B"):
            raise ScenarioError(f"steps[{i}].role must be 'A' or 'B'")
        method = str(step.get("method") or "GET").upper()
        if method not in SAFE_METHODS | WRITE_METHODS:
            raise ScenarioError(f"steps[{i}].method {method!r} not supported")
        if not (step.get("path") or step.get("url")):
            raise ScenarioError(f"steps[{i}] needs path or url")
        sid = step.get("id")
        if sid is not None:
            if sid in ids:
                raise ScenarioError(f"duplicate step id {sid!r}")
            ids.add(sid)
    claim = data.get("claim")
    if claim is not None:
        if not isinstance(claim, dict) or claim.get("type") not in CLAIM_TYPES:
            raise ScenarioError(f"claim.type must be one of {CLAIM_TYPES}")
        required = ("step",) if claim["type"] == "idor_read" else ("mutate", "verify")
        for key in required:
            if claim.get(key) not in ids:
                raise ScenarioError(f"claim.{key} must reference a step id")
        if claim.get("owner", "A") not in ("A", "B") or \
                claim.get("attacker", "B") not in ("A", "B"):
            raise ScenarioError("claim.owner/attacker must be 'A' or 'B'")


# ---------- substitution and extraction ----------

def substitute(value, variables: dict, *, strict: bool = True):
    if isinstance(value, str):
        whole = PLACEHOLDER.fullmatch(value.strip())
        if whole:
            key = whole.group(1)
            if key in variables:
                return variables[key]
            if strict:
                raise ScenarioError(f"unresolved placeholder ${{{key}}}")
            return value
        def repl(match: re.Match) -> str:
            key = match.group(1)
            if key in variables:
                return str(variables[key])
            if strict:
                raise ScenarioError(f"unresolved placeholder ${{{key}}}")
            return match.group(0)
        return PLACEHOLDER.sub(repl, value)
    if isinstance(value, dict):
        return {k: substitute(v, variables, strict=strict) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables, strict=strict) for v in value]
    return value


def dig_json(obj, path: str):
    p = (path or "").strip()
    if p.startswith("$"):
        p = p[1:]
    if p.startswith("."):
        p = p[1:]
    if not p:
        return obj
    current = obj
    for part in p.split("."):
        match = re.fullmatch(r"([^\[\]]*)(?:\[(\d+)\])?", part)
        if not match:
            return None
        name, index = match.group(1), match.group(2)
        if name:
            if not isinstance(current, dict) or name not in current:
                return None
            current = current[name]
        if index is not None:
            if not isinstance(current, list):
                return None
            i = int(index)
            if i >= len(current):
                return None
            current = current[i]
    return current


def _check_expect(step: dict, resp, variables: dict) -> list[str]:
    expect = step.get("expect") or {}
    failures: list[str] = []
    if "status" in expect:
        allowed = expect["status"] if isinstance(expect["status"], list) else [expect["status"]]
        if getattr(resp, "status_code", 0) not in allowed:
            failures.append(f"status {getattr(resp, 'status_code', 0)} not in {allowed}")
    body = ""
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    for needle in expect.get("body_contains") or []:
        resolved = str(substitute(needle, variables))
        if resolved not in body:
            failures.append(f"body missing {resolved!r}")
    for needle in expect.get("body_not_contains") or []:
        resolved = str(substitute(needle, variables))
        if resolved in body:
            failures.append(f"body unexpectedly contains {resolved!r}")
    return failures


# ---------- claims ----------

def evaluate_claim(claim: dict, results: dict[str, StepResult], roles: dict[str, Role],
                   variables: dict) -> tuple[str, str]:
    """Return (verdict, explanation)."""
    if claim["type"] == "idor_read":
        result = results.get(claim["step"])
        if not result or not result.response:
            return "inconclusive", "claim step did not run"
        status = result.status
        if status in (401, 402, 403, 404):
            return "enforced", f"attacker received HTTP {status}"
        if not 200 <= status < 300:
            return "inconclusive", f"attacker received HTTP {status}"
        owner = roles.get(claim.get("owner", "A"))
        attacker = roles.get(claim.get("attacker", "B"))
        body = result.body
        if not owner or not owner.identity:
            return "inconclusive", "owner identity is unknown; pass identity in the accounts file"
        if owner.identity not in body:
            return "inconclusive", "owner identity absent from the attacker's response"
        if attacker and attacker.identity and attacker.identity in body:
            return "inconclusive", "attacker's own identity is in the response (self-object)"
        return "confirmed", (f"attacker HTTP {status} with owner identity "
                             f"{owner.identity!r} and no attacker identity")
    # idor_write
    mutate = results.get(claim["mutate"])
    verify = results.get(claim["verify"])
    if not mutate or not verify or not mutate.response or not verify.response:
        return "inconclusive", "mutate/verify step did not run"
    if mutate.status in (401, 402, 403, 404):
        return "enforced", f"mutation denied with HTTP {mutate.status}"
    if not 200 <= mutate.status < 300:
        return "inconclusive", f"mutation returned HTTP {mutate.status}"
    marker = str(substitute(claim.get("marker", "${marker}"), variables))
    if verify.status in (401, 403, 404):
        return "inconclusive", f"owner verification returned HTTP {verify.status}"
    if marker and marker in verify.body:
        return "confirmed", f"owner observed attacker marker {marker!r}"
    return "inconclusive", "owner did not observe the attacker's marker"


# ---------- runner ----------

def _find_step(steps: list[dict], sid: str) -> int:
    for i, step in enumerate(steps):
        if step.get("id") == sid:
            return i
    raise ScenarioError(f"no step with id {sid!r}")


def run_scenario(scenario: dict, *, scope: Scope, accounts: dict, program: str,
                 store: Store, allow_write: bool = False, dry_run: bool = False,
                 proxy: str | None = None, transport=None, llm: bool = False,
                 queue: bool = True, log=print) -> dict:
    validate_scenario(scenario)
    base_url = scenario.get("base_url") or accounts.get("base_url")
    if not base_url:
        raise ScenarioError("scenario or accounts file needs base_url")
    if not scope.is_in_scope(base_url):
        raise ScenarioError(f"base_url {base_url} is out of scope for {program}")

    if not dry_run:
        for step in scenario["steps"]:
            if str(step.get("method") or "GET").upper() in WRITE_METHODS and not allow_write:
                raise ScenarioError(
                    f"step {step.get('id')!r} uses {step.get('method')}; rerun with "
                    "--allow-write (disposable resources, program policy permitting)")

    run_id = store.start_run(program, base_url, scope.fingerprint,
                             {"source": "scenario", "scenario": scenario.get("name", "")})
    client = ScopedClient(scope, base_url=base_url, proxy=proxy,
                          rate=float(scenario.get("rate", 3.0)), dry_run=dry_run,
                          store=store, run_id=run_id, tool="scenario", transport=transport)
    verdict = "inconclusive"
    finding: Finding | None = None
    results: dict[str, StepResult] = {}
    variables: dict = {}
    role_map: dict[str, Role] = {}
    try:
        if dry_run:
            roles = [Role(label=acc.get("label", f"role{i}"), email=acc.get("email", ""),
                          identity=acc.get("identity") or acc.get("email", ""), user_id=i + 1)
                     for i, acc in enumerate((accounts.get("accounts") or [])[:2])]
            log("  [scenario] dry-run: login skipped")
        else:
            roles = login_roles(client, accounts, log=log)
        role_map = {"A": roles[0], "B": roles[1]}
        variables = {
            "A.email": roles[0].email, "A.id": roles[0].user_id, "A.identity": roles[0].identity,
            "B.email": roles[1].email, "B.id": roles[1].user_id, "B.identity": roles[1].identity,
            "run_id": run_id, "marker": f"bb-{run_id}",
        }

        for step in scenario["steps"]:
            sid = step.get("id") or f"step{len(results) + 1}"
            method = str(step.get("method") or "GET").upper()
            role = role_map[step["role"]]
            path = substitute(step.get("path") or step.get("url"), variables,
                              strict=not dry_run)
            headers = dict(role.headers)
            headers.update(substitute(step.get("headers") or {}, variables,
                                      strict=not dry_run))
            json_body = substitute(step.get("json"), variables,
                                   strict=not dry_run) if "json" in step else None
            data_body = substitute(step.get("data"), variables,
                                   strict=not dry_run) if "data" in step else None
            params = substitute(step.get("params"), variables,
                                strict=not dry_run) if "params" in step else None

            if dry_run:
                client.request(method, path, headers=headers, json=json_body,
                               data=data_body, params=params)
                log(f"  [plan] {step['role']} {method} {client.resolve(path)}")
                results[sid] = StepResult(step=step, role=step["role"], ok=True)
                continue

            try:
                resp = client.request(method, path, headers=headers, json=json_body,
                                      data=data_body, params=params)
            except Exception as exc:
                results[sid] = StepResult(step=step, role=step["role"], ok=False,
                                          error=str(exc))
                log(f"  [step] {sid}: {step['role']} {method} {path} -> ERROR {exc}")
                break

            ex = client.last_exchange
            failures = _check_expect(step, resp, variables)
            result = StepResult(step=step, role=step["role"], response=resp, exchange=ex,
                                ok=not failures, failures=failures)
            results[sid] = result
            log(f"  [step] {sid}: {step['role']} {method} {path} -> {resp.status_code}"
                + (f"  ! {'; '.join(failures)}" if failures else ""))
            if failures and not step.get("continue_on_failure"):
                break

            for name, path_expr in (step.get("extract") or {}).items():
                try:
                    value = dig_json(resp.json(), path_expr)
                except Exception:
                    value = None
                if value is None:
                    result.ok = False
                    result.failures.append(f"extract {name} from {path_expr} failed")
                    log(f"  [step] {sid}: extraction {name} failed")
                    break
                variables[name] = value
                variables[f"{sid}.{name}"] = value

        if dry_run:
            verdict = "dry-run"
            return {"run_id": run_id, "verdict": verdict, "finding": None,
                    "steps": results, "planned": list(client.planned)}
        if all(r.ok for r in results.values()):
            if scenario.get("claim"):
                verdict, why = evaluate_claim(scenario["claim"], results, role_map, variables)
                log(f"  [claim] {scenario['claim']['type']} -> {verdict}: {why}")
                if verdict == "confirmed":
                    finding = _build_finding(scenario, results, role_map, verdict, why,
                                             program, scope, run_id)
                    store.add_finding(finding, run_id)
                    from bb.pipeline import finalize_findings
                    finalize_findings([finding], program=program, scope=scope, store=store,
                                      llm=llm, queue=queue, log=log)
            else:
                verdict = "observed"
                log("  [scenario] no claim: steps completed, results are observational")
        elif scenario.get("claim"):
            verdict = "inconclusive"
            log("  [claim] skipped: a step failed")

    finally:
        if allow_write and not dry_run and scenario.get("cleanup") and role_map:
            _cleanup(client, scenario["cleanup"], variables, role_map, log)
        client.close()
        store.finish_run(run_id, {"verdict": verdict,
                                  "finding": finding.id if finding else None})
    return {"run_id": run_id, "verdict": verdict, "finding": finding,
            "steps": results, "requests": client.sent}


def _cleanup(client: ScopedClient, steps: list[dict], variables: dict,
             role_map: dict[str, Role], log) -> None:
    for step in steps:
        if not isinstance(step, dict):
            continue
        method = str(step.get("method") or "DELETE").upper()
        if method not in WRITE_METHODS:
            continue
        try:
            path = substitute(step.get("path") or step.get("url"), variables, strict=True)
            role = role_map.get(step.get("role", "A"), role_map.get("A"))
            headers = dict(role.headers) if role else {}
            headers.update(substitute(step.get("headers") or {}, variables, strict=True))
            client.request(method, path, json=substitute(step.get("json"), variables)
                           if "json" in step else None, headers=headers)
            log(f"  [cleanup] {step.get('role', 'A')} {method} {path}")
        except Exception as exc:
            log(f"  [cleanup] skipped: {exc}")


def _build_finding(scenario: dict, results: dict[str, StepResult], roles: dict[str, Role],
                   verdict: str, why: str, program: str, scope: Scope,
                   run_id: str) -> Finding:
    claim = scenario["claim"]
    if claim["type"] == "idor_read":
        attack = results[claim["step"]]
        owner_step = results.get(claim.get("owner_step", "")) if claim.get("owner_step") else None
        verb = "read"
    else:
        attack = results[claim["mutate"]]
        owner_step = results.get(claim["verify"])
        verb = "write"
    url = attack.step.get("path") or attack.step.get("url")
    try:
        url = attack.exchange.url if attack.exchange else url
    except Exception:
        pass
    host = urlsplit(url).hostname or ""
    owner = roles.get(claim.get("owner", "A"))
    attacker = roles.get(claim.get("attacker", "B"))
    title = scenario.get("title") or (
        f"Broken object-level authorization: {attacker.label} can {verb} "
        f"{owner.label}'s object at {urlsplit(url).path}")
    summary = scenario.get("summary") or (
        f"{why}. The scenario created or selected an object as {owner.label}, then "
        f"replayed an operation as {attacker.label}; the result crosses the ownership "
        f"boundary.")
    evidence = []
    for label, result in (("owner baseline", owner_step), ("attacker", attack)):
        if result and result.exchange:
            evidence.append(Evidence(f"{label}: {result.role} {result.step.get('method', 'GET')} "
                                     f"{urlsplit(result.exchange.url).path} -> {result.status}",
                                     result.exchange))
    if claim["type"] == "idor_write":
        verify = results[claim["verify"]]
        if verify.exchange:
            evidence.append(Evidence(f"owner verification: {verify.role} -> {verify.status}",
                                     verify.exchange))
    steps = [f"{r.role} {r.step.get('method', 'GET')} "
             f"{r.step.get('path') or r.step.get('url')} -> {r.status}"
             for r in results.values() if r.response]
    return Finding(
        title=title, bug_class="IDOR", severity=scenario.get("severity", "high"),
        confidence="high", host=host, url=url,
        summary=summary,
        impact=scenario.get("impact") or (
            "An authenticated user can " + ("modify" if verb == "write" else "read") +
            " another user's object by changing its identifier."),
        remediation=scenario.get("remediation") or (
            "Enforce an object-owner/tenant check on the resolution layer for every "
            "operation, and verify the state change, not just the route."),
        steps=steps, evidence=evidence,
        meta={"program": program, "scenario": scenario.get("name", ""),
              "claim": claim, "scope_fingerprint": scope.fingerprint, "run_id": run_id},
    )
