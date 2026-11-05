"""Stateful authorization scenarios: a sequence of dependent requests, not one replay.

Schema 1 (default) is unchanged: roles A and B, `idor_read` and `idor_write`.
Schema 2 (`"schema": 2`) adds:
  * a `roles` map with arbitrary labels (A=account 0 and B=account 1 remain valid);
  * `expect.json` assertions with dotted paths and matchers;
  * `denied_is_coverage` for steps where 401/402/403/404 is coverage, not failure;
  * the `state_change` claim, with optional second-role `owner_verify`.

Safety:
  * any non-GET/HEAD step requires `--allow-write`;
  * the scenario's base URL and every step are scope-checked by the client;
  * cleanup runs only when writes are allowed, in the listed order, and only against
    resources the scenario created itself; use disposable test accounts;
  * strict substitution is retained: a step whose variable is unresolved is skipped, never
    sent with a guessed id, and cleanup refuses to delete without a resolved path.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

from bb.http import ScopedClient
from bb.models import Evidence, Exchange, Finding
from bb.scope import Scope
from bb.session import Role, login_accounts
from bb.store import Store

PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DENIED_STATUSES = {401, 402, 403, 404}
CLAIM_TYPES = {"idor_read", "idor_write", "state_change"}
ROLE_FIELDS = ("email", "id", "identity")
LABEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,39}$")
EXTRACT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MATCHER_KEYS = {"equals", "not_equals", "contains", "one_of", "exists"}
SCHEMAS = (1, 2)


class ScenarioError(RuntimeError):
    pass


@dataclass
class StepResult:
    step: dict
    role: str
    response: object | None = None
    exchange: Exchange | None = None
    ok: bool = True
    coverage: bool = False
    skipped: bool = False
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


# ---------- validation ----------

def _role_defs(data: dict, schema: int) -> dict[str, dict]:
    defs: dict[str, dict] = {
        "A": {"account": 0, "headers": {}},
        "B": {"account": 1, "headers": {}},
    }
    roles = data.get("roles")
    if roles is None:
        return defs
    if schema != 2:
        raise ScenarioError("roles requires \"schema\": 2")
    if not isinstance(roles, dict) or not roles:
        raise ScenarioError("roles must be a non-empty object")
    for label, spec in roles.items():
        if not isinstance(label, str) or not LABEL_RE.fullmatch(label):
            raise ScenarioError(f"invalid role label {label!r}")
        if isinstance(spec, int) and not isinstance(spec, bool):
            spec = {"account": spec}
        if not isinstance(spec, dict) or "account" not in spec:
            raise ScenarioError(f"role {label!r} needs an account index")
        account = spec["account"]
        if not isinstance(account, int) or isinstance(account, bool) or account < 0:
            raise ScenarioError(f"role {label!r} account must be a non-negative integer")
        headers = spec.get("headers") or {}
        if not isinstance(headers, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
            raise ScenarioError(f"role {label!r} headers must be a string map")
        defs[label] = {"account": account, "headers": dict(headers)}
    return defs


def _validate_json_matcher(value, where: str) -> None:
    if isinstance(value, dict) and set(value) & MATCHER_KEYS:
        unknown = set(value) - MATCHER_KEYS
        if unknown:
            raise ScenarioError(f"{where}: unknown matcher(s) {sorted(unknown)}")
        if len(value) != 1:
            raise ScenarioError(f"{where}: use one matcher per assertion")
        key, expected = next(iter(value.items()))
        if key == "exists" and not isinstance(expected, bool):
            raise ScenarioError(f"{where}: exists must be true/false")
        if key == "one_of" and not isinstance(expected, list):
            raise ScenarioError(f"{where}: one_of must be a list")
        if key == "contains" and not isinstance(expected, (str, list, dict)):
            raise ScenarioError(f"{where}: contains must be a string, list, or object")


def _validate_expect(step: dict, schema: int, where: str) -> None:
    expect = step.get("expect")
    if expect is None:
        return
    if not isinstance(expect, dict):
        raise ScenarioError(f"{where}.expect must be an object")
    status = expect.get("status")
    if status is not None:
        values = status if isinstance(status, list) else [status]
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in values):
            raise ScenarioError(f"{where}.expect.status must be an integer or list")
    for key in ("body_contains", "body_not_contains"):
        values = expect.get(key)
        if values is not None and (not isinstance(values, list) or
                                   not all(isinstance(v, str) for v in values)):
            raise ScenarioError(f"{where}.expect.{key} must be a list of strings")
    if "json" in expect:
        if schema != 2:
            raise ScenarioError(f"{where}.expect.json requires \"schema\": 2")
        assertions = expect["json"]
        if not isinstance(assertions, dict) or not assertions:
            raise ScenarioError(f"{where}.expect.json must be a non-empty object")
        for path, expected in assertions.items():
            if not isinstance(path, str) or not path:
                raise ScenarioError(f"{where}.expect.json path must be a string")
            _validate_json_matcher(expected, f"{where}.expect.json[{path!r}]")


def _reserved_names(defs: dict[str, dict]) -> set[str]:
    reserved = {"run_id", "marker"}
    for label in defs:
        reserved |= {f"{label}.{field}" for field in ROLE_FIELDS}
    return reserved


def validate_scenario(data: dict) -> tuple[int, dict[str, dict]]:
    if not isinstance(data, dict):
        raise ScenarioError("scenario must be a JSON object")
    schema = data.get("schema", 1)
    if not isinstance(schema, int) or isinstance(schema, bool) or schema not in SCHEMAS:
        raise ScenarioError(f"schema must be one of {SCHEMAS}")
    defs = _role_defs(data, schema)

    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ScenarioError("scenario needs a non-empty steps[] list")
    ids: set[str] = set()
    reserved = _reserved_names(defs)
    for i, step in enumerate(steps):
        where = f"steps[{i}]"
        if not isinstance(step, dict):
            raise ScenarioError(f"{where} must be an object")
        if step.get("role") not in defs:
            raise ScenarioError(f"{where}.role must be one of {sorted(defs)}")
        method = str(step.get("method") or "GET").upper()
        if method not in SAFE_METHODS | WRITE_METHODS:
            raise ScenarioError(f"{where}.method {method!r} not supported")
        if not (step.get("path") or step.get("url")):
            raise ScenarioError(f"{where} needs path or url")
        sid = step.get("id")
        if sid is not None:
            if not isinstance(sid, str) or not LABEL_RE.fullmatch(sid):
                raise ScenarioError(f"{where}.id {sid!r} is invalid")
            if sid in ids:
                raise ScenarioError(f"duplicate step id {sid!r}")
            ids.add(sid)
        if "denied_is_coverage" in step:
            if schema != 2:
                raise ScenarioError(f"{where}.denied_is_coverage requires \"schema\": 2")
            if not isinstance(step["denied_is_coverage"], bool):
                raise ScenarioError(f"{where}.denied_is_coverage must be true/false")
        _validate_expect(step, schema, where)
        extract = step.get("extract")
        if extract is not None:
            if not isinstance(extract, dict):
                raise ScenarioError(f"{where}.extract must be an object")
            for name in extract:
                if not isinstance(name, str) or not EXTRACT_RE.fullmatch(name):
                    raise ScenarioError(f"{where}.extract name {name!r} is invalid")
                dotted = f"{sid}.{name}" if sid else name
                if name in reserved or dotted in reserved:
                    raise ScenarioError(
                        f"{where}.extract {name!r} collides with a reserved role variable")

    cleanup = data.get("cleanup")
    if cleanup is not None:
        if not isinstance(cleanup, list):
            raise ScenarioError("cleanup must be a list")
        for i, step in enumerate(cleanup):
            where = f"cleanup[{i}]"
            if not isinstance(step, dict):
                raise ScenarioError(f"{where} must be an object")
            if step.get("role") not in defs:
                raise ScenarioError(f"{where}.role must be one of {sorted(defs)}")
            if str(step.get("method") or "DELETE").upper() not in WRITE_METHODS:
                raise ScenarioError(f"{where}.method must be a write method")
            if not (step.get("path") or step.get("url")):
                raise ScenarioError(f"{where} needs path or url")
            if "ignore_failure" in step and not isinstance(step["ignore_failure"], bool):
                raise ScenarioError(f"{where}.ignore_failure must be true/false")

    claim = data.get("claim")
    if claim is not None:
        if not isinstance(claim, dict) or claim.get("type") not in CLAIM_TYPES:
            raise ScenarioError(f"claim.type must be one of {sorted(CLAIM_TYPES)}")
        required = {"idor_read": ("step",),
                    "idor_write": ("mutate", "verify"),
                    "state_change": ("step",)}[claim["type"]]
        for key in required:
            if claim.get(key) not in ids:
                raise ScenarioError(f"claim.{key} must reference a step id")
        owner = claim.get("owner", "A")
        attacker = claim.get("attacker", "B")
        if owner not in defs or attacker not in defs:
            raise ScenarioError(f"claim.owner/attacker must be role labels in {sorted(defs)}")
        if owner == attacker:
            raise ScenarioError("claim.owner and claim.attacker must differ")
        if claim["type"] == "state_change" and schema != 2:
            raise ScenarioError("claim state_change requires \"schema\": 2")
        if claim["type"] == "state_change":
            assertions = claim.get("json")
            if not isinstance(assertions, dict) or not assertions:
                raise ScenarioError("state_change claim needs a non-empty json assertion")
            for path, expected in assertions.items():
                _validate_json_matcher(expected, f"claim.json[{path!r}]")
            step = next(s for s in steps if s.get("id") == claim["step"])
            if step.get("role") != attacker:
                raise ScenarioError("state_change claim.step must run as the attacker role")
            verify = claim.get("owner_verify")
            if verify is not None:
                if verify not in ids or verify == claim["step"]:
                    raise ScenarioError("claim.owner_verify must reference another step")
                verify_step = next(s for s in steps if s.get("id") == verify)
                if verify_step.get("role") != owner:
                    raise ScenarioError("claim.owner_verify must run as the owner role")
        if "owner_marker" in claim or "attacker_marker" in claim:
            if schema != 2:
                raise ScenarioError("claim markers require \"schema\": 2")

    used = set()
    for step in steps:
        used.add(step["role"])
    for step in cleanup or []:
        used.add(step["role"])
    if claim:
        used.add(claim.get("owner", "A"))
        used.add(claim.get("attacker", "B"))
    if len(used) < 2:
        raise ScenarioError("scenario must reference at least two role labels")
    return schema, defs


def _used_indices(scenario: dict, defs: dict[str, dict]) -> list[int]:
    used = {step["role"] for step in scenario["steps"]}
    used |= {step["role"] for step in scenario.get("cleanup") or []}
    claim = scenario.get("claim")
    if claim:
        used.add(claim.get("owner", "A"))
        used.add(claim.get("attacker", "B"))
    return sorted({defs[label]["account"] for label in used})


# ---------- substitution and JSON paths ----------

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


def _resolve_json(obj, path: str) -> tuple[bool, object]:
    """Resolve `$.data.items[0].id`. Dotted numeric parts (`items.0.id`) also work.

    Keys containing a literal dot are not addressable; use body_contains for those.
    """
    p = (path or "").strip()
    if p in ("$", ""):
        return True, obj
    if p.startswith("$"):
        p = p[1:]
    if p.startswith("."):
        p = p[1:]
    current = obj
    for part in p.split("."):
        if not part:
            continue
        match = re.fullmatch(r"([^\[\]]*)((?:\[\d+\])*)", part)
        if not match:
            return False, None
        name, indexes = match.group(1), match.group(2)
        if name:
            if isinstance(current, list) and name.isdigit():
                i = int(name)
                if i >= len(current):
                    return False, None
                current = current[i]
            elif isinstance(current, dict) and name in current:
                current = current[name]
            else:
                return False, None
        for index in re.findall(r"\[(\d+)\]", indexes or ""):
            if not isinstance(current, list):
                return False, None
            i = int(index)
            if i >= len(current):
                return False, None
            current = current[i]
    return True, current


def dig_json(obj, path: str):
    found, value = _resolve_json(obj, path)
    return value if found else None


def _json_equal(left, right) -> bool:
    try:
        return (json.dumps(left, sort_keys=True, separators=(",", ":")) ==
                json.dumps(right, sort_keys=True, separators=(",", ":")))
    except (TypeError, ValueError):
        return left == right


def _match_expected(expected, actual, found: bool) -> tuple[bool, str]:
    if isinstance(expected, dict) and set(expected) & MATCHER_KEYS:
        key, wanted = next(iter(expected.items()))
        if key == "exists":
            return found is wanted, f"exists={wanted}, found={found}"
        if not found:
            return False, "path not found"
        if key == "equals":
            return _json_equal(actual, wanted), f"expected {wanted!r}, got {actual!r}"
        if key == "not_equals":
            return not _json_equal(actual, wanted), f"expected not {wanted!r}"
        if key == "contains":
            if isinstance(actual, str) and isinstance(wanted, str):
                return wanted in actual, f"{wanted!r} not in string"
            if isinstance(actual, list):
                return any(_json_equal(item, wanted) for item in actual), f"{wanted!r} not in list"
            if isinstance(actual, dict):
                return wanted in actual, f"{wanted!r} not a key"
            return False, "contains needs a string, list, or object"
        if key == "one_of":
            return any(_json_equal(actual, item) for item in wanted), f"{actual!r} not in one_of"
    if not found:
        return False, "path not found"
    return _json_equal(actual, expected), f"expected {expected!r}, got {actual!r}"


def _check_expect(step: dict, resp, variables: dict) -> tuple[list[str], bool]:
    expect = step.get("expect") or {}
    failures: list[str] = []
    status = getattr(resp, "status_code", 0)
    if "status" in expect:
        allowed = expect["status"] if isinstance(expect["status"], list) else [expect["status"]]
        if status not in allowed:
            if step.get("denied_is_coverage") and status in DENIED_STATUSES:
                return [], True
            failures.append(f"status {status} not in {allowed}")
    try:
        body = resp.text or ""
    except Exception:
        body = ""
    for needle in expect.get("body_contains") or []:
        try:
            resolved = str(substitute(needle, variables))
        except ScenarioError as exc:
            failures.append(str(exc))
            continue
        if resolved not in body:
            failures.append(f"body missing {resolved!r}")
    for needle in expect.get("body_not_contains") or []:
        try:
            resolved = str(substitute(needle, variables))
        except ScenarioError as exc:
            failures.append(str(exc))
            continue
        if resolved in body:
            failures.append(f"body unexpectedly contains {resolved!r}")
    assertions = expect.get("json") or {}
    if assertions:
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            failures.append("response is not JSON")
            parsed = None
        if parsed is not None:
            for path, expected in assertions.items():
                try:
                    resolved = substitute(expected, variables)
                except ScenarioError as exc:
                    failures.append(str(exc))
                    continue
                found, actual = _resolve_json(parsed, path)
                ok, why = _match_expected(resolved, actual, found)
                if not ok:
                    failures.append(f"json {path}: {why}")
    return failures, False


def _assert_json(assertions: dict, body: str, variables: dict) -> list[str]:
    failures: list[str] = []
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ["response is not JSON"]
    for path, expected in assertions.items():
        try:
            resolved = substitute(expected, variables)
        except ScenarioError as exc:
            failures.append(str(exc))
            continue
        found, actual = _resolve_json(parsed, path)
        ok, why = _match_expected(resolved, actual, found)
        if not ok:
            failures.append(f"json {path}: {why}")
    return failures


# ---------- claims ----------

def _ran(result: StepResult | None) -> bool:
    return bool(result and result.response is not None and not result.skipped)


def evaluate_claim(claim: dict, results: dict[str, StepResult], roles: dict[str, Role],
                   variables: dict) -> tuple[str, str, str]:
    """Return (verdict, explanation, evidence_grade)."""
    owner = roles.get(claim.get("owner", "A"))
    attacker = roles.get(claim.get("attacker", "B"))

    if claim["type"] == "idor_read":
        result = results.get(claim["step"])
        if not _ran(result):
            return "inconclusive", "claim step did not run", "single-role"
        status = result.status
        if status in DENIED_STATUSES:
            return "enforced", f"attacker received HTTP {status}", "dual-role"
        if not 200 <= status < 300:
            return "inconclusive", f"attacker received HTTP {status}", "single-role"
        if not owner:
            return "inconclusive", "owner role is unknown", "single-role"
        try:
            owner_marker = str(substitute(claim.get("owner_marker", owner.identity or ""),
                                          variables))
            attacker_marker = str(substitute(claim.get("attacker_marker",
                                                       attacker.identity or ""),
                                             variables)) if attacker else ""
        except ScenarioError as exc:
            return "inconclusive", str(exc), "single-role"
        if not owner_marker:
            return "inconclusive", "owner marker is empty", "single-role"
        if owner_marker not in result.body:
            return "inconclusive", "owner marker absent from the attacker's response", "single-role"
        if attacker_marker and attacker_marker in result.body:
            return "inconclusive", "attacker marker is in the response (self-object)", "single-role"
        owner_step = results.get(claim.get("owner_step", "")) if claim.get("owner_step") else None
        grade = "dual-role" if _ran(owner_step) and owner_step.ok else "single-role"
        return ("confirmed",
                f"attacker HTTP {status} with owner marker {owner_marker!r} and no attacker marker",
                grade)

    if claim["type"] == "idor_write":
        mutate = results.get(claim["mutate"])
        verify = results.get(claim["verify"])
        if not _ran(mutate) or not _ran(verify):
            return "inconclusive", "mutate/verify step did not run", "single-role"
        if mutate.status in DENIED_STATUSES:
            return "enforced", f"mutation denied with HTTP {mutate.status}", "dual-role"
        if not 200 <= mutate.status < 300:
            return "inconclusive", f"mutation returned HTTP {mutate.status}", "single-role"
        try:
            marker = str(substitute(claim.get("marker", "${marker}"), variables))
        except ScenarioError as exc:
            return "inconclusive", str(exc), "single-role"
        if verify.status in DENIED_STATUSES:
            return "inconclusive", f"owner verification returned HTTP {verify.status}", "single-role"
        if marker and marker in verify.body:
            return "confirmed", f"owner observed attacker marker {marker!r}", "dual-role"
        return "inconclusive", "owner did not observe the attacker's marker", "single-role"

    # state_change
    result = results.get(claim["step"])
    if not _ran(result):
        return "inconclusive", "state-change step did not run", "single-role"
    if result.status in DENIED_STATUSES:
        return "enforced", f"state change denied with HTTP {result.status}", "dual-role"
    if not 200 <= result.status < 300:
        return "inconclusive", f"state change returned HTTP {result.status}", "single-role"
    failures = _assert_json(claim.get("json") or {}, result.body, variables)
    if failures:
        return "inconclusive", "claim assertion failed: " + "; ".join(failures), "single-role"
    verify_id = claim.get("owner_verify")
    if verify_id:
        verify = results.get(verify_id)
        if not _ran(verify) or not verify.ok or not 200 <= verify.status < 300:
            return "inconclusive", "owner verification did not confirm the state change", "single-role"
        return ("confirmed", f"state change observed and verified by {verify.role}", "dual-role")
    if not attacker:
        return "inconclusive", "attacker role is unknown", "single-role"
    return ("confirmed", "state change observed in the attacker's own response", "single-role")


# ---------- role setup ----------

def _role_for_account(index: int, accounts: list[dict]) -> Role:
    acc = accounts[index]
    return Role(label=acc.get("label", f"account{index}"), email=acc.get("email", ""),
                identity=acc.get("identity") or acc.get("email", ""),
                user_id=index + 1, headers=dict(acc.get("headers") or {}))


def _build_role_map(by_index: dict[int, Role], scenario: dict, defs: dict[str, dict]) -> dict[str, Role]:
    used = {step["role"] for step in scenario["steps"]}
    used |= {step["role"] for step in scenario.get("cleanup") or []}
    claim = scenario.get("claim")
    if claim:
        used.add(claim.get("owner", "A"))
        used.add(claim.get("attacker", "B"))
    role_map: dict[str, Role] = {}
    for label in used:
        base = by_index[defs[label]["account"]]
        role_map[label] = replace(base, headers={**base.headers, **defs[label]["headers"]})
    return role_map


def _seed_variables(role_map: dict[str, Role], run_id: str) -> dict:
    variables: dict = {"run_id": run_id, "marker": f"bb-{run_id}"}
    for label, role in role_map.items():
        variables[f"{label}.email"] = role.email
        variables[f"{label}.id"] = role.user_id
        variables[f"{label}.identity"] = role.identity
    return variables


# ---------- runner ----------

def run_scenario(scenario: dict, *, scope: Scope, accounts: dict, program: str,
                 store: Store, allow_write: bool = False, dry_run: bool = False,
                 proxy: str | None = None, transport=None, llm: bool = False,
                 queue: bool = True, log=print) -> dict:
    schema, defs = validate_scenario(scenario)
    base_url = scenario.get("base_url") or accounts.get("base_url")
    if not base_url:
        raise ScenarioError("scenario or accounts file needs base_url")
    if not scope.is_in_scope(base_url):
        raise ScenarioError(f"base_url {base_url} is out of scope for {program}")

    account_list = accounts.get("accounts") or []
    used_indices = _used_indices(scenario, defs)
    if len(used_indices) < 2:
        raise ScenarioError("scenario needs at least two distinct role accounts")
    max_defined = max(spec["account"] for spec in defs.values())
    if account_list and max_defined >= len(account_list):
        raise ScenarioError(f"role account index {max_defined} out of range "
                            f"(accounts: {len(account_list)})")

    if not dry_run:
        for step in scenario["steps"]:
            if str(step.get("method") or "GET").upper() in WRITE_METHODS and not allow_write:
                raise ScenarioError(
                    f"step {step.get('id')!r} uses {step.get('method')}; rerun with "
                    "--allow-write (disposable resources, program policy permitting)")

    run_id = store.start_run(program, base_url, scope.fingerprint,
                             {"source": "scenario", "scenario": scenario.get("name", ""),
                              "schema": schema})
    client = ScopedClient(scope, base_url=base_url, proxy=proxy,
                          rate=float(scenario.get("rate", 3.0)), dry_run=dry_run,
                          store=store, run_id=run_id, tool="scenario", transport=transport)
    verdict = "inconclusive"
    finding: Finding | None = None
    results: dict[str, StepResult] = {}
    variables: dict = {}
    role_map: dict[str, Role] = {}
    cleanup_errors: list[str] = []
    try:
        if dry_run:
            by_index = {i: _role_for_account(i, account_list) for i in used_indices}
            log("  [scenario] dry-run: login skipped")
        else:
            by_index = login_accounts(client, accounts, indices=used_indices, log=log)
        role_map = _build_role_map(by_index, scenario, defs)
        variables = _seed_variables(role_map, run_id)
        log("  [roles] " + ", ".join(f"{label}={role.label}" for label, role in sorted(role_map.items())))

        for step in scenario["steps"]:
            sid = step.get("id") or f"step{len(results) + 1}"
            method = str(step.get("method") or "GET").upper()
            label = step["role"]
            role = role_map[label]
            try:
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
            except ScenarioError as exc:
                results[sid] = StepResult(step=step, role=label, ok=False,
                                          skipped=True, error=str(exc))
                log(f"  [step] {sid}: skipped — {exc}")
                continue

            if dry_run:
                client.request(method, path, headers=headers, json=json_body,
                               data=data_body, params=params)
                display = str(path)
                if not display.startswith(("http://", "https://")):
                    display = client.base_url.rstrip("/") + "/" + display.lstrip("/")
                log(f"  [plan] {label} {method} {display}")
                results[sid] = StepResult(step=step, role=label, ok=True)
                continue

            try:
                resp = client.request(method, path, headers=headers, json=json_body,
                                      data=data_body, params=params)
            except Exception as exc:
                results[sid] = StepResult(step=step, role=label, ok=False, error=str(exc))
                log(f"  [step] {sid}: {label} {method} {path} -> ERROR {exc}")
                break

            failures, coverage = _check_expect(step, resp, variables)
            result = StepResult(step=step, role=label, response=resp,
                                exchange=client.last_exchange, ok=not failures,
                                coverage=coverage, failures=failures)
            results[sid] = result
            suffix = "  (coverage)" if coverage else (
                f"  ! {'; '.join(failures)}" if failures else "")
            log(f"  [step] {sid}: {label} {method} {path} -> {resp.status_code}{suffix}")
            if coverage:
                continue
            if failures and not step.get("continue_on_failure"):
                break

            for name, path_expr in (step.get("extract") or {}).items():
                try:
                    found, value = _resolve_json(resp.json(), path_expr)
                except Exception:
                    found, value = False, None
                if not found or value is None:
                    result.ok = False
                    result.failures.append(f"extract {name} from {path_expr} failed")
                    log(f"  [step] {sid}: extraction {name} failed")
                    break
                variables[name] = value
                variables[f"{sid}.{name}"] = value

        if dry_run:
            verdict = "dry-run"
            return {"run_id": run_id, "verdict": verdict, "finding": None,
                    "steps": results, "planned": list(client.planned),
                    "roles": sorted(role_map)}

        claim = scenario.get("claim")
        if claim:
            if claim.get("type") == "idor_read" and not claim.get("owner_step"):
                log("  [claim] warning: idor_read has no owner_step; the report will carry "
                    "only the attacker's exchange (add the owner's baseline request)")
            verdict, why, grade = evaluate_claim(claim, results, role_map, variables)
            log(f"  [claim] {claim['type']} -> {verdict}: {why} (evidence: {grade})")
            if verdict == "confirmed":
                finding = _build_finding(scenario, claim, results, role_map, why, grade,
                                         program, scope, run_id, base_url)
                store.add_finding(finding, run_id)
                from bb.pipeline import finalize_findings
                finalize_findings([finding], program=program, scope=scope, store=store,
                                  llm=llm, queue=queue, log=log)
        elif any(r.skipped or not r.ok for r in results.values()):
            verdict = "inconclusive"
            log("  [scenario] no claim: at least one step failed or was skipped")
        else:
            verdict = "observed"
            log("  [scenario] no claim: steps completed, results are observational")

    finally:
        if allow_write and not dry_run and scenario.get("cleanup") and role_map:
            _cleanup(client, scenario["cleanup"], variables, role_map, cleanup_errors, log)
        client.close()
        store.finish_run(run_id, {"verdict": verdict,
                                  "finding": finding.id if finding else None,
                                  "cleanup_errors": cleanup_errors})
    return {"run_id": run_id, "verdict": verdict, "finding": finding,
            "steps": results, "requests": client.sent, "roles": sorted(role_map),
            "cleanup_errors": cleanup_errors}


def _cleanup(client: ScopedClient, steps: list[dict], variables: dict,
             role_map: dict[str, Role], errors: list[str], log) -> None:
    for step in steps:
        if not isinstance(step, dict):
            continue
        method = str(step.get("method") or "DELETE").upper()
        if method not in WRITE_METHODS:
            continue
        try:
            path = substitute(step.get("path") or step.get("url"), variables, strict=True)
        except ScenarioError as exc:
            # Never guess a resource identity for deletion.
            log(f"  [cleanup] skipped (unresolved): {exc}")
            continue
        try:
            role = role_map.get(step.get("role", "A"), role_map.get("A"))
            headers = dict(role.headers) if role else {}
            headers.update(substitute(step.get("headers") or {}, variables, strict=True))
        except ScenarioError as exc:
            log(f"  [cleanup] skipped (unresolved): {exc}")
            continue
        try:
            resp = client.request(method, path,
                                  json=substitute(step.get("json"), variables)
                                  if "json" in step else None, headers=headers)
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}")
            log(f"  [cleanup] {step.get('role', 'A')} {method} {path}")
        except Exception as exc:
            if step.get("ignore_failure", True):
                log(f"  [cleanup] ignored: {exc}")
            else:
                errors.append(f"{method} {path}: {exc}")
                log(f"  [cleanup] failed: {exc}")


# ---------- findings ----------

def _build_finding(scenario: dict, claim: dict, results: dict[str, StepResult],
                   roles: dict[str, Role], why: str, grade: str, program: str,
                   scope: Scope, run_id: str, base_url: str) -> Finding:
    owner = roles.get(claim.get("owner", "A"))
    attacker = roles.get(claim.get("attacker", "B"))
    if claim["type"] == "state_change":
        attack = results[claim["step"]]
        owner_step = results.get(claim["owner_verify"]) if claim.get("owner_verify") else None
        bug_class = scenario.get("bug_class", "Broken Access Control")
        default_title = (f"Unauthorized state change at "
                         f"{urlsplit(attack.step.get('path') or attack.step.get('url')).path} "
                         f"as {attacker.label if attacker else claim.get('attacker')}")
        verb = "change state"
    elif claim["type"] == "idor_read":
        attack = results[claim["step"]]
        owner_step = results.get(claim.get("owner_step", "")) if claim.get("owner_step") else None
        bug_class = "IDOR"
        default_title = (f"Broken object-level authorization: "
                         f"{attacker.label if attacker else 'attacker'} can read "
                         f"{owner.label if owner else 'owner'}'s object at "
                         f"{urlsplit(attack.step.get('path') or attack.step.get('url')).path}")
        verb = "read"
    else:
        attack = results[claim["mutate"]]
        owner_step = results.get(claim["verify"])
        bug_class = "IDOR"
        default_title = (f"Broken object-level authorization: "
                         f"{attacker.label if attacker else 'attacker'} can modify "
                         f"{owner.label if owner else 'owner'}'s object at "
                         f"{urlsplit(attack.step.get('path') or attack.step.get('url')).path}")
        verb = "modify"

    url = attack.step.get("path") or attack.step.get("url") or ""
    if attack.exchange:
        url = attack.exchange.url
    elif not str(url).startswith(("http://", "https://")):
        url = base_url.rstrip("/") + "/" + str(url).lstrip("/")
    host = urlsplit(url).hostname or ""

    title = scenario.get("title") or default_title
    summary = scenario.get("summary") or (
        f"{why}. The scenario requested the resource as {owner.label if owner else 'owner'} "
        f"and as {attacker.label if attacker else 'attacker'}; the result crosses the "
        f"authorization boundary (evidence: {grade}).")
    impact = scenario.get("impact") or (
        "An authenticated user can " + ("change state or modify another user's object"
                                        if verb != "read" else
                                        "read another user's object") +
        " by requesting an identifier they do not own.")
    evidence: list[Evidence] = []
    evidence_label = "owner baseline" if claim["type"] == "idor_read" else "owner verification"
    for label, result in ((evidence_label, owner_step), ("attacker", attack)):
        if result and result.exchange:
            evidence.append(Evidence(
                f"{label}: {result.role} {result.step.get('method', 'GET')} "
                f"{urlsplit(result.exchange.url).path} -> {result.status}",
                result.exchange))
    steps = [f"{r.role} {r.step.get('method', 'GET')} "
             f"{r.step.get('path') or r.step.get('url')} -> "
             f"{'skipped' if r.skipped else r.status}"
             for r in results.values() if r.response or r.skipped]
    return Finding(
        title=title, bug_class=bug_class, severity=scenario.get("severity", "high"),
        confidence="high", host=host, url=url, summary=summary, impact=impact,
        remediation=scenario.get("remediation") or (
            "Enforce an authorization check on the resolution layer for every operation, "
            "and verify the resulting state, not just the route."),
        steps=steps, evidence=evidence,
        meta={"program": program, "scenario": scenario.get("name", ""),
              "claim": claim, "scope_fingerprint": scope.fingerprint,
              "run_id": run_id, "schema": scenario.get("schema", 1),
              "evidence": grade},
    )
