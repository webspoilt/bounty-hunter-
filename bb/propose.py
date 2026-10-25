"""Propose stateful scenarios from an authenticated HAR.

This is a *drafting* step, not an executor. It never sends a request, never writes to a
store, and never queues a finding. It looks for a captured create (2xx with an object id),
then for later requests that reference that id, and emits reviewable scenario JSON.

The captured session is assumed to be the owner (role A); every draft says so. A reviewer
decides whether the roles, body replay, and mutation field are correct before running
anything with `--allow-write`.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlunsplit

from bb.config import DATA, now_iso
from bb.har import HarEntry, HarError, load_har
from bb.scope import Scope

ID_KEYS = {"id", "_id", "uuid", "itemid", "item_id", "objectid", "object_id", "pk"}
SAFE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_PROPOSALS = 25


@dataclass
class Proposal:
    kind: str
    origin: str
    template: str
    create: HarEntry
    id_value: str
    id_path: str
    reads: list[HarEntry] = field(default_factory=list)
    mutations: list[HarEntry] = field(default_factory=list)
    deletes: list[HarEntry] = field(default_factory=list)
    scenario: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    slug: str = ""


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _path(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (("?" + parts.query) if parts.query else "")


def _json_body(entry: HarEntry):
    if not entry.request_body:
        return None
    try:
        value = json.loads(entry.request_body)
    except (json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _walk_ids(value, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not SAFE_KEY.match(key):
                continue
            child_path = f"{path}.{key}"
            if key.lower() in ID_KEYS and isinstance(child, (str, int)) \
                    and not isinstance(child, bool):
                text = str(child)
                if 1 <= len(text) <= 64 and " " not in text:
                    out.append((text, child_path))
            else:
                _walk_ids(child, child_path, out)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            _walk_ids(child, f"{path}[{i}]", out)


def find_id(entry: HarEntry) -> tuple[str, str] | None:
    """Return (id, JSON path) from a create response, preferring object ids over user ids."""
    try:
        body = json.loads(entry.response_body or "")
    except (json.JSONDecodeError, ValueError):
        return None
    found: list[tuple[str, str]] = []
    _walk_ids(body, "$", found)
    if not found:
        return None
    found.sort(key=lambda item: (item[1].lower().find("user") >= 0, len(item[1])))
    return found[0]


def _references(entry: HarEntry, object_id: str) -> bool:
    parts = urlsplit(entry.url)
    if object_id in [segment for segment in (parts.path or "/").split("/") if segment]:
        return True
    return any(object_id in values for values in parse_qs(parts.query).values())


def _with_placeholder(url: str, object_id: str) -> str:
    pattern = re.compile(r"(?<=[/=])" + re.escape(object_id) + r"(?=[/&?#]|$)")
    return pattern.sub("${item_id}", url)


def _marker_body(value):
    """Copy the mutation body, replacing one innocuous string leaf with ${marker}."""
    marker_path = None

    def walk(node, path):
        nonlocal marker_path
        if marker_path is not None:
            return node
        if isinstance(node, dict):
            out = {}
            for key, child in node.items():
                child_path = f"{path}.{key}" if path else key
                if isinstance(child, str) and 1 <= len(child) <= 80 \
                        and "[REDACTED]" not in child and "://" not in child \
                        and child.lower() not in ("true", "false", "null"):
                    marker_path = child_path
                    out[key] = "${marker}"
                else:
                    out[key] = walk(child, child_path)
            return out
        if isinstance(node, list):
            return [walk(child, f"{path}[{i}]") if marker_path is None else child
                    for i, child in enumerate(node)]
        return node

    marked = walk(value, "")
    return (marked, marker_path) if marker_path else (None, None)


def _create_step(entry: HarEntry, object_path: str, warnings: list[str]) -> dict:
    step = {"id": "create", "role": "A", "method": entry.method,
            "path": _path(entry.url), "expect": {"status": [200, 201, 204]},
            "extract": {"item_id": object_path}}
    body = _json_body(entry)
    if body is not None:
        step["json"] = body
        if "[REDACTED]" in entry.request_body:
            warnings.append("create body contains redacted values; replace them before running")
    elif entry.method in ("POST", "PUT", "PATCH"):
        warnings.append("create request had a non-JSON or absent body; add the payload manually")
    return step


def _read_scenario(entry: HarEntry, object_id: str, create: HarEntry,
                   warnings: list[str]) -> dict | None:
    if not entry or not (200 <= entry.status < 300):
        return None
    path = _path(entry.url)
    return {
        "name": f"proposed-read-{object_id}",
        "base_url": _origin(entry.url),
        "steps": [
            {"id": "owner_read", "role": "A", "method": "GET", "path": path},
            {"id": "attack_read", "role": "B", "method": "GET", "path": path},
        ],
        "claim": {"type": "idor_read", "step": "attack_read",
                  "owner_step": "owner_read", "owner": "A", "attacker": "B"},
    }


def _write_scenario(create: HarEntry, object_id: str, mutation: HarEntry,
                    read: HarEntry | None, delete: HarEntry | None,
                    object_path: str, warnings: list[str]) -> dict | None:
    body = _json_body(mutation)
    if body is None:
        return None
    marked, marker_path = _marker_body(body)
    if marked is None:
        warnings.append("mutation body has no replaceable string field; write draft skipped")
        return None
    warnings.append(f"marker placed at body path {marker_path!r}")

    steps = [_create_step(create, object_path, warnings)]
    if read is not None and 200 <= read.status < 300:
        steps.append({"id": "owner_read", "role": "A", "method": "GET",
                      "path": _with_placeholder(read.url, object_id)})
    steps.append({"id": "attack_write", "role": "B", "method": mutation.method,
                  "path": _with_placeholder(mutation.url, object_id), "json": marked})
    verify = read if read is not None else mutation
    steps.append({"id": "owner_verify", "role": "A", "method": "GET",
                  "path": _with_placeholder(verify.url, object_id)})
    scenario = {
        "name": f"proposed-write-{object_id}",
        "base_url": _origin(create.url),
        "steps": steps,
        "claim": {"type": "idor_write", "mutate": "attack_write",
                  "verify": "owner_verify", "marker": "${marker}"},
    }
    if delete is not None:
        scenario["cleanup"] = [{"role": "A", "method": "DELETE",
                                "path": _with_placeholder(delete.url, object_id)}]
    else:
        warnings.append("no captured delete; the run may leave a test resource behind")
    return scenario


def _slug(template: str, kind: str, used: set[str]) -> str:
    stem = re.sub(r"[^a-z0-9]+", "-", template.strip("/").lower()).strip("-")[:50] or "root"
    base = f"{stem}-{kind.replace('idor_', '')}"
    slug, n = base, 2
    while slug in used:
        slug = f"{base}-{n}"
        n += 1
    used.add(slug)
    return slug


def propose(har_path: str | Path, scope: Scope, program: str,
            out_dir: str | Path | None = None, limit: int = MAX_PROPOSALS,
            log=print) -> dict:
    """Parse, cluster, and write draft scenarios. Never sends a request."""
    har_path = Path(har_path).expanduser().resolve()
    entries = load_har(har_path)
    in_scope, denied = [], 0
    for entry in entries:
        if scope.check(entry.url).allowed:
            in_scope.append(entry)
        else:
            denied += 1

    creates = [e for e in in_scope
               if e.method in ("POST", "PUT") and 200 <= e.status < 300 and find_id(e)]
    proposals: list[Proposal] = []
    seen_templates: set[tuple[str, str]] = set()
    used_slugs: set[str] = set()

    for create in creates:
        found = find_id(create)
        if not found:
            continue
        object_id, object_path = found
        origin = _origin(create.url)
        template = _with_placeholder(create.url, object_id)
        key = (origin, template)
        if key in seen_templates:
            continue
        seen_templates.add(key)

        related = [e for e in in_scope if e.index > create.index
                   and _origin(e.url) == origin and _references(e, object_id)]
        reads = [e for e in related if e.method in ("GET", "HEAD") and 200 <= e.status < 300]
        mutations = [e for e in related if e.method in ("PUT", "PATCH") and 200 <= e.status < 300]
        deletes = [e for e in related if e.method == "DELETE" and 200 <= e.status < 300]
        if not reads and not mutations:
            continue

        warnings = ["captured session assumed to be owner A; verify both roles before running"]
        read = reads[0] if reads else None
        if read is not None:
            scenario = _read_scenario(read, object_id, create, warnings)
            if scenario:
                proposals.append(Proposal(
                    kind="idor_read", origin=origin, template=template, create=create,
                    id_value=object_id, id_path=object_path, reads=reads,
                    mutations=mutations, deletes=deletes, scenario=scenario,
                    warnings=list(warnings), slug=_slug(template.split("://")[-1], "idor_read",
                                                        used_slugs)))
        if mutations:
            write_warnings = list(warnings)
            scenario = _write_scenario(create, object_id, mutations[0], read,
                                       deletes[0] if deletes else None, object_path,
                                       write_warnings)
            if scenario:
                proposals.append(Proposal(
                    kind="idor_write", origin=origin, template=template, create=create,
                    id_value=object_id, id_path=object_path, reads=reads,
                    mutations=mutations, deletes=deletes, scenario=scenario,
                    warnings=write_warnings,
                    slug=_slug(template.split("://")[-1], "idor_write", used_slugs)))
        if len(proposals) >= limit:
            break

    proposals = proposals[:limit]
    out = Path(out_dir).expanduser().resolve() if out_dir else (
        DATA / "proposed" / f"{re.sub(r'[^a-zA-Z0-9_.-]', '_', program)}-{now_iso()[:19].replace(':', '')}")
    out.mkdir(parents=True, exist_ok=True)

    written = []
    for proposal in proposals:
        from bb.scenario import validate_scenario
        validate_scenario(proposal.scenario)
        path = out / f"{proposal.slug}.json"
        path.write_text(json.dumps(proposal.scenario, indent=2) + "\n", encoding="utf-8")
        written.append({
            "file": path.name, "kind": proposal.kind, "method": proposal.create.method,
            "template": proposal.template, "origin": proposal.origin,
            "source_entry_index": proposal.create.index,
            "warnings": proposal.warnings,
        })

    index = {
        "program": program,
        "har": str(har_path),
        "generated_at": now_iso(),
        "entries": len(entries),
        "in_scope": len(in_scope),
        "denied": denied,
        "proposals": written,
    }
    (out / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    (out / "REVIEW.md").write_text(_review(program, har_path, written), encoding="utf-8")
    log(f"  [propose] {len(entries)} entries ({len(in_scope)} in scope, {denied} denied) -> "
        f"{len(written)} draft scenario(s) in {out}")
    return {"out": out, "index": index, "written": written}


def _review(program: str, har_path: Path, written: list[dict]) -> str:
    lines = [
        f"# Scenario proposals — {program}",
        "",
        f"Source: `{har_path}`  ·  generated {now_iso()}",
        "",
        "> Drafts only. Nothing here was executed, queued, or submitted.",
        "",
        "**Assumption:** the captured session is the owner (role A). Verify the roles,",
        "the create payload (redacted fields are marked), and any mutation marker before",
        "running with `--allow-write`.",
        "",
        "| file | kind | create | warnings |",
        "|---|---|---|---|",
    ]
    for item in written:
        warnings = "; ".join(item["warnings"]).replace("|", "\\|")
        template = item["template"].replace("|", "\\|")
        lines.append(f"| `{item['file']}` | {item['kind']} | `{item['method']} "
                     f"{template}` | {warnings} |")
    lines += [
        "",
        "## Review checklist",
        "",
        "1. Read the draft and confirm the object really belongs to A.",
        "2. Replace any `[REDACTED]` or placeholder body values.",
        "3. Dry-run first: `bb scenario run --file <file> --program "
        f"{program} --accounts <accounts.json> --dry-run`.",
        "4. Only then add `--allow-write`, and only with disposable accounts/resources.",
        "5. Run `bb outcome` after the program responds.",
        "",
        "Read drafts are GET-only. Write drafts create, mutate, verify, and (when a delete was",
        "captured) clean up.",
    ]
    return "\n".join(lines) + "\n"
