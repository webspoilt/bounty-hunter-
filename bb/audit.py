"""Cloudflare security-audit skill: vendored contract, validators, and a scaffold.

The skill (MIT, `skills/security-audit/`) is a *source-code* audit methodology. Its
outputs are machine-verifiable: `findings.json` (three verdicts) and
`coverage-ledger.json`, each with a zero-dependency Node validator.

bb does not re-implement the audit. It:
  * vendors the skill so a coding agent can load it offline, pinned to a commit;
  * scaffolds a run directory with the skill's required metadata and valid empty
    ledger/findings files;
  * runs the authoritative validators with Node, so the contract cannot drift;
  * ingests the methodology into the knowledge base.

A dynamic web finding from `bb hunt` is *not* converted into a `confirmed` source
finding: that verdict requires file/line trace evidence. Keeping the two evidence
models separate is the point.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from bb.config import AUDIT_SKILL, now_iso

FINDINGS_VALIDATOR = AUDIT_SKILL / "validate-findings.cjs"
LEDGER_VALIDATOR = AUDIT_SKILL / "validate-coverage-ledger.cjs"
SCHEMA = AUDIT_SKILL / "report-schema.json"

PROFILES = ("quick", "standard", "deep")
VALIDATORS = {"findings": FINDINGS_VALIDATOR, "ledger": LEDGER_VALIDATOR}

ARCHITECTURE_SCAFFOLD = """# Security audit — {repo_name}

> **Scaffold only.** `bb audit init` created this directory; no audit has run yet.
> Fill this file during Phase 1 (reconnaissance), then keep it current.

- **Target:** `{target}`
- **Source ref:** `{source_ref}`{dirty_note}
- **Profile:** `{profile}`
- **Scope paths:** {scope_paths}
- **Created:** {created_at}
- **Skill:** `{skill_dir}/SKILL.md`

## System overview

_TODO: entrypoints, services, data stores, deployment model._

## Trust boundaries

_TODO: lower-trust principals, the controls they cross, and the resources behind each boundary._

## Input surfaces

_TODO: routes, RPC methods, CLI flags, file parsers, IPC, queues, webhooks._

## Prior evidence

_TODO: prior `coverage-ledger.json` / `findings.json` paths and what they establish._

## Deterministic coverage plan

_TODO: seed units in `coverage-ledger.json` (surface x boundary x attack_class) and
record why companion blocks are selected or excluded._
"""

RUN_README = """# Audit workspace

Created by `bb audit init`. The vendored Cloudflare `security-audit` skill owns the
method; this directory only holds its artifacts.

## Run it

1. Give your coding agent the skill:
   - vendored copy: `{skill_dir}/SKILL.md`, or
   - install: `npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit`
2. Ask it, with this directory as the output path:
   `security audit {target} output to {out}`
3. Validate what it produced:
   `bb audit validate --findings {out}/findings.json --ledger {out}/coverage-ledger.json`

## Files (owned by the skill's parent agent)

| File | State |
|---|---|
| `run-metadata.json` | scaffolded; update when facts change |
| `architecture.md` | scaffolded; fill in Phase 1 |
| `coverage-ledger.json` | empty `[]` (valid per the vendored validator) |
| `findings.json` | empty `[]` (valid per the vendored validator) |
| `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` | written in Phase 6 |

A finding is `confirmed` only with a complete source trace (`file:line`), bounded
local evidence, and independent verification. Dynamic HTTP evidence belongs in
`bb`'s report, not here.
"""


def node_available() -> bool:
    return shutil.which("node") is not None


# The upstream CLIs refuse to read a file unless O_NOFOLLOW/O_NONBLOCK exist (a
# *nix hardening measure). Windows lacks those flags, so there we call the same
# exported schema interpreter directly on a path we just resolved ourselves. The
# validation logic is still the vendored one; only the hardened file-open is
# skipped, and only on Windows. POSIX runs the untouched CLI.
_WINDOWS_WRAPPER = r"""
const fs = require('fs');
const path = require('path');
const [kind, file, dir] = process.argv.slice(-3);
process.chdir(dir);
const name = kind === 'findings' ? 'validate-findings.cjs' : 'validate-coverage-ledger.cjs';
const mod = require(path.join(dir, name));
const text = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
const value = JSON.parse(text);
let errors;
if (kind === 'findings') {
  const schema = JSON.parse(fs.readFileSync(path.join(dir, 'report-schema.json'), 'utf8'));
  errors = mod.validateDocument(value, schema);
} else {
  errors = mod.validateDocument(value);
}
if (!errors || errors.length === 0) {
  console.log('PASS: document valid');
  process.exit(0);
}
console.error(errors.map((e) => 'FAIL: ' + e).join('\n'));
process.exit(1);
"""


def _validator_command(kind: str, target: Path) -> list[str]:
    if os.name == "nt":
        return ["node", "-e", _WINDOWS_WRAPPER, kind, str(target), str(AUDIT_SKILL)]
    return ["node", str(VALIDATORS[kind]), str(target)]


def validate(kind: str, path: str | Path) -> tuple[int, str]:
    """Run the authoritative validator. Returns (exit_code, combined output)."""
    if kind not in VALIDATORS:
        raise ValueError(f"unknown validator {kind!r}; use 'findings' or 'ledger'")
    validator = VALIDATORS[kind]
    target = Path(path).expanduser().resolve()
    if not validator.exists():
        raise FileNotFoundError(f"vendored validator missing: {validator}")
    if not target.exists():
        raise FileNotFoundError(f"document not found: {target}")
    if not node_available():
        raise RuntimeError("Node.js 18+ is required to run the vendored validators "
                           "(install Node or skip bb audit validate)")
    proc = subprocess.run(_validator_command(kind, target), capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=120)
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode, output


def default_out_dir(repo: Path) -> Path:
    base = Path.home() / "security-audit-skill" / repo.name
    n = 1
    while (base / f"run-{n}").exists():
        n += 1
    return base / f"run-{n}"


def _git_source(repo: Path) -> tuple[str | None, bool]:
    try:
        sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                                capture_output=True, text=True, timeout=10).stdout
        return (sha or None), bool(status.strip())
    except Exception:
        return None, False


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def init_workspace(repo: str | Path, out: str | Path | None = None,
                   profile: str = "standard", scope: list[str] | None = None,
                   budget: int | None = None, allow_inside: bool = False) -> dict:
    """Create the skill's run directory with a valid empty contract.

    Refuses an output directory inside the target by default: the skill's write
    isolation requires audit artifacts to live outside the code under review.
    """
    repo_path = Path(repo).expanduser().resolve()
    if not repo_path.is_dir():
        raise ValueError(f"target repo is not a directory: {repo_path}")
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")

    out_path = Path(out).expanduser().resolve() if out else default_out_dir(repo_path)
    if not allow_inside and (_within(out_path, repo_path) or out_path == repo_path):
        raise ValueError(
            f"output directory {out_path} is inside the target {repo_path}; the skill "
            "requires an external output directory (use --allow-inside to override)")

    out_path.mkdir(parents=True, exist_ok=True)
    (out_path / "agents").mkdir(exist_ok=True)

    sha, dirty = _git_source(repo_path)
    source_ref = sha or "working-tree (not a git checkout)"
    if dirty and sha:
        source_ref += "+dirty"
    scope_paths = scope or ["."]
    created = now_iso()

    metadata = {
        "run_id": out_path.name,
        "repo": repo_path.name,
        "target": str(repo_path),
        "source_ref": source_ref,
        "worktree_dirty": dirty,
        "profile": profile,
        "scope_paths": scope_paths,
        "budget": budget,
        "execution_policy": "sandboxed-source-and-local-only",
        "companion_files": [],
        "prior_run_paths": [],
        "shared_file_owners": {
            "run-metadata.json": "parent",
            "architecture.md": "parent",
            "coverage-ledger.json": "parent",
            "findings.json": "parent",
        },
        "run_status": "in_progress",
        "scaffold": "bb audit init",
        "created_at": created,
    }
    (out_path / "run-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n",
                                                encoding="utf-8")
    (out_path / "coverage-ledger.json").write_text("[]\n", encoding="utf-8")
    (out_path / "findings.json").write_text("[]\n", encoding="utf-8")
    (out_path / "architecture.md").write_text(
        ARCHITECTURE_SCAFFOLD.format(
            repo_name=repo_path.name, target=repo_path, source_ref=source_ref,
            dirty_note=" (dirty worktree)" if dirty else "", profile=profile,
            scope_paths=", ".join(f"`{s}`" for s in scope_paths), created_at=created,
            skill_dir=AUDIT_SKILL),
        encoding="utf-8")
    (out_path / "README.md").write_text(
        RUN_README.format(skill_dir=AUDIT_SKILL, target=repo_path, out=out_path),
        encoding="utf-8")

    return {"out": out_path, "metadata": metadata,
            "files": sorted(p.name for p in out_path.iterdir())}


def ingest_skill(kb) -> int:
    """Add the vendored methodology docs to the knowledge base."""
    docs = []
    for path in sorted(AUDIT_SKILL.glob("*.md")):
        if path.name == "NOTICE.md":
            continue
        docs.append((f"security-audit/{path.stem}", path.read_text(encoding="utf-8"),
                     {"source": "cloudflare-security-audit", "path": str(path)}))
    return kb.add_documents(docs)


def skill_info() -> dict:
    notice = AUDIT_SKILL / "NOTICE.md"
    commit = ""
    if notice.exists():
        text = notice.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"commit\s*`([0-9a-f]{40})`", text, re.I)
        commit = match.group(1) if match else ""
    docs = sorted(p.name for p in AUDIT_SKILL.glob("*.md")) if AUDIT_SKILL.exists() else []
    return {"dir": AUDIT_SKILL, "exists": (AUDIT_SKILL / "SKILL.md").exists(),
            "commit": commit, "docs": docs,
            "validators": {k: v.exists() for k, v in VALIDATORS.items()},
            "schema": SCHEMA.exists(), "node": node_available()}
