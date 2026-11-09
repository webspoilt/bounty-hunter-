"""Persistent Task Manifest for coding agent handoffs.

Tracks the exact state of work, current provider, branch/worktree, git diff,
acceptance criteria, test results, unfinished tasks, and next recommended actions.
All git inspections are strictly read-only; no destructive git operations are
ever executed.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from bb.config import DATA, ROOT, now_iso

DEFAULT_MANIFEST_PATH = DATA / "task_manifest.json"


@dataclass
class TaskManifest:
    task_id: str
    objective: str
    current_provider: str = "primary"  # e.g. "antigravity", "codex", "qwen"
    branch: str = ""
    worktree: str = ""
    last_known_commit: str = ""
    files_changed: list[str] = field(default_factory=list)
    acceptance_criteria: list[str] = field(default_factory=list)
    tests_run: list[str] = field(default_factory=list)
    test_results: dict[str, Any] = field(default_factory=dict)
    unfinished_tasks: list[str] = field(default_factory=list)
    known_issues: list[str] = field(default_factory=list)
    next_action: str = ""
    git_diff_stat: str = ""
    git_diff_patch: str = ""
    manifest_path: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TaskManifest:
        valid_keys = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def save(self, path: Path | str | None = None) -> Path:
        target = Path(path) if path else (Path(self.manifest_path) if self.manifest_path else DEFAULT_MANIFEST_PATH)
        target.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path = str(target.resolve())
        self.updated_at = now_iso()
        with open(target, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        return target

    @classmethod
    def load(cls, path: Path | str | None = None) -> TaskManifest:
        target = Path(path) if path else DEFAULT_MANIFEST_PATH
        if not target.exists():
            raise FileNotFoundError(f"Task manifest not found at: {target}")
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        obj = cls.from_dict(data)
        obj.manifest_path = str(target.resolve())
        return obj

    def refresh_git_status(self, repo_dir: Path | str | None = None) -> None:
        """Inspect working tree using strictly read-only git queries."""
        cwd = Path(repo_dir) if repo_dir else ROOT

        # Branch
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                cwd=cwd,
                timeout=5.0,
            )
            if r.returncode == 0:
                self.branch = r.stdout.strip()
        except Exception:
            pass

        # Worktree absolute path
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                cwd=cwd,
                timeout=5.0,
            )
            if r.returncode == 0:
                self.worktree = str(Path(r.stdout.strip()).resolve())
            else:
                self.worktree = str(cwd.resolve())
        except Exception:
            self.worktree = str(cwd.resolve())

        # Last known commit
        try:
            r = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                cwd=cwd,
                timeout=5.0,
            )
            if r.returncode == 0:
                self.last_known_commit = r.stdout.strip()
        except Exception:
            pass

        # Files changed (working tree dirty state)
        try:
            r = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                cwd=cwd,
                timeout=5.0,
            )
            if r.returncode == 0:
                lines = [line.strip() for line in r.stdout.splitlines() if line.strip()]
                self.files_changed = lines
        except Exception:
            pass

        # Diff stat
        try:
            r = subprocess.run(
                ["git", "diff", "--stat"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                cwd=cwd,
                timeout=5.0,
            )
            if r.returncode == 0:
                self.git_diff_stat = r.stdout.strip()
        except Exception:
            pass

        # Diff patch (capped to prevent huge files in manifest)
        try:
            r = subprocess.run(
                ["git", "diff"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                cwd=cwd,
                timeout=10.0,
            )
            if r.returncode == 0:
                patch = r.stdout
                if len(patch) > 100_000:
                    patch = patch[:100_000] + "\n... [diff truncated at 100k chars]"
                self.git_diff_patch = patch
        except Exception:
            pass

        self.updated_at = now_iso()

    def check_branch_match(self, repo_dir: Path | str | None = None) -> bool:
        """Verify that current working tree branch matches the manifest branch."""
        if not self.branch:
            return True
        cwd = Path(repo_dir) if repo_dir else ROOT
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                cwd=cwd,
                timeout=5.0,
            )
            if r.returncode == 0:
                current = r.stdout.strip()
                return current == self.branch
        except Exception:
            pass
        return True

    def validate(self, check_branch: bool = False, repo_dir: Path | str | None = None) -> list[str]:
        """Check essential fields are present and optionally verify branch alignment."""
        errors: list[str] = []
        if not self.task_id.strip():
            errors.append("Missing task_id")
        if not self.objective.strip():
            errors.append("Missing objective")
        if not self.current_provider.strip():
            errors.append("Missing current_provider")
        if check_branch and self.branch and not self.check_branch_match(repo_dir):
            errors.append(f"Branch mismatch: manifest recorded on '{self.branch}', but repository is on a different branch")
        return errors

    def resume_task(self, next_action: str = "", new_criteria: list[str] | None = None) -> None:
        """Resume an in-progress task and refresh read-only git context."""
        self.refresh_git_status()
        if next_action:
            self.next_action = next_action
        if new_criteria:
            for c in new_criteria:
                if c not in self.acceptance_criteria:
                    self.acceptance_criteria.append(c)
        self.updated_at = now_iso()
        self.save()
