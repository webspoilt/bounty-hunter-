"""Bounty Hunter 2.0 - Semgrep Static Analysis (SAST) Engine Adapter.

Official Repository: https://github.com/semgrep/semgrep
License: LGPL-2.1 / Commercial
Role: Source-code vulnerability analysis and rule-based security pattern matching.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from bb.config import DATA_DIR
from bb.engines.base import (
    BaseEngine,
    EngineAvailability,
    EngineCategory,
    EngineExecutionResult,
    ExecutionContext,
)
from bb.models import Evidence, Finding

logger = logging.getLogger(__name__)


class SemgrepEngine(BaseEngine):
    """Adapter for Semgrep SAST Engine."""

    def __init__(self):
        self._work_dir = DATA_DIR / "semgrep"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._ruleset = "p/security-audit"
        self._cached_avail: EngineAvailability | None = None


    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def display_name(self) -> str:
        return "Semgrep Static Code Analyzer"

    @property
    def version(self) -> str:
        avail = self.check_availability()
        return avail.version

    @property
    def official_repository(self) -> str:
        return "https://github.com/semgrep/semgrep"

    @property
    def license(self) -> str:
        return "LGPL-2.1"

    @property
    def category(self) -> EngineCategory:
        return EngineCategory.SAST

    def check_availability(self) -> EngineAvailability:
        if self._cached_avail is not None:
            return self._cached_avail
        binary = shutil.which("semgrep") or shutil.which("semgrep.exe")
        if binary:
            try:
                proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5)
                lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                version_str = lines[-1] if lines else "installed"
                self._cached_avail = EngineAvailability(
                    name=self.name,
                    available=True,
                    version=version_str,
                    binary_path=binary,
                )
                return self._cached_avail
            except Exception:
                self._cached_avail = EngineAvailability(name=self.name, available=True, binary_path=binary)
                return self._cached_avail

        self._cached_avail = EngineAvailability(
            name=self.name,
            available=False,
            version="not_installed",
            issues=["semgrep executable not found in PATH"],
            remediation_hint="Install via 'pip install semgrep'",
        )
        return self._cached_avail


    def get_capabilities(self) -> list[str]:
        return [
            "sast",
            "sqli",
            "xss",
            "hardcoded_secrets",
            "insecure_deserialization",
            "command_injection",
            "cors_misconfiguration",
            "weak_crypto",
        ]

    def validate_target(self, target: str) -> bool:
        # Semgrep accepts source directories or file paths
        p = Path(target)
        return p.exists() or target.startswith(("http://", "https://"))

    def configure(self, config: dict[str, Any]) -> None:
        if "ruleset" in config:
            self._ruleset = str(config["ruleset"])

    def execute(self, context: ExecutionContext) -> EngineExecutionResult:
        avail = self.check_availability()
        if not avail.available:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"Semgrep unavailable: {', '.join(avail.issues)}. Hint: {avail.remediation_hint}",
            )

        start_time = time.time()
        source_target = context.source_repo or context.target

        # If target is a URL, check if context has source_repo configured
        if str(source_target).startswith(("http://", "https://")) and not context.source_repo:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error="Semgrep requires a local source repository path (context.source_repo). Target URL cannot be scanned purely via SAST.",
            )

        target_path = Path(source_target)
        if not target_path.exists():
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"Source repository path '{target_path}' does not exist.",
            )

        cmd = [
            avail.binary_path,
            "scan",
            "--config", "auto",
            "--json",
            "--metrics=off",
            str(target_path.resolve()),
        ]

        if context.dry_run:
            return EngineExecutionResult(
                engine_name=self.name,
                target=str(target_path),
                success=True,
                stdout=f"[DRY-RUN] Semgrep would execute: {' '.join(cmd)}",
                duration_sec=0.1,
            )

        try:
            logger.info("Executing Semgrep: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=context.timeout_sec or 300,
            )
            duration = time.time() - start_time

            findings = []
            if proc.stdout:
                try:
                    data = json.loads(proc.stdout)
                    findings = self.collect_findings(data, context)
                except Exception as exc:
                    logger.warning("Failed to parse Semgrep JSON output: %s", exc)

            return EngineExecutionResult(
                engine_name=self.name,
                target=str(target_path),
                success=proc.returncode in (0, 1), # Semgrep returns 1 when findings are present
                exit_code=proc.returncode,
                duration_sec=duration,
                stdout=proc.stdout[:2000],
                stderr=proc.stderr[:1000],
                findings=findings,
                meta={"findings_count": len(findings)},
            )
        except Exception as exc:
            return EngineExecutionResult(
                engine_name=self.name,
                target=str(target_path),
                success=False,
                error=f"Semgrep execution error: {exc}",
                duration_sec=time.time() - start_time,
            )

    def collect_findings(self, raw_data: Any, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(raw_data, dict):
            return findings

        results = raw_data.get("results", [])
        for res in results:
            check_id = res.get("check_id", "semgrep-finding")
            extra = res.get("extra", {})
            msg = extra.get("message", "Semgrep security pattern matched")
            sev = extra.get("severity", "WARNING").lower()
            sev_map = {"error": "high", "warning": "medium", "info": "low"}
            severity = sev_map.get(sev, "medium")

            path = res.get("path", "")
            start_line = res.get("start", {}).get("line", 1)
            code_snippet = extra.get("lines", "")

            # Map check_id to bug class
            bug_class = self._map_check_id_to_bug_class(check_id)

            f = Finding(
                title=f"[Semgrep] {check_id}: {msg[:80]}",
                bug_class=bug_class,
                severity=severity,
                confidence="medium",
                host="source-code",
                url=f"{path}#L{start_line}",
                status="hypothesis",
                summary=f"{msg}\nFile: {path}:{start_line}",
                impact=f"Static code vulnerability pattern detected in {path}.",
                remediation="Refactor code according to Semgrep security rule guidance.",
                steps=[
                    f"1. Inspect file: {path} at line {start_line}",
                    f"2. Matched code pattern:\n{code_snippet}",
                ],
                evidence=[Evidence(summary=f"Code at {path}:{start_line}", extra={"snippet": code_snippet, "check_id": check_id})],
                meta={
                    "discovery_engine": self.name,
                    "engine_version": self.version,
                    "program": context.program,
                    "check_id": check_id,
                    "cwe": extra.get("metadata", {}).get("cwe", []),
                },
            )
            findings.append(f)

        return findings

    def collect_evidence(self, finding: Finding) -> list[Evidence]:
        return finding.evidence

    def cleanup(self) -> None:
        pass

    @staticmethod
    def _map_check_id_to_bug_class(check_id: str) -> str:
        c = check_id.lower()
        if "sql" in c:
            return "sqli"
        if "xss" in c:
            return "xss"
        if "cors" in c:
            return "cors"
        if "ssrf" in c:
            return "ssrf"
        if "secret" in c or "key" in c or "password" in c:
            return "exposed_secret"
        if "crypto" in c or "md5" in c or "sha1" in c:
            return "weak_crypto"
        return "code_vulnerability"
