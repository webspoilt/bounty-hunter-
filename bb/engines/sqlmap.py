"""Bounty Hunter 2.0 - SQLmap Specialist Injection Adapter.

Official Repository: https://github.com/sqlmapproject/sqlmap
License: GPL-2.0
Role: Specialist SQL injection detection and non-destructive proof-of-concept verification.
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
from urllib.parse import urlparse

from bb.config import DATA_DIR
from bb.engines.base import (
    BaseEngine,
    EngineAvailability,
    EngineCategory,
    EngineExecutionResult,
    EngineState,
    ExecutionContext,
    FindingLifecycle,
)
from bb.models import Evidence, Exchange, Finding


logger = logging.getLogger(__name__)


class SQLmapEngine(BaseEngine):
    """Adapter for SQLmap Specialist Engine."""

    def __init__(self):
        self._work_dir = DATA_DIR / "sqlmap"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._rate_limit = 3.0
        self._timeout_sec = 180
        self._cached_avail: EngineAvailability | None = None


    @property
    def name(self) -> str:
        return "sqlmap"

    @property
    def display_name(self) -> str:
        return "SQLmap Specialist Engine"

    @property
    def version(self) -> str:
        avail = self.check_availability()
        return avail.version

    @property
    def official_repository(self) -> str:
        return "https://github.com/sqlmapproject/sqlmap"

    @property
    def license(self) -> str:
        return "GPL-2.0"

    @property
    def category(self) -> EngineCategory:
        return EngineCategory.SPECIALIST

    def check_availability(self) -> EngineAvailability:
        if self._cached_avail is not None:
            return self._cached_avail
        binary = shutil.which("sqlmap") or shutil.which("sqlmap.exe") or shutil.which("sqlmap.py")
        if binary:
            try:
                proc = subprocess.run([binary, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", input="\n", timeout=3)
                v_lines = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip() and not l.startswith("Press")]
                version_str = v_lines[0] if v_lines else "installed"
                self._cached_avail = EngineAvailability(
                    name=self.name,
                    state=EngineState.READY,
                    version=version_str,
                    binary_path=binary,
                )
                return self._cached_avail
            except Exception:
                self._cached_avail = EngineAvailability(name=self.name, state=EngineState.READY, version="1.10.11", binary_path=binary)
                return self._cached_avail

        self._cached_avail = EngineAvailability(
            name=self.name,
            state=EngineState.NOT_INSTALLED,
            version="not_installed",
            issues=["sqlmap not found in Windows PATH"],
            remediation_hint="Clone sqlmap (git clone https://github.com/sqlmapproject/sqlmap.git) or use Kali WSL",
        )
        return self._cached_avail



    def get_capabilities(self) -> list[str]:
        return ["sqli", "blind_sqli", "time_based_sqli", "error_based_sqli", "union_sqli"]

    def validate_target(self, target: str) -> bool:
        return target.startswith(("http://", "https://"))

    def configure(self, config: dict[str, Any]) -> None:
        if "rate_limit" in config:
            self._rate_limit = float(config["rate_limit"])
        if "timeout_sec" in config:
            self._timeout_sec = int(config["timeout_sec"])

    def execute(self, context: ExecutionContext) -> EngineExecutionResult:
        avail = self.check_availability()
        if not avail.available:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"SQLmap unavailable: {', '.join(avail.issues)}. Hint: {avail.remediation_hint}",
            )

        start_time = time.time()
        output_dir = self._work_dir / f"run_{int(start_time)}"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Strict safety flags: non-destructive, single thread, low risk, enforced rate limit delay
        rate = context.rate_limit or self._rate_limit
        is_loopback = "127.0.0.1" in context.target or "localhost" in context.target
        delay_sec = 0.1 if is_loopback else round(1.0 / max(rate, 0.1), 2)
        base_cmd = [
            avail.binary_path,
            "-u", context.target,
            "--batch",
            "--random-agent",
            "--threads=1",
            "--level=1",
            "--risk=1",
            f"--delay={delay_sec}",
        ]


        if context.dry_run:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=True,
                stdout=f"[DRY-RUN] SQLmap would execute: {' '.join(base_cmd)}",
                duration_sec=0.1,
            )

        try:
            logger.info("Executing SQLmap: %s", " ".join(base_cmd))
            proc = subprocess.run(
                base_cmd,
                input="\n",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=context.timeout_sec or self._timeout_sec,
            )
            duration = time.time() - start_time

            findings = self.collect_findings(proc.stdout, context)

            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=len(findings) > 0 or proc.returncode == 0,
                exit_code=proc.returncode,
                duration_sec=duration,
                stdout=proc.stdout[:2000],
                stderr=proc.stderr[:1000],
                findings=findings,
                meta={"findings_count": len(findings)},
            )
        except subprocess.TimeoutExpired:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"SQLmap timed out after {self._timeout_sec}s",
                duration_sec=time.time() - start_time,
            )
        except Exception as exc:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"SQLmap execution error: {exc}",
                duration_sec=time.time() - start_time,
            )

    def collect_findings(self, raw_output: Any, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        text = str(raw_output)

        # Check for confirmed injection markers in SQLmap output
        lower_text = text.lower()
        is_injectable = (
            "the following injection point" in lower_text
            or "is vulnerable" in lower_text
            or ("parameter:" in lower_text and "payload:" in lower_text)
        )
        if not is_injectable:
            return findings

        parsed = urlparse(context.target)
        host = parsed.netloc

        f = Finding(
            title=f"[SQLmap] Identified SQL Injection on {parsed.path}",
            bug_class="sqli",
            severity="critical",
            confidence="medium",  # Candidate finding until independently verified
            host=host,
            url=context.target,
            status=FindingLifecycle.DISCOVERED.value,  # Starts as DISCOVERED
            summary=f"SQLmap identified SQL injection on endpoint {context.target}.",
            impact="An attacker can execute arbitrary SQL queries against the database, leading to complete database compromise and confidential data exfiltration.",
            remediation="Enforce parameterized queries (prepared statements) for all database operations.",
            steps=[
                f"1. Target URL: {context.target}",
                f"2. Execute SQLmap probe: sqlmap -u '{context.target}' --batch",
                "3. Observe SQL parameter vulnerability confirmation.",
            ],
            evidence=[Evidence(summary="SQLmap Injection Summary", extra={"raw_output_snippet": text[:1000]})],
            meta={
                "discovery_engine": self.name,
                "engine_version": self.version,
                "program": context.program,
                "cwe": "CWE-89",
                "upstream_status": "sqlmap_confirmed_injection",
                "verified_by": None,
                "reproduced_by": None,
            },
        )

        findings.append(f)
        return findings

    def collect_evidence(self, finding: Finding) -> list[Evidence]:
        return finding.evidence

    def cleanup(self) -> None:
        pass
