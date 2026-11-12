"""Bounty Hunter 2.0 - Dalfox Specialist XSS Adapter.

Official Repository: https://github.com/hahwul/dalfox
License: MIT
Role: Fast, parameter-focused Cross-Site Scripting (XSS) scanner and PoC generator.
"""
from __future__ import annotations

import json
import logging
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
    ExecutionContext,
)
from bb.models import Evidence, Finding

logger = logging.getLogger(__name__)


class DalfoxEngine(BaseEngine):
    """Adapter for Dalfox XSS Specialist Engine."""

    def __init__(self):
        self._work_dir = DATA_DIR / "dalfox"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._rate_limit = 3.0
        self._timeout_sec = 120

    @property
    def name(self) -> str:
        return "dalfox"

    @property
    def display_name(self) -> str:
        return "Dalfox XSS Specialist"

    @property
    def version(self) -> str:
        avail = self.check_availability()
        return avail.version

    @property
    def official_repository(self) -> str:
        return "https://github.com/hahwul/dalfox"

    @property
    def license(self) -> str:
        return "MIT"

    @property
    def category(self) -> EngineCategory:
        return EngineCategory.SPECIALIST

    def check_availability(self) -> EngineAvailability:
        binary = shutil.which("dalfox") or shutil.which("dalfox.exe")
        if binary:
            try:
                proc = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=5)
                return EngineAvailability(
                    name=self.name,
                    available=True,
                    version=proc.stdout.strip().splitlines()[0] if proc.stdout else "installed",
                    binary_path=binary,
                )
            except Exception:
                return EngineAvailability(name=self.name, available=True, binary_path=binary)

        return EngineAvailability(
            name=self.name,
            available=False,
            version="not_installed",
            issues=["dalfox not found in PATH"],
            remediation_hint="Download from https://github.com/hahwul/dalfox/releases or 'go install github.com/hahwul/dalfox/v2@latest'",
        )

    def get_capabilities(self) -> list[str]:
        return ["xss", "reflected_xss", "stored_xss", "dom_xss", "blind_xss"]

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
                error=f"Dalfox unavailable: {', '.join(avail.issues)}. Hint: {avail.remediation_hint}",
            )

        start_time = time.time()
        cmd = [
            avail.binary_path,
            "url", context.target,
            "--format", "json",
            "--delay", str(int(1000 / self._rate_limit)),
            "--waf-evasion",
            "--silence",
        ]

        if context.dry_run:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=True,
                stdout=f"[DRY-RUN] Dalfox would execute: {' '.join(cmd)}",
                duration_sec=0.1,
            )

        try:
            logger.info("Executing Dalfox: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=context.timeout_sec or self._timeout_sec,
            )
            duration = time.time() - start_time

            findings = self.collect_findings(proc.stdout, context)

            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=proc.returncode == 0,
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
                target=context.target,
                success=False,
                error=f"Dalfox execution error: {exc}",
                duration_sec=time.time() - start_time,
            )

    def collect_findings(self, raw_output: Any, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        if not raw_output:
            return findings

        # Parse line-delimited JSON
        lines = str(raw_output).splitlines()
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
                param = item.get("param", "unknown")
                poc = item.get("data", "")
                severity = item.get("severity", "medium").lower()
                parsed = urlparse(context.target)

                f = Finding(
                    title=f"[Dalfox] Verified XSS on parameter '{param}'",
                    bug_class="xss",
                    severity="high" if severity in ("high", "critical") else "medium",
                    confidence="high",
                    host=parsed.netloc,
                    url=context.target,
                    status="verified",
                    summary=f"Dalfox verified Cross-Site Scripting on parameter '{param}' at {context.target}.",
                    impact="An attacker can execute arbitrary JavaScript in the victim's browser context, steal session cookies, or initiate unauthorized state-changing actions.",
                    remediation="Apply context-aware HTML entity encoding or Content-Security-Policy (CSP) headers.",
                    steps=[
                        f"1. Target endpoint: {context.target}",
                        f"2. Payload injected into parameter '{param}': {poc}",
                        "3. Verify script execution or unescaped reflection.",
                    ],
                    evidence=[Evidence(summary=f"XSS PoC on {param}", extra={"poc": poc, "param": param})],
                    meta={
                        "discovery_engine": self.name,
                        "engine_version": self.version,
                        "program": context.program,
                        "param": param,
                        "cwe": "CWE-79",
                    },
                )
                findings.append(f)
            except Exception:
                continue

        return findings

    def collect_evidence(self, finding: Finding) -> list[Evidence]:
        return finding.evidence

    def cleanup(self) -> None:
        pass
