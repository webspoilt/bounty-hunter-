"""Bounty Hunter 2.0 - Dalfox Specialist XSS Adapter.

Official Repository: https://github.com/hahwul/dalfox
License: MIT
Role: Fast, parameter-focused Cross-Site Scripting (XSS) scanner and PoC generator.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bb.config import DATA_DIR, PROJECT_ROOT
from bb.engines.base import (
    BaseEngine,
    EngineAvailability,
    EngineCategory,
    EngineExecutionResult,
    EngineState,
    ExecutionContext,
    FindingLifecycle,
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
        self._cached_avail: EngineAvailability | None = None

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
        if self._cached_avail is not None:
            return self._cached_avail
        binary = shutil.which("dalfox") or shutil.which("dalfox.exe")
        if not binary:
            for cand in [
                PROJECT_ROOT / "tools" / "dalfox" / "dalfox.exe",
                PROJECT_ROOT / "tools" / "dalfox" / "dalfox",
                PROJECT_ROOT.parent / "tools" / "dalfox" / "dalfox.exe",
                PROJECT_ROOT.parent / "tools" / "dalfox" / "dalfox",
            ]:
                if cand.exists():
                    binary = str(cand)
                    break
        if binary:
            try:
                proc = subprocess.run([binary, "version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3)
                combined = (proc.stdout or "") + (proc.stderr or "")
                m = re.search(r"v\d+\.\d+\.\d+", combined)
                version_str = m.group(0) if m else "v2.13.0"
                self._cached_avail = EngineAvailability(
                    name=self.name,
                    state=EngineState.READY,
                    version=version_str,
                    binary_path=binary,
                )
                return self._cached_avail
            except Exception:
                self._cached_avail = EngineAvailability(name=self.name, state=EngineState.READY, binary_path=binary)
                return self._cached_avail

        self._cached_avail = EngineAvailability(
            name=self.name,
            state=EngineState.NOT_INSTALLED,
            version="not_installed",
            issues=["dalfox not found in PATH"],
            remediation_hint="Download from https://github.com/hahwul/dalfox/releases or 'go install github.com/hahwul/dalfox/v2@latest'",
        )
        return self._cached_avail


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
        is_loopback = "127.0.0.1" in context.target or "localhost" in context.target
        cmd = [
            avail.binary_path,
            "url", context.target,
            "--format", "json",
            "--silence",
            "--only-poc", "v,r",
            "--mining-dict=false",
            "--mining-dom=false",
        ]
        if not is_loopback:
            cmd.extend(["--delay", str(int(1000 / self._rate_limit))])

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
                encoding="utf-8",
                errors="replace",
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

        items: list[dict] = []
        text = str(raw_output).strip()
        try:
            parsed_json = json.loads(text)
            if isinstance(parsed_json, list):
                items.extend([x for x in parsed_json if isinstance(x, dict)])
            elif isinstance(parsed_json, dict):
                items.append(parsed_json)
        except Exception:
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if line.startswith("{") and line.endswith("}"):
                    try:
                        items.append(json.loads(line))
                    except Exception:
                        pass

        for item in items:
            param = item.get("param", "")
            if not param:
                continue
            poc = item.get("data", "") or item.get("payload", "")
            severity = item.get("severity", "medium").lower()
            parsed = urlparse(context.target)

            f = Finding(
                title=f"[Dalfox] Identified Reflected XSS on parameter '{param}'",
                bug_class="xss",
                severity="high" if severity in ("high", "critical") else "medium",
                confidence="high" if item.get("type") == "V" else "medium",
                host=parsed.netloc,
                url=item.get("data") or context.target,
                status=FindingLifecycle.DISCOVERED.value,
                summary=f"Dalfox identified Cross-Site Scripting on parameter '{param}' at {context.target}.",
                impact="An attacker can execute arbitrary JavaScript in the victim's browser context, steal session cookies, or initiate unauthorized state-changing actions.",
                remediation="Apply context-aware HTML entity encoding or Content-Security-Policy (CSP) headers.",
                steps=[
                    f"1. Target endpoint: {context.target}",
                    f"2. Payload injected into parameter '{param}': {poc}",
                    "3. Verify script execution or unescaped reflection.",
                ],
                evidence=[Evidence(summary=f"XSS PoC on {param}", extra={"poc": poc, "param": param, "dalfox_type": item.get("type")})],
                meta={
                    "discovery_engine": self.name,
                    "engine_version": self.version,
                    "program": context.program,
                    "param": param,
                    "cwe": item.get("cwe", "CWE-79"),
                    "upstream_status": "dalfox_verified" if item.get("type") == "V" else "dalfox_poc_candidate",
                    "active_discovery": True,
                    "imported_finding": False,
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
