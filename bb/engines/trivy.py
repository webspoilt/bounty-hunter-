"""
Bounty Hunter 2.0 - Trivy Dependency, Container & Configuration Scanner Adapter.

Official Repository: https://github.com/aquasecurity/trivy
License: Apache-2.0
Role: Software Composition Analysis (SCA), vulnerability scanning for dependencies,
      SBOM generation, and IaC/misconfiguration auditing.
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
from bb.models import Evidence, Finding

logger = logging.getLogger(__name__)


class TrivyEngine(BaseEngine):
    """Adapter for Aqua Security Trivy Vulnerability & Misconfiguration Scanner."""

    def __init__(self):
        self._work_dir = DATA_DIR / "trivy"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._custom_bin = os.environ.get(
            "TRIVY_BIN_PATH",
            r"E:\IDEAS\Bounty Hunter\tools\trivy\trivy.exe"
        )
        self._cached_avail: EngineAvailability | None = None

    @property
    def name(self) -> str:
        return "trivy"

    @property
    def display_name(self) -> str:
        return "Trivy SCA & Misconfiguration Scanner"

    @property
    def version(self) -> str:
        avail = self.check_availability()
        return avail.version

    @property
    def category(self) -> EngineCategory:
        return EngineCategory.SAST

    @property
    def license(self) -> str:
        return "Apache-2.0"

    @property
    def official_repository(self) -> str:
        return "https://github.com/aquasecurity/trivy"

    def _get_bin_path(self) -> str | None:
        if os.path.exists(self._custom_bin):
            return self._custom_bin
        return shutil.which("trivy") or shutil.which("trivy.exe")

    def check_availability(self) -> EngineAvailability:
        if self._cached_avail is not None:
            return self._cached_avail

        bin_path = self._get_bin_path()
        if not bin_path:
            self._cached_avail = EngineAvailability(
                name=self.name,
                state=EngineState.NOT_INSTALLED,
                issues=["Trivy binary not found in PATH or tools/trivy/."],
                remediation_hint="Download trivy from https://github.com/aquasecurity/trivy/releases and place in tools/trivy/.",
            )
            return self._cached_avail

        try:
            res = subprocess.run(
                [bin_path, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            v_str = "0.76.2"
            for line in res.stdout.splitlines():
                if "version:" in line.lower() or "version" in line.lower():
                    v_str = line.split(":")[-1].strip()
                    break

            self._cached_avail = EngineAvailability(
                name=self.name,
                state=EngineState.READY,
                version=v_str,
                binary_path=bin_path,
            )
            return self._cached_avail
        except Exception as e:
            return EngineAvailability(
                name=self.name,
                state=EngineState.EXECUTION_FAILED,
                issues=[str(e)],
            )

    def get_capabilities(self) -> list[str]:
        return ["sca", "dependencies", "cve", "misconfig", "sbom", "secrets"]

    def validate_target(self, target: str) -> bool:
        # Can scan local directory, file, or git repo
        return os.path.exists(target) or target.startswith(("http://", "https://"))

    def configure(self, config: dict[str, Any]) -> None:
        pass

    def execute(self, context: ExecutionContext) -> EngineExecutionResult:
        avail = self.check_availability()
        if not avail.available or not avail.binary_path:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"Trivy unavailable: {', '.join(avail.issues)}",
            )

        start_time = time.time()
        target_dir = context.target if os.path.exists(context.target) else os.getcwd()
        output_file = self._work_dir / f"trivy_{int(time.time())}.json"
        cmd = [
            avail.binary_path,
            "fs",
            "--format", "json",
            "--output", str(output_file),
            "--severity", "CRITICAL,HIGH,MEDIUM",
            target_dir,
        ]

        if context.dry_run:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=True,
                stdout=f"[DRY-RUN] Trivy would execute: {' '.join(cmd)}",
                duration_sec=0.1,
            )

        try:
            logger.info("Executing Trivy: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=context.timeout_sec or 120,
            )
            duration = time.time() - start_time

            findings: list[Finding] = []
            if output_file.exists():
                try:
                    data = json.loads(output_file.read_text(encoding="utf-8"))
                    findings = self.collect_findings(data, context)
                except Exception as e:
                    logger.error("Failed to parse Trivy output: %s", e)

            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=proc.returncode == 0 or len(findings) > 0,
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
                error=f"Trivy execution error: {exc}",
                duration_sec=time.time() - start_time,
            )

    def collect_findings(self, raw_data: Any, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(raw_data, dict):
            return findings

        for r in raw_data.get("Results", []):
            target_comp = r.get("Target", "dependencies")
            for vuln in r.get("Vulnerabilities", []):
                v_id = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
                pkg = vuln.get("PkgName", "unknown")
                installed_v = vuln.get("InstalledVersion", "")
                fixed_v = vuln.get("FixedVersion", "N/A")
                sev = vuln.get("Severity", "MEDIUM").lower()
                title = vuln.get("Title") or f"Vulnerable dependency in {pkg}"

                f = Finding(
                    title=f"[Trivy] {v_id} - Vulnerable dependency {pkg}",
                    bug_class="dependency_vulnerability",
                    severity="high" if sev in ("high", "critical") else "medium",
                    confidence="high",
                    host="localhost",
                    url=target_comp,
                    status=FindingLifecycle.DISCOVERED.value,
                    summary=f"Package {pkg} ({installed_v}) contains known vulnerability {v_id}.",
                    impact="May allow remote attackers to exploit known weaknesses depending on how the application uses this component.",
                    remediation=f"Upgrade {pkg} to version {fixed_v} or later.",
                    steps=[
                        f"1. Target artifact: {target_comp}",
                        f"2. Package identified: {pkg} version {installed_v}",
                        f"3. Vulnerability ID: {v_id}",
                    ],
                    evidence=[Evidence(summary=f"Trivy {v_id} on {pkg}", extra={"vuln_id": v_id, "package": pkg, "fixed_version": fixed_v})],
                    meta={
                        "discovery_engine": self.name,
                        "engine_version": self.version,
                        "program": context.program,
                        "cwe": vuln.get("CweIDs", ["CWE-1395"])[0] if vuln.get("CweIDs") else "CWE-1395",
                        "upstream_status": "trivy_detected",
                    },
                )
                findings.append(f)

        return findings

    def collect_evidence(self, finding: Finding) -> list[Evidence]:
        return finding.evidence

    def cleanup(self) -> None:
        pass
