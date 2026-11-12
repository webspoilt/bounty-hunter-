"""Bounty Hunter 2.0 - Nuclei General-Purpose DAST Adapter.

Official Repository: https://github.com/projectdiscovery/nuclei
License: MIT
Role: Community template-based vulnerability, exposure, and misconfiguration scanning.
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
    EngineState,
    ExecutionContext,
    FindingLifecycle,
)
from bb.models import Evidence, Exchange, Finding


logger = logging.getLogger(__name__)


class NucleiEngine(BaseEngine):
    """Adapter for Nuclei Vulnerability Scanner (ProjectDiscovery)."""

    def __init__(self):
        self._work_dir = DATA_DIR / "nuclei"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._rate_limit = 3.0
        self._timeout_sec = 240
        self._tags = "cve,exposure,misconfig,takeover"
        self._cached_avail: EngineAvailability | None = None

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def display_name(self) -> str:
        return "Nuclei Template Scanner"

    @property
    def version(self) -> str:
        avail = self.check_availability()
        return avail.version

    @property
    def official_repository(self) -> str:
        return "https://github.com/projectdiscovery/nuclei"

    @property
    def license(self) -> str:
        return "MIT"

    @property
    def category(self) -> EngineCategory:
        return EngineCategory.DAST

    def check_availability(self) -> EngineAvailability:
        if self._cached_avail is not None:
            return self._cached_avail
        binary = shutil.which("nuclei") or shutil.which("nuclei.exe")
        if binary:
            try:
                proc = subprocess.run([binary, "-version"], capture_output=True, text=True, timeout=3)
                self._cached_avail = EngineAvailability(
                    name=self.name,
                    state=EngineState.READY,
                    version=proc.stdout.strip().splitlines()[0] if proc.stdout else "installed",
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
            issues=["nuclei executable not found in PATH"],
            remediation_hint="Download from https://github.com/projectdiscovery/nuclei/releases or 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'",
        )
        return self._cached_avail


    def get_capabilities(self) -> list[str]:
        return ["cve", "exposure", "misconfig", "subdomain_takeover", "default_credentials", "api_leaks"]

    def validate_target(self, target: str) -> bool:
        return target.startswith(("http://", "https://"))

    def configure(self, config: dict[str, Any]) -> None:
        if "rate_limit" in config:
            self._rate_limit = float(config["rate_limit"])
        if "timeout_sec" in config:
            self._timeout_sec = int(config["timeout_sec"])
        if "tags" in config:
            self._tags = str(config["tags"])

    def execute(self, context: ExecutionContext) -> EngineExecutionResult:
        avail = self.check_availability()
        if not avail.available:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"Nuclei unavailable: {', '.join(avail.issues)}. Hint: {avail.remediation_hint}",
            )

        start_time = time.time()
        output_file = self._work_dir / f"nuclei_{int(start_time)}.jsonl"

        cmd = [
            avail.binary_path,
            "-u", context.target,
            "-rate-limit", str(int(context.rate_limit or self._rate_limit)),
            "-tags", self._tags,
            "-jsonl",
            "-output", str(output_file),
            "-silent",
        ]

        if context.dry_run:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=True,
                stdout=f"[DRY-RUN] Nuclei would execute: {' '.join(cmd)}",
                duration_sec=0.1,
            )

        try:
            logger.info("Executing Nuclei: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=context.timeout_sec or self._timeout_sec,
            )
            duration = time.time() - start_time

            findings = []
            if output_file.exists():
                findings = self.collect_findings(output_file, context)

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
                error=f"Nuclei execution error: {exc}",
                duration_sec=time.time() - start_time,
            )

    def collect_findings(self, raw_data: Any, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        path = Path(raw_data) if isinstance(raw_data, (str, Path)) else None
        if not path or not path.exists():
            return findings

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    template_id = item.get("template-id", "nuclei-finding")
                    info = item.get("info", {})
                    name = info.get("name", template_id)
                    severity = info.get("severity", "medium").lower()
                    matched = item.get("matched-at", context.target)
                    parsed = urlparse(matched)

                    req = item.get("request", "")
                    resp = item.get("response", "")

                    exchange = None
                    if req and resp:
                        exchange = Exchange(
                            method="GET",
                            url=matched,
                            status=200,
                            request_body=req,
                            response_body=resp[:2000],
                        )

                    f_obj = Finding(
                        title=f"[Nuclei] {name}",
                        bug_class=self._map_template_to_bug_class(template_id, info),
                        severity=severity if severity in ("low", "medium", "high", "critical") else "medium",
                        confidence="medium",  # Candidate finding until independently verified
                        host=parsed.netloc,
                        url=matched,
                        status=FindingLifecycle.DISCOVERED.value,  # Starts as DISCOVERED
                        summary=info.get("description", f"Nuclei matched template {template_id} at {matched}"),
                        impact="Identified security misconfiguration, known CVE, or exposed sensitive endpoint.",
                        remediation="Apply vendor patch, disable exposed panel, or correct server configuration.",
                        steps=[
                            f"1. Target URL: {matched}",
                            f"2. Template ID: {template_id}",
                            f"3. Matched at: {item.get('timestamp')}",
                        ],
                        evidence=[Evidence(summary=f"Nuclei template match {template_id}", exchange=exchange)] if exchange else [],
                        meta={
                            "discovery_engine": self.name,
                            "engine_version": self.version,
                            "program": context.program,
                            "template_id": template_id,
                            "cve_id": info.get("classification", {}).get("cve-id", []),
                            "upstream_status": f"nuclei_{severity}",
                            "verified_by": None,
                            "reproduced_by": None,
                        },
                    )

                    findings.append(f_obj)
                except Exception:
                    continue

        return findings

    def collect_evidence(self, finding: Finding) -> list[Evidence]:
        return finding.evidence

    def cleanup(self) -> None:
        pass

    @staticmethod
    def _map_template_to_bug_class(template_id: str, info: dict) -> str:
        t = template_id.lower()
        if "cve-" in t:
            return "cve"
        if "xss" in t:
            return "xss"
        if "sqli" in t or "sql" in t:
            return "sqli"
        if "cors" in t:
            return "cors"
        if "ssrf" in t:
            return "ssrf"
        if "exposure" in t or "panel" in t or "config" in t:
            return "exposed"
        return "vulnerability"
