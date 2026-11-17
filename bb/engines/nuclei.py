"""Bounty Hunter 2.0 - Nuclei General-Purpose DAST Adapter.

Official Repository: https://github.com/projectdiscovery/nuclei
License: MIT
Role: Community template-based vulnerability, exposure, and misconfiguration scanning.
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
    def template_version(self) -> str:
        cfg_path = Path.home() / "AppData" / "Roaming" / "nuclei" / ".templates-config.json"
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
                return data.get("nuclei-templates-version") or data.get("nuclei-templates-latest-version") or "v10.5.2"
            except Exception:
                pass
        return "v10.5.2"

    @property
    def templates_directory(self) -> Path:
        cfg_path = Path.home() / "AppData" / "Roaming" / "nuclei" / ".templates-config.json"
        if cfg_path.exists():
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
                p = data.get("nuclei-templates-directory")
                if p and Path(p).exists():
                    return Path(p)
            except Exception:
                pass
        return Path.home() / "nuclei-templates"

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
        if not binary:
            for cand in [
                PROJECT_ROOT / "tools" / "nuclei" / "nuclei.exe",
                PROJECT_ROOT / "tools" / "nuclei" / "nuclei",
                PROJECT_ROOT.parent / "tools" / "nuclei" / "nuclei.exe",
                PROJECT_ROOT.parent / "tools" / "nuclei" / "nuclei",
            ]:
                if cand.exists():
                    binary = str(cand)
                    break
        if binary:
            try:
                proc = subprocess.run([binary, "-version"], capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=3)
                combined = (proc.stdout or "") + (proc.stderr or "")
                m = re.search(r"v\d+\.\d+\.\d+", combined)
                version_str = m.group(0) if m else "v3.11.1"
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

        # Determine templates path: explicit flags > bundled safe templates > tags
        custom_t = None
        for flag in context.extra_flags:
            if flag.startswith("-t=") or flag.startswith("--template="):
                custom_t = flag.split("=", 1)[1]
                break

        template_arg: list[str] = []
        if custom_t and Path(custom_t).exists():
            template_arg = ["-t", custom_t]
        else:
            bundled_templates = Path(__file__).resolve().parent.parent.parent / "templates" / "nuclei"
            if bundled_templates.exists():
                template_arg = ["-t", str(bundled_templates)]
            elif self._tags:
                template_arg = ["-tags", self._tags]

        cmd = [
            avail.binary_path,
            "-u", context.target,
            "-rate-limit", str(int(context.rate_limit or self._rate_limit)),
            *template_arg,
            "-etags", "dos,fuzz,intrusive",
            "-jsonl",
            "-output", str(output_file),
            "-silent",
            "-duc",
            "-no-stdin",
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
                encoding="utf-8",
                errors="replace",
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
        seen_keys: set[str] = set()
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
                    dedupe_key = f"{template_id}:{matched}"
                    if dedupe_key in seen_keys:
                        continue
                    seen_keys.add(dedupe_key)

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
                            "template_version": self.template_version,
                            "program": context.program,
                            "template_id": template_id,
                            "cve_id": info.get("classification", {}).get("cve-id", []),
                            "upstream_status": f"nuclei_{severity}",
                            "active_discovery": True,
                            "imported_finding": False,
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
