"""Bounty Hunter 2.0 - Shannon Autonomous Pentesting Engine Adapter.

Official Repository: https://github.com/KeygraphHQ/shannon
License: AGPL-3.0
Role: Autonomous source-assisted web application and API penetration testing.
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


class ShannonEngine(BaseEngine):
    """Adapter for Shannon Autonomous Pentester (KeygraphHQ/shannon)."""

    def __init__(self):
        self._rate_limit = 3.0
        self._timeout_sec = 300
        self._custom_headers: dict[str, str] = {}
        self._work_dir = DATA_DIR / "shannon"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._cached_avail: EngineAvailability | None = None

    @property
    def name(self) -> str:
        return "shannon"

    @property
    def display_name(self) -> str:
        return "Shannon Autonomous Pentester"

    @property
    def version(self) -> str:
        avail = self.check_availability()
        return avail.version

    @property
    def official_repository(self) -> str:
        return "https://github.com/KeygraphHQ/shannon"

    @property
    def license(self) -> str:
        return "AGPL-3.0"

    @property
    def category(self) -> EngineCategory:
        return EngineCategory.AUTONOMOUS

    def check_availability(self) -> EngineAvailability:
        if self._cached_avail is not None:
            return self._cached_avail

        npx_path = shutil.which("npx")
        node_path = shutil.which("node")
        docker_path = shutil.which("docker")

        # Test if Docker daemon is running (mandatory for Shannon worker containers)
        docker_running = False
        docker_version = "unknown"
        if docker_path:
            try:
                proc_d = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=3)
                docker_running = (proc_d.returncode == 0)
                if docker_running:
                    ver_proc = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, timeout=3)
                    docker_version = ver_proc.stdout.strip() or "running"
            except Exception:
                docker_running = False

        if npx_path and node_path:
            try:
                proc = subprocess.run(["node", "-v"], capture_output=True, text=True, timeout=3)
                node_ver = proc.stdout.strip()
            except Exception:
                node_ver = "installed"

            # Shannon CLI uses npx, but spawns worker containers via Docker
            if not docker_running:
                self._cached_avail = EngineAvailability(
                    name=self.name,
                    state=EngineState.BLOCKED_DEPENDENCY,
                    version=f"npx ({node_ver}) [Docker daemon STOPPED]",
                    binary_path=npx_path,
                    issues=[
                        "Node.js/npx is installed, but Docker daemon is stopped",
                        "Shannon requires a running Docker daemon to launch worker containers",
                    ],
                    remediation_hint="Start Docker Desktop daemon to enable Shannon worker execution",
                )
                return self._cached_avail

            # Both npx and Docker daemon running
            self._cached_avail = EngineAvailability(
                name=self.name,
                state=EngineState.READY,
                version=f"npx ({node_ver}) / Docker {docker_version}",
                binary_path=npx_path,
            )
            return self._cached_avail

        if docker_path and docker_running:
            self._cached_avail = EngineAvailability(
                name=self.name,
                state=EngineState.READY,
                version=f"Docker container ({docker_version})",
                binary_path=docker_path,
            )
            return self._cached_avail

        self._cached_avail = EngineAvailability(
            name=self.name,
            state=EngineState.NOT_INSTALLED,
            version="not_installed",
            issues=["Neither Node.js/npx nor running Docker daemon found"],
            remediation_hint="Install Node.js (https://nodejs.org/) and start Docker Desktop",
        )
        return self._cached_avail



    def get_capabilities(self) -> list[str]:
        return [
            "source_assisted_pentest",
            "sqli",
            "xss",
            "ssrf",
            "broken_authn",
            "broken_authz",
            "api_exploitation",
            "proof_of_concept_validation",
        ]

    def validate_target(self, target: str) -> bool:
        if not target.startswith(("http://", "https://")):
            return False
        # Shannon performs active exploitation; verify target is non-empty
        return True

    def configure(self, config: dict[str, Any]) -> None:
        if "rate_limit" in config:
            self._rate_limit = float(config["rate_limit"])
        if "timeout_sec" in config:
            self._timeout_sec = int(config["timeout_sec"])
        if "custom_headers" in config:
            self._custom_headers = dict(config["custom_headers"])

    def execute(self, context: ExecutionContext) -> EngineExecutionResult:
        avail = self.check_availability()
        if not avail.available:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"Shannon unavailable: {', '.join(avail.issues)}. Hint: {avail.remediation_hint}",
            )

        start_time = time.time()
        output_sarif = self._work_dir / f"shannon_results_{int(start_time)}.sarif"

        # Resolve repo path
        repo_path = context.source_repo or Path.cwd()
        if isinstance(repo_path, str):
            repo_path = Path(repo_path)

        # Build CLI command
        target_url = context.target
        # Adjust loopback target if running via Docker
        parsed = urlparse(target_url)
        if "docker" in avail.version.lower() and parsed.hostname in ("127.0.0.1", "localhost"):
            target_url = target_url.replace(parsed.hostname, "host.docker.internal")

        cmd = [
            "npx", "@keygraph/shannon@latest", "start",
            "--url", target_url,
            "--repo", str(repo_path.resolve()),
        ]

        if context.dry_run:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=True,
                stdout=f"[DRY-RUN] Shannon would execute: {' '.join(cmd)}",
                duration_sec=0.1,
            )

        try:
            logger.info("Executing Shannon: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=context.timeout_sec or self._timeout_sec,
                cwd=str(self._work_dir),
            )
            duration = time.time() - start_time

            # Attempt to parse output SARIF or stdout JSON
            findings = []
            if output_sarif.exists():
                findings = self.collect_findings(output_sarif, context)
            elif "{" in proc.stdout:
                # Attempt to extract JSON from stdout
                try:
                    raw_json = json.loads(proc.stdout[proc.stdout.find("{"):proc.stdout.rfind("}")+1])
                    findings = self.collect_findings(raw_json, context)
                except Exception:
                    pass

            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=proc.returncode == 0 or len(findings) > 0,
                exit_code=proc.returncode,
                duration_sec=duration,
                stdout=proc.stdout,
                stderr=proc.stderr,
                findings=findings,
                meta={"command": cmd, "repo_path": str(repo_path)},
            )
        except subprocess.TimeoutExpired:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"Shannon run timed out after {self._timeout_sec}s",
                duration_sec=time.time() - start_time,
            )
        except Exception as exc:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=False,
                error=f"Shannon execution error: {exc}",
                duration_sec=time.time() - start_time,
            )

    def collect_findings(self, raw_data: Any, context: ExecutionContext) -> list[Finding]:
        """Parses Shannon SARIF or JSON output into Bounty Hunter Finding objects."""
        findings: list[Finding] = []

        if isinstance(raw_data, (str, Path)) and Path(raw_data).exists():
            try:
                with open(raw_data, "r", encoding="utf-8") as f:
                    sarif_data = json.load(f)
            except Exception:
                return findings
        elif isinstance(raw_data, dict):
            sarif_data = raw_data
        else:
            return findings

        # SARIF standard extraction
        runs = sarif_data.get("runs", [])
        for run in runs:
            results = run.get("results", [])
            for res in results:
                rule_id = res.get("ruleId", "SHANNON-VULN")
                msg = res.get("message", {}).get("text", "Shannon Autonomous Exploit Discovery")
                level = res.get("level", "warning")
                sev_map = {"error": "high", "warning": "medium", "note": "low"}
                severity = sev_map.get(level, "medium")

                # Extract location / endpoint
                locations = res.get("locations", [])
                target_url = context.target
                if locations:
                    uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    if uri.startswith("http"):
                        target_url = uri

                parsed = urlparse(target_url)
                host = parsed.netloc

                f = Finding(
                    title=f"[Shannon] {rule_id}: {msg[:80]}",
                    bug_class=self._map_rule_to_bug_class(rule_id),
                    severity=severity,
                    confidence="medium",  # Unverified candidate until independently verified
                    host=host,
                    url=target_url,
                    status=FindingLifecycle.DISCOVERED.value,  # Starts as DISCOVERED
                    summary=msg,
                    impact=f"Autonomously flagged attack path reported by Shannon against {target_url}.",
                    remediation="Apply secure coding controls on vulnerable source location identified by Shannon.",
                    steps=[
                        f"1. Target repository: {context.source_repo}",
                        f"2. Run: npx @keygraph/shannon start --url {target_url} --repo {context.source_repo}",
                        f"3. Verify exploit response matches SARIF rule {rule_id}.",
                    ],
                    meta={
                        "discovery_engine": self.name,
                        "engine_version": self.version,
                        "program": context.program,
                        "rule_id": rule_id,
                        "upstream_status": f"sarif_{level}",
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

    @staticmethod
    def _map_rule_to_bug_class(rule_id: str) -> str:
        r = rule_id.lower()
        if "sqli" in r or "sql" in r:
            return "sqli"
        if "xss" in r:
            return "xss"
        if "authz" in r or "idor" in r or "access" in r:
            return "idor"
        if "ssrf" in r:
            return "ssrf"
        if "authn" in r or "auth" in r:
            return "broken_authn"
        return "vulnerability"
