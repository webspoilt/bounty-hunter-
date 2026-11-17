"""
Bounty Hunter 2.0 - TruffleHog Secret & Leaked Credential Discovery Adapter.

Official Repository: https://github.com/trufflesecurity/trufflehog
License: AGPL-3.0
Role: High-confidence secret detection (API keys, private keys, database credentials)
      with non-invasive credential scanning.
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
    EngineState,
    ExecutionContext,
    FindingLifecycle,
)
from bb.models import Evidence, Finding

logger = logging.getLogger(__name__)


class TruffleHogEngine(BaseEngine):
    """Adapter for TruffleHog Leaked Secret Scanner."""

    def __init__(self):
        self._work_dir = DATA_DIR / "trufflehog"
        self._work_dir.mkdir(parents=True, exist_ok=True)
        self._custom_bin = os.environ.get(
            "TRUFFLEHOG_BIN_PATH",
            r"E:\IDEAS\Bounty Hunter\tools\trufflehog\trufflehog.exe"
        )
        self._cached_avail: EngineAvailability | None = None

    @property
    def name(self) -> str:
        return "trufflehog"

    @property
    def display_name(self) -> str:
        return "TruffleHog Secret Scanner"

    @property
    def version(self) -> str:
        avail = self.check_availability()
        return avail.version

    @property
    def category(self) -> EngineCategory:
        return EngineCategory.SAST

    @property
    def license(self) -> str:
        return "AGPL-3.0"

    @property
    def official_repository(self) -> str:
        return "https://github.com/trufflesecurity/trufflehog"

    def _get_bin_path(self) -> str | None:
        if os.path.exists(self._custom_bin):
            return self._custom_bin
        return shutil.which("trufflehog") or shutil.which("trufflehog.exe")

    def check_availability(self) -> EngineAvailability:
        if self._cached_avail is not None:
            return self._cached_avail

        bin_path = self._get_bin_path()
        if not bin_path:
            self._cached_avail = EngineAvailability(
                name=self.name,
                state=EngineState.NOT_INSTALLED,
                issues=["TruffleHog binary not found in PATH or tools/trufflehog/."],
                remediation_hint="Download trufflehog from https://github.com/trufflesecurity/trufflehog/releases and place in tools/trufflehog/.",
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
            version = res.stdout.strip() or "3.99.9"
            self._cached_avail = EngineAvailability(
                name=self.name,
                state=EngineState.READY,
                version=version,
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
        return ["secrets", "credentials", "api_keys", "private_keys", "git_scan"]

    def validate_target(self, target: str) -> bool:
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
                error=f"TruffleHog unavailable: {', '.join(avail.issues)}",
            )

        start_time = time.time()
        target_path = context.target if os.path.exists(context.target) else os.getcwd()
        cmd = [
            avail.binary_path,
            "filesystem",
            "--json",
            "--no-verification",
            target_path,
        ]

        if context.dry_run:
            return EngineExecutionResult(
                engine_name=self.name,
                target=context.target,
                success=True,
                stdout=f"[DRY-RUN] TruffleHog would execute: {' '.join(cmd)}",
                duration_sec=0.1,
            )

        try:
            logger.info("Executing TruffleHog: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=context.timeout_sec or 120,
            )
            duration = time.time() - start_time

            findings = self.collect_findings(proc.stdout, context)

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
                error=f"TruffleHog execution error: {exc}",
                duration_sec=time.time() - start_time,
            )

    def collect_findings(self, raw_data: Any, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        text = str(raw_data).strip()
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
                detector_name = record.get("DetectorName", "Secret")
                raw_secret = record.get("Raw", "")
                redacted = raw_secret[:4] + ("*" * max(0, len(raw_secret) - 8)) + raw_secret[-4:] if len(raw_secret) > 8 else "***REDACTED***"
                source_meta = record.get("SourceMetadata", {}).get("Data", {})
                file_path = source_meta.get("Filesystem", {}).get("file", "unknown_file")

                f = Finding(
                    title=f"[TruffleHog] Exposed {detector_name} Key",
                    bug_class="hardcoded_credential",
                    severity="high",
                    confidence="high",
                    host="localhost",
                    url=file_path,
                    status=FindingLifecycle.DISCOVERED.value,
                    summary=f"Detected potentially exposed {detector_name} secret in {file_path}.",
                    impact="Exposed credentials can grant unauthorized access to sensitive backend services or third-party APIs.",
                    remediation="Revoke the exposed key immediately and store credentials in secure environment variables or vault.",
                    steps=[
                        f"1. Target file: {file_path}",
                        f"2. Secret detector matched: {detector_name}",
                        f"3. Redacted token: {redacted}",
                    ],
                    evidence=[Evidence(summary=f"Exposed {detector_name}", extra={"detector": detector_name, "redacted": redacted, "file": file_path})],
                    meta={
                        "discovery_engine": self.name,
                        "engine_version": self.version,
                        "program": context.program,
                        "cwe": "CWE-798",
                        "upstream_status": "trufflehog_verified_secret",
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
