"""Bounty Hunter 2.0 - Core Engine Interface & Types.

Every external security tool, autonomous pentesting agent, and specialist scanner
implements this standardized BaseEngine adapter interface.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from bb.models import Evidence, Exchange, Finding


class EngineCategory(str, Enum):
    RECON = "recon"
    DAST = "dast"
    SAST = "sast"
    AUTONOMOUS = "autonomous"
    SPECIALIST = "specialist"


class EngineState(str, Enum):
    NOT_INSTALLED = "NOT_INSTALLED"
    INSTALLED = "INSTALLED"
    READY = "READY"
    BLOCKED_DEPENDENCY = "BLOCKED_DEPENDENCY"
    CONFIGURATION_REQUIRED = "CONFIGURATION_REQUIRED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    VERIFIED_OPERATIONAL = "VERIFIED_OPERATIONAL"


class FindingLifecycle(str, Enum):
    DISCOVERED = "DISCOVERED"
    HYPOTHESIS = "HYPOTHESIS"
    REPRODUCING = "REPRODUCING"
    VERIFIED = "VERIFIED"
    IMPACT_ASSESSED = "IMPACT_ASSESSED"
    REPORT_READY = "REPORT_READY"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"


@dataclass
class EngineAvailability:
    name: str
    state: EngineState
    version: str = "unknown"
    binary_path: str | None = None
    issues: list[str] = field(default_factory=list)
    remediation_hint: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return self.state in (EngineState.READY, EngineState.VERIFIED_OPERATIONAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "available": self.available,
            "version": self.version,
            "binary_path": self.binary_path,
            "issues": self.issues,
            "remediation_hint": self.remediation_hint,
            "meta": self.meta,
        }



@dataclass
class ExecutionContext:
    program: str
    target: str
    scope_fingerprint: str = ""
    rate_limit: float = 3.0
    timeout_sec: int = 300
    auth_tokens: dict[str, str] = field(default_factory=dict)
    custom_headers: dict[str, str] = field(default_factory=dict)
    source_repo: Path | str | None = None
    output_dir: Path | None = None
    dry_run: bool = False
    extra_flags: list[str] = field(default_factory=list)


@dataclass
class EngineExecutionResult:
    engine_name: str
    target: str
    success: bool
    exit_code: int = 0
    duration_sec: float = 0.0
    stdout: str = ""
    stderr: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_name": self.engine_name,
            "target": self.target,
            "success": self.success,
            "exit_code": self.exit_code,
            "duration_sec": round(self.duration_sec, 2),
            "findings_count": len(self.findings),
            "error": self.error,
            "meta": self.meta,
        }


class BaseEngine(ABC):
    """Abstract base class for all Bounty Hunter 2.0 engine adapters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique machine-readable name of the engine (e.g. 'shannon', 'nuclei')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Installed version string or 'not_installed'."""
        pass

    @property
    @abstractmethod
    def official_repository(self) -> str:
        """Official project repository URL."""
        pass

    @property
    @abstractmethod
    def license(self) -> str:
        """Official software license."""
        pass

    @property
    @abstractmethod
    def category(self) -> EngineCategory:
        """Primary category of the engine."""
        pass

    @abstractmethod
    def check_availability(self) -> EngineAvailability:
        """Probes system path, Docker, or environment variables for engine readiness."""
        pass

    @abstractmethod
    def get_capabilities(self) -> list[str]:
        """Returns supported vulnerability categories (e.g. ['sqli', 'xss', 'idor'])."""
        pass

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Ensures target matches approved format and engine prerequisites."""
        pass

    @abstractmethod
    def configure(self, config: dict[str, Any]) -> None:
        """Configures execution parameters (rate limits, timeouts, tokens)."""
        pass

    @abstractmethod
    def execute(self, context: ExecutionContext) -> EngineExecutionResult:
        """Executes the engine safely under the provided ExecutionContext."""
        pass

    @abstractmethod
    def collect_findings(self, raw_data: Any, context: ExecutionContext) -> list[Finding]:
        """Parses native engine outputs into normalized Finding models."""
        pass

    @abstractmethod
    def collect_evidence(self, finding: Finding) -> list[Evidence]:
        """Extracts raw HTTP request/response exchanges for a finding."""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Cleans up temporary files, containers, or scratch artifacts."""
        pass
