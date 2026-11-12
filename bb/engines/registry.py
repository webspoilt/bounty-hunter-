"""Bounty Hunter 2.0 - Central Engine Registry.

Registers, configures, audits, and dispatches security engines and autonomous agents.
"""
from __future__ import annotations

import logging
from typing import Any

from bb.engines.base import BaseEngine, EngineAvailability, EngineCategory
from bb.engines.bountybot_authz import BountybotAuthzEngine
from bb.engines.dalfox import DalfoxEngine
from bb.engines.doctor import DependencyDoctor, DiagnosticItem
from bb.engines.nuclei import NucleiEngine
from bb.engines.semgrep import SemgrepEngine
from bb.engines.shannon import ShannonEngine
from bb.engines.sqlmap import SQLmapEngine

logger = logging.getLogger(__name__)


class EngineRegistry:
    """Singleton registry managing all Bounty Hunter 2.0 security engines."""

    _instance: EngineRegistry | None = None

    def __init__(self):
        self._engines: dict[str, BaseEngine] = {}
        self._register_defaults()

    @classmethod
    def get_instance(cls) -> EngineRegistry:
        if cls._instance is None:
            cls._instance = EngineRegistry()
        return cls._instance

    def _register_defaults(self) -> None:
        """Registers official and specialist engines."""
        defaults = [
            ShannonEngine(),
            NucleiEngine(),
            SQLmapEngine(),
            DalfoxEngine(),
            SemgrepEngine(),
            BountybotAuthzEngine(),
        ]
        for engine in defaults:
            self.register(engine)

    def register(self, engine: BaseEngine) -> None:
        self._engines[engine.name.lower()] = engine
        logger.debug("Registered engine: %s (%s)", engine.name, engine.display_name)

    def get(self, name: str) -> BaseEngine | None:
        return self._engines.get(name.lower())

    def list_engines(self, category: EngineCategory | None = None) -> list[BaseEngine]:
        engines = list(self._engines.values())
        if category:
            engines = [e for e in engines if e.category == category]
        return engines

    def check_all(self) -> list[EngineAvailability]:
        return [engine.check_availability() for engine in self._engines.values()]

    def run_doctor(self) -> list[DiagnosticItem]:
        return DependencyDoctor.run_full_diagnosis()

    def format_engines_table(self) -> str:
        lines = [
            f"{'ENGINE NAME':<18} {'CATEGORY':<12} {'STATE':<22} {'VERSION':<26} {'LICENSE':<10} {'OFFICIAL REPO'}",
            "─" * 120,
        ]
        for eng in self._engines.values():
            avail = eng.check_availability()
            state_str = avail.state.value
            lines.append(
                f"{eng.name:<18} {eng.category.value:<12} {state_str:<22} {avail.version[:24]:<26} {eng.license:<10} {eng.official_repository}"
            )
        return "\n".join(lines)

