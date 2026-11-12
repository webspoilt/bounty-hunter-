"""Bounty Hunter 2.0 Engine Adapter Framework."""
from bb.engines.base import (
    BaseEngine,
    EngineAvailability,
    EngineCategory,
    EngineExecutionResult,
    ExecutionContext,
)
from bb.engines.dedupe import FindingDeduplicator
from bb.engines.doctor import DependencyDoctor, DiagnosticItem
from bb.engines.registry import EngineRegistry

__all__ = [
    "BaseEngine",
    "EngineCategory",
    "EngineAvailability",
    "ExecutionContext",
    "EngineExecutionResult",
    "EngineRegistry",
    "DependencyDoctor",
    "DiagnosticItem",
    "FindingDeduplicator",
]
