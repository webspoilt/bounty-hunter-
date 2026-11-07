"""Coding agent handoff package — primary/fallback orchestration and task manifests."""
from __future__ import annotations

from bb.coder.adapter import QwenCoderAdapter
from bb.coder.manifest import TaskManifest
from bb.coder.provider import ProviderStateManager, WorktreeLock

__all__ = [
    "QwenCoderAdapter",
    "TaskManifest",
    "ProviderStateManager",
    "WorktreeLock",
]
