"""Bounty Hunter Persistent Orchestration Engine.

Provides persistent state machine, agent registry, resource management,
bounded planning, deterministic policy gates, Tev1 decision integration,
and continuous autonomous research scheduling (Strategic P9).
"""
from __future__ import annotations

from bb.orchestrator.agent_registry import AgentCapability, AgentRegistry, AgentSpec
from bb.orchestrator.controller import Controller, ControllerConfig
from bb.orchestrator.lifecycle import LifecycleManager, State
from bb.orchestrator.planner import Planner
from bb.orchestrator.resource_manager import ResourceManager, SecurityPolicy
from bb.orchestrator.scheduler import Scheduler
from bb.orchestrator.profile import AutonomyLevel, ProfileValidity, ProgramProfile, ScopeChangeDetector
from bb.orchestrator.prioritizer import ContinuousPrioritizer, ResearchPriorityScore
from bb.orchestrator.continuous_scheduler import ContinuousScheduler, ContinuousSchedulerState, SchedulerStatus

__all__ = [
    "AgentCapability",
    "AgentRegistry",
    "AgentSpec",
    "AutonomyLevel",
    "ContinuousPrioritizer",
    "ContinuousScheduler",
    "ContinuousSchedulerState",
    "Controller",
    "ControllerConfig",
    "LifecycleManager",
    "Planner",
    "ProfileValidity",
    "ProgramProfile",
    "ResearchPriorityScore",
    "ResourceManager",
    "Scheduler",
    "SchedulerStatus",
    "ScopeChangeDetector",
    "SecurityPolicy",
    "State",
]
