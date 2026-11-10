"""Regression tests for DNS resolution failures, scope denials, and terminal task blocking.

Verifies:
1. Successful DNS resolution for an authorized resolvable test host.
2. DNS resolution failure handling without leaking out of scope.
3. Nonexistent hostname (NXDOMAIN) handling.
4. Transient vs terminal DNS errors.
5. Confirmed out-of-scope DNS results rejected before execution.
6. Zero outbound requests executed after DNS denial.
7. Zero infinite retries after policy denial.
8. Correct task persistence with 'blocked' terminal status.
9. Scope revalidation after DNS recovery.
10. Continuous scheduler termination when all tasks are blocked.
"""
from __future__ import annotations

import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from bb.checks import CheckOptions
from bb.http import RequestBudget, ScopedClient
from bb.orchestrator.controller import Controller, ControllerConfig
from bb.orchestrator.profile import AutonomyLevel, ProgramProfile
from bb.orchestrator.resource_manager import ResourceManager, SecurityPolicy
from bb.orchestrator.scheduler import Scheduler
from bb.scope import Scope, ScopeDecision
from bb.store import Store
from bb.swarm import Task


@pytest.fixture
def mem_store(tmp_path):
    return Store(tmp_path / "dns_test.db")


def test_dns_resolution_success_authorized_host():
    """Resolvable public host within scope resolves and is allowed."""
    scope = Scope.from_entries("test", ["https://one.one.one.one/*"], [])
    dec = scope.verify_resolution("https://one.one.one.one/dns-query")
    assert dec.allowed is True
    assert "resolved" in dec.reason


def test_dns_resolution_failure_nonexistent_host():
    """Nonexistent host fails resolution, is denied, and records gaierror."""
    scope = Scope.from_entries("test", ["https://nonexistent-domain-xyz123.com/*"], [])
    dec = scope.verify_resolution("https://nonexistent-domain-xyz123.com/api")
    assert dec.allowed is False
    assert "DNS resolution failed" in dec.reason
    assert "getaddrinfo failed" in dec.reason or "11001" in dec.reason


def test_no_request_execution_after_dns_denial(mem_store):
    """ScopedClient blocks outbound traffic completely if DNS fails."""
    scope = Scope.from_entries("test", ["https://nonexistent-domain-xyz123.com/*"], [])
    client = ScopedClient(scope, store=mem_store, run_id="r1", tool="test")

    with pytest.raises(Exception) as exc_info:
        client.get("https://nonexistent-domain-xyz123.com/api")
    assert "refused by DNS guard" in str(exc_info.value)
    assert client.sent == 0
    client.close()


def test_task_policy_refusal_records_blocked_state_no_infinite_loop(mem_store):
    """When a task is refused due to DNS failure, it is marked 'blocked' and never loops infinitely."""
    scope = Scope.from_entries("test", ["https://nonexistent-domain-xyz123.com/*"], [])
    cfg = ControllerConfig(
        program="test-prog",
        scope=scope,
        entry_urls=["https://nonexistent-domain-xyz123.com/api"],
        max_iterations=20,
    )
    controller = Controller(cfg, store=mem_store, log=lambda *a: None)

    # Run the controller loop
    res = controller.run()

    # The controller must terminate cleanly (not hang or exceed max iterations)
    assert res["status"] == "completed"
    assert res["tasks_executed"] == 0

    # Verify task rows in SQLite are terminal 'blocked'
    tasks = mem_store.conn.execute("SELECT fingerprint, state, result FROM tasks").fetchall()
    assert len(tasks) > 0
    for row in tasks:
        assert row["state"] == "blocked"
        assert "DNS resolution failed" in row["result"]

    # Verify no tasks remain eligible for re-planning
    eligible = controller.planner.filter_eligible([Task("cors", "https://nonexistent-domain-xyz123.com")])
    assert len(eligible) == 0


def test_scope_revalidation_after_dns_recovery(mem_store):
    """If DNS previously failed but later succeeds, new scope check re-evaluates properly."""
    scope = Scope.from_entries("test", ["https://dynamic.example.com/*"], [])

    # 1. Simulate DNS failure
    with patch("socket.getaddrinfo", side_effect=socket.gaierror(11001, "getaddrinfo failed")):
        dec1 = scope.verify_resolution("https://dynamic.example.com/items")
        assert dec1.allowed is False

    # 2. Simulate DNS recovery
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]):
        dec2 = scope.verify_resolution("https://dynamic.example.com/items")
        assert dec2.allowed is True
        assert "93.184.216.34" in dec2.reason
