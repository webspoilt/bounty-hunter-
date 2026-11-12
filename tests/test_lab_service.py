"""Unit tests for OWASP Lab background service management."""
import pytest
from bb.lab_service import (
    OwaspLabServiceManager,
    is_port_in_use,
    probe_lab_service,
)


def test_probe_lab_service_active():
    active, catalog = probe_lab_service(timeout=3.0)
    assert active is True
    assert "scenarios" in catalog
    assert len(catalog["scenarios"]) == 32


def test_lab_status_reporting():
    st = OwaspLabServiceManager.status()
    assert st["state"] == "RUNNING"
    assert st["port_open"] is True
    assert st["is_owasp_lab"] is True
    assert st["catalog_scenarios"] == 32


def test_lab_start_idempotency_reuses_existing():
    # Calling start when server is already running must reuse it and never spawn duplicates
    res = OwaspLabServiceManager.start()
    assert res["success"] is True
    assert res["action"] == "REUSED_EXISTING"
    assert "Reusing existing server" in res["message"]
