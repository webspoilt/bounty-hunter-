"""Unit tests for OWASP Lab background service management and health states."""
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from bb.lab_service import (
    OwaspLabServiceManager,
    is_port_in_use,
    probe_lab_service,
)


def test_probe_lab_service_active():
    active, data = probe_lab_service(timeout=3.0)
    assert active is True
    # Could be {'status': 'ok'} or {'count': 32, 'scenarios': [...]}
    assert data is not None


def test_lab_status_reporting():
    st = OwaspLabServiceManager.status()
    assert st["state"] == "RUNNING"
    assert st["port_open"] is True
    assert st["is_owasp_lab"] is True


def test_lab_start_idempotency_reuses_existing():
    # Calling start when server is already running must reuse it and never spawn duplicates
    res = OwaspLabServiceManager.start()
    assert res["success"] is True
    assert res["action"] == "REUSED_EXISTING"
    assert "Reusing existing server" in res["message"]


@patch("urllib.request.urlopen")
def test_probe_healthy_state_canonical_endpoint(mock_urlopen):
    """Test healthy state responding to canonical GET /health returning 200 {'status': 'ok'}."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = b'{"status": "ok"}'
    mock_urlopen.return_value = mock_resp

    active, data = probe_lab_service()
    assert active is True
    assert data == {"status": "ok"}


@patch("urllib.request.urlopen")
def test_probe_healthy_state_fallback_catalog_on_404(mock_urlopen):
    """Test fallback when /health returns 404 but /api/lab/catalog returns 200 with catalog.
    Verifies that HTTP 404 from an unmounted route is NOT classified as startup failure.
    """
    # First call to /health raises HTTP 404
    err_404 = urllib.error.HTTPError(
        url="http://127.0.0.1:8000/health",
        code=404,
        msg="Not Found",
        hdrs={},
        fp=None,
    )
    # Second call to /api/lab/catalog succeeds with 200
    mock_cat = MagicMock()
    mock_cat.status = 200
    mock_cat.__enter__.return_value = mock_cat
    mock_cat.read.return_value = b'{"count": 32, "scenarios": []}'

    mock_urlopen.side_effect = [err_404, mock_cat]

    active, data = probe_lab_service()
    assert active is True
    assert data.get("count") == 32


@patch("urllib.request.urlopen")
def test_probe_unreachable_state(mock_urlopen):
    """Test unreachable service state (e.g. Connection Refused)."""
    mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

    active, data = probe_lab_service()
    assert active is False
    assert data == {}


@patch("urllib.request.urlopen")
def test_probe_unhealthy_state_500_error(mock_urlopen):
    """Test unhealthy service state (e.g. internal server error on all probes)."""
    err_500 = urllib.error.HTTPError(
        url="http://127.0.0.1:8000/health",
        code=500,
        msg="Internal Server Error",
        hdrs={},
        fp=None,
    )
    mock_urlopen.side_effect = err_500

    active, data = probe_lab_service()
    assert active is False
    assert data == {}

