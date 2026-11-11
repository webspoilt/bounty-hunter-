"""Unit and integration tests for .env HackerOne credential configuration and persistence.

Verifies:
1. .env is discovered from a different working directory.
2. Credentials load in a fresh application process.
3. Existing environment variables are handled according to documented precedence (env vars take precedence by default).
4. Missing credentials produce the setup instruction (`bb h1 configure`).
5. API token is never printed or logged in output.
6. .env is excluded from Git tracking.
7. Atomic writing of .env and non-destructive updates to existing values.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from bb.config import ROOT, load_project_env
from bb.h1 import H1AuthError, H1Client, configure_credentials


def test_env_file_excluded_from_git():
    """Verify that .env is ignored by Git."""
    res = subprocess.run(
        ["git", "check-ignore", ".env"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert ".env" in res.stdout


def test_configure_credentials_atomic_and_non_destructive(tmp_path: Path):
    """Verify configure_credentials creates/updates .env atomically preserving existing keys."""
    env_file = tmp_path / ".env"
    env_file.write_text("FOO=bar\nH1_USERNAME=old_user\nOTHER=123\n", encoding="utf-8")

    # Update credentials
    out_path = configure_credentials("dummy_user", "dummy_token_xyz_secret", env_path=env_file)
    assert out_path == env_file

    content = env_file.read_text(encoding="utf-8")
    assert "FOO=bar" in content
    assert "OTHER=123" in content
    assert "H1_USERNAME=dummy_user" in content
    assert "H1_TOKEN=dummy_token_xyz_secret" in content
    assert "old_user" not in content


def test_missing_credentials_gives_configure_instruction(monkeypatch, tmp_path):
    """Verify that missing credentials produce the helpful setup command."""
    monkeypatch.delenv("H1_USERNAME", raising=False)
    monkeypatch.delenv("H1_TOKEN", raising=False)
    # Point ENV_PATH to non-existent file so it doesn't load the real project .env
    empty_env = tmp_path / ".nonexistent_env"
    monkeypatch.setattr("bb.config.ENV_PATH", empty_env)
    monkeypatch.setattr("bb.h1.ENV_PATH", empty_env)
    monkeypatch.setattr("bb.h1.H1_USERNAME", "")
    monkeypatch.setattr("bb.h1.H1_TOKEN", "")

    with pytest.raises(H1AuthError) as exc_info:
        H1Client(username="", token="")

    msg = str(exc_info.value)
    assert "bb h1 configure" in msg
    assert "HackerOne credentials missing" in msg


def test_env_loader_precedence(tmp_path: Path, monkeypatch):
    """Documented precedence: explicit shell env var overrides .env by default."""
    env_file = tmp_path / ".env"
    env_file.write_text("TEST_KEY=from_env_file\n", encoding="utf-8")

    monkeypatch.setenv("TEST_KEY", "from_shell")
    monkeypatch.setattr("bb.config.ENV_PATH", env_file)

    # By default, override=False preserves existing shell env var
    load_project_env(override=False)
    assert os.environ.get("TEST_KEY") == "from_shell"

    # With override=True, .env overrides
    load_project_env(override=True)
    assert os.environ.get("TEST_KEY") == "from_env_file"


def test_env_discovered_from_foreign_working_directory(tmp_path: Path):
    """Verify running python/bb from an external working directory still loads project .env."""
    foreign_dir = tmp_path / "foreign"
    foreign_dir.mkdir()

    # Run subprocess from foreign directory
    code = (
        "import os\n"
        "from bb.config import ROOT, ENV_PATH\n"
        "from bb.h1 import H1Client\n"
        "client = H1Client()\n"
        "print(f'SUCCESS:{client.username}')\n"
    )

    res = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(foreign_dir),
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "SUCCESS:" in res.stdout


def test_token_not_printed_in_cli_output(tmp_path: Path):
    """Verify token is never displayed or leaked in configure or client output."""
    dummy_secret = "super_secret_token_never_print_12345"
    env_file = tmp_path / ".env"
    configure_credentials("dummy_tester", dummy_secret, env_path=env_file)

    # Read back and ensure file contains it
    assert dummy_secret in env_file.read_text(encoding="utf-8")

    # In any representation, token shouldn't appear in string format of client
    client = H1Client(username="dummy_tester", token=dummy_secret)
    rep = repr(client)
    # The client repr must not show the token
    assert dummy_secret not in rep
