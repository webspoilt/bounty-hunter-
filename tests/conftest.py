import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bb.scope import Scope
from bb.store import Store


@pytest.fixture()
def scope() -> Scope:
    return Scope.from_entries(
        "test-program",
        ["app.example.com", "*.example.com", "api.other.test", "10.0.0.0/24", "203.0.113.7"],
        out_of_scope=["staging.example.com", "*.internal.example.com"],
    )


@pytest.fixture()
def store(tmp_path) -> Store:
    s = Store(tmp_path / "test.db")
    yield s
    s.close()
