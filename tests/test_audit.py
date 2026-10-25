import json
import shutil

import pytest

from bb import audit


class FakeLLM:
    def available(self):
        return True

    def embed(self, texts, **kw):
        return [[float(len(t) % 11), 1.0, 0.5] for t in texts]


def make_repo(tmp_path):
    repo = tmp_path / "service"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return repo


def test_vendored_skill_is_present():
    info = audit.skill_info()
    assert info["exists"]
    assert info["schema"]
    assert all(info["validators"].values())
    assert len(info["docs"]) >= 10
    assert info["commit"] and len(info["commit"]) == 40
    assert (audit.AUDIT_SKILL / "LICENSE").exists()
    assert (audit.AUDIT_SKILL / "NOTICE.md").exists()


def test_init_creates_a_valid_empty_contract(tmp_path):
    repo = make_repo(tmp_path)
    out = tmp_path / "audit-run"
    result = audit.init_workspace(repo, out=out, profile="quick", budget=12)
    assert result["out"] == out.resolve()
    for name in ("run-metadata.json", "architecture.md", "coverage-ledger.json",
                 "findings.json", "README.md"):
        assert (out / name).exists(), name
    assert json.loads((out / "coverage-ledger.json").read_text()) == []
    assert json.loads((out / "findings.json").read_text()) == []

    meta = json.loads((out / "run-metadata.json").read_text())
    assert meta["repo"] == "service"
    assert meta["target"] == str(repo.resolve())
    assert meta["profile"] == "quick"
    assert meta["budget"] == 12
    assert meta["scope_paths"] == ["."]
    assert meta["execution_policy"] == "sandboxed-source-and-local-only"
    assert meta["run_status"] == "in_progress"
    assert meta["shared_file_owners"]["coverage-ledger.json"] == "parent"
    assert "Scaffold only" in (out / "architecture.md").read_text()


def test_init_refuses_output_inside_target(tmp_path):
    repo = make_repo(tmp_path)
    with pytest.raises(ValueError, match="inside the target"):
        audit.init_workspace(repo, out=repo / "audit")
    # explicit override still works
    result = audit.init_workspace(repo, out=repo / "audit", allow_inside=True)
    assert (result["out"] / "findings.json").exists()


def test_init_rejects_unknown_profile(tmp_path):
    repo = make_repo(tmp_path)
    with pytest.raises(ValueError, match="profile"):
        audit.init_workspace(repo, out=tmp_path / "run", profile="paranoid")


def test_validate_missing_document(tmp_path):
    with pytest.raises(FileNotFoundError):
        audit.validate("ledger", tmp_path / "nope.json")
    with pytest.raises(ValueError):
        audit.validate("bogus", tmp_path / "nope.json")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_vendored_validators_accept_empty_documents(tmp_path):
    ledger = tmp_path / "coverage-ledger.json"
    findings = tmp_path / "findings.json"
    ledger.write_text("[]\n", encoding="utf-8")
    findings.write_text("[]\n", encoding="utf-8")
    code, out = audit.validate("ledger", ledger)
    assert code == 0, out
    code, out = audit.validate("findings", findings)
    assert code == 0, out


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_vendored_findings_validator_rejects_incomplete_record(tmp_path):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([{"verdict": "confirmed", "title": "x"}]), encoding="utf-8")
    code, out = audit.validate("findings", findings)
    assert code != 0
    assert "fingerprint" in out or "missing" in out.lower()


def test_ingest_adds_methodology_to_kb(tmp_path, monkeypatch):
    from bb.kb import KnowledgeBase

    monkeypatch.setattr(audit, "AUDIT_SKILL", audit.AUDIT_SKILL)
    kb = KnowledgeBase(tmp_path / "kb.json", llm=FakeLLM())
    added = audit.ingest_skill(kb)
    assert added > 0
    assert kb.stats()["documents"] >= 10
    titles = {e["title"] for e in kb.entries}
    assert any(t.startswith("security-audit/") for t in titles)
