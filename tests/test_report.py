from bb.models import Evidence, Exchange, Finding
from bb.report import (build_facts, lint, polish, render_cbh_finding, render_h1,
                       write_report)


class NoLLM:
    def available(self):
        return False


def sample() -> Finding:
    ex_a = Exchange("GET", "http://lab.test/api/invoices/42", 200,
                    request_headers={"Authorization": "[REDACTED]"},
                    response_headers={"content-type": "application/json"},
                    response_body='{"invoice": {"id": 42, "email": "alice@lab.test"}}',
                    note="A owner")
    ex_b = Exchange("GET", "http://lab.test/api/invoices/42", 200,
                    request_headers={"Authorization": "[REDACTED]"},
                    response_body='{"invoice": {"id": 42, "email": "alice@lab.test"}}',
                    note="B replay")
    return Finding(
        title="Broken object-level authorization at /api/invoices/42",
        bug_class="IDOR", severity="high", confidence="high", host="lab.test",
        url="http://lab.test/api/invoices/42",
        summary="Role B receives role A's invoice object.",
        impact="Cross-user PII disclosure.", remediation="Add an ownership check.",
        steps=["Request as A.", "Request as B."],
        evidence=[Evidence("A owner view", ex_a), Evidence("B replay", ex_b)])


def test_render_h1_has_every_required_section():
    md = render_h1(sample())
    for section in ("## Summary", "## Steps to reproduce", "## Impact",
                    "## Remediation", "## Evidence", "HTTP/1.1"):
        assert section in md
    assert "alice@lab.test" in md          # proof preserved
    assert "```http" in md


def test_render_h1_never_leaks_tokens():
    f = sample()
    md = render_h1(f)
    assert "Bearer A" not in md
    assert "[REDACTED]" in md


def test_scope_attestation_present():
    from bb.scope import Scope
    scope = Scope.from_entries("acme", ["lab.test"])
    md = render_h1(sample(), scope=scope)
    assert scope.fingerprint in md
    assert "matched an in-scope rule" in md


def test_cbh_finding_frontmatter_is_parseable():
    md = render_cbh_finding(sample())
    assert md.startswith("---")
    assert "title: Broken object-level authorization" in md
    assert "## Steps to reproduce" in md
    assert "curl " in md                     # cbh triage Q1 looks for a lowercase curl
    assert "H1 Hacktivity" in md             # novelty is stated, not assumed


def test_data_classes_and_novelty():
    from bb.report import data_classes, novelty_note
    f = sample()
    classes = data_classes(f)
    assert "email address" in classes
    note = novelty_note(f, kb=None)
    assert "Novelty not checked" in note
    assert "H1 Hacktivity" in note

    class FakeKB:
        entries = [{"text": "nothing here"}]

        def lexical_contains(self, needle):
            return 0

    assert "No precedent" in novelty_note(f, FakeKB())


def test_lint_flags_placeholders_and_missing_sections():
    issues = lint("# T\n\n## Summary\nTBD\n")
    assert any("Impact" in i for i in issues)
    assert any("placeholder" in i for i in issues)


def test_lint_clean_report():
    assert lint(render_h1(sample())) == []


def test_polish_returns_empty_without_model():
    assert polish(sample(), llm=NoLLM()) == {}


def test_write_report_files(tmp_path, monkeypatch):
    monkeypatch.setattr("bb.report.REPORTS", tmp_path)
    f = sample()
    report, cbh = write_report(f)
    assert report.exists() and cbh.exists()
    assert report.parent.name == f.id
    assert "## Impact" in report.read_text(encoding="utf-8")


def test_build_facts_includes_evidence():
    facts = build_facts(sample())
    assert "IDOR" in facts and "alice@lab.test" in facts
