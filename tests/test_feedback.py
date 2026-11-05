"""Feedback readback: outcomes recorded via `bb outcome` must change downstream behavior."""
import pytest

from bb import feedback
from bb.models import Finding, Evidence
from bb.store import Store


def _store_with_history(tmp_path) -> Store:
    store = Store(tmp_path / "fb.db")
    classes = {
        "IDOR": ("accepted", "accepted", "duplicate"),
        "CORS": ("duplicate", "duplicate", "rejected"),
    }
    for cls, statuses in classes.items():
        for status in statuses:
            f = Finding(title=f"{cls} case", bug_class=cls,
                        host="app.example.com", url=f"https://app.example.com/{cls}/{status}")
            f.evidence = [Evidence("baseline")]
            store.add_finding(f, run_id=None)
            store.set_outcome(f.id, status=status, bounty=100.0 if status == "accepted" else 0.0)
    return store


def test_priors_rank_good_class_above_bad(tmp_path):
    store = _store_with_history(tmp_path)
    priors = feedback.class_priors(store)
    assert priors["IDOR"]["weight"] > priors["CORS"]["weight"]
    # IDOR: (2+1)/(3+2)=0.6 ; CORS: (0+1)/(3+2)=0.2
    assert priors["IDOR"]["weight"] == 0.6
    assert priors["CORS"]["weight"] == 0.2


def test_few_decided_outcomes_stay_neutral(tmp_path):
    store = _store_with_history(tmp_path)
    f = Finding(title="one-off", bug_class="SSRF", url="https://app.example.com/ssrf/1")
    f.evidence = [Evidence("baseline")]
    store.add_finding(f)
    store.set_outcome(f.id, status="rejected")     # 1 decided outcome
    priors = feedback.class_priors(store)
    assert priors["SSRF"]["neutral"]
    assert priors["SSRF"]["weight"] == 0.5


def test_program_filter_changes_priors(tmp_path):
    store = _store_with_history(tmp_path)
    # a different program where the same class actually pays (3/3 accepted)
    for i in range(3):
        f = Finding(title=f"paid IDOR elsewhere {i}", bug_class="IDOR",
                    url=f"https://other.test/x{i}")
        f.evidence = [Evidence("baseline")]
        store.add_finding(f)
        run_id = store.start_run("other-program", "https://other.test")
        store.conn.execute("UPDATE findings SET run_id=? WHERE id=?", (run_id, f.id))
        store.conn.commit()
        store.set_outcome(f.id, status="accepted")
    else_priors = feedback.class_priors(store, program="other-program")
    assert else_priors["IDOR"]["weight"] == round((3 + 1) / (3 + 2), 3)   # 0.8
    assert else_priors["IDOR"]["weight"] > feedback.class_priors(store)["IDOR"]["weight"]


def test_annotate_adds_meta_and_warns_on_bad_classes(tmp_path):
    store = _store_with_history(tmp_path)
    good = Finding(title="idor", bug_class="IDOR", url="https://app.example.com/a")
    good.evidence = [Evidence("baseline")]
    bad = Finding(title="cors", bug_class="CORS", url="https://app.example.com/b")
    bad.evidence = [Evidence("baseline")]
    advisories = feedback.annotate([good, bad], store)
    assert good.meta["feedback_prior"] == 0.6
    assert bad.meta["feedback_prior"] == 0.2
    ids = {a["finding_id"] for a in advisories}
    assert ids == {bad.id}          # only the 0.2 class triggers the warning


def test_annotate_never_drops_findings(tmp_path):
    store = _store_with_history(tmp_path)
    bad = Finding(title="cors", bug_class="CORS", url="https://app.example.com/b")
    bad.evidence = [Evidence("baseline")]
    out = feedback.annotate([bad], store)
    # the finding is untouched apart from meta; validation stays a human decision
    assert bad.status == "candidate"
    assert isinstance(out, list)


def test_rank_priority_orders_by_class_weight(tmp_path):
    store = _store_with_history(tmp_path)
    mid = Finding(title="mid sev good class", bug_class="IDOR", severity="medium",
                  url="https://app.example.com/m")
    mid.evidence = [Evidence("baseline")]
    low = Finding(title="low sev bad class", bug_class="CORS", severity="medium",
                  url="https://app.example.com/n")
    low.evidence = [Evidence("baseline")]
    ranked = feedback.rank_priority([low, mid], store)
    assert ranked[0].id == mid.id
