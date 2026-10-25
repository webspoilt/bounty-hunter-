import pytest

from bb.metrics import collect, format_metrics
from bb.models import Finding
from bb.store import Store


def finding(title, bug_class="IDOR", severity="high"):
    return Finding(title=title, bug_class=bug_class, severity=severity,
                   host="lab.test", url=f"http://lab.test/{title}")


def test_outcome_roundtrip_and_merge(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    run = store.start_run("acme")
    f = finding("one")
    store.add_finding(f, run)

    out = store.set_outcome(f.id, status="accepted", bounty=500, currency="INR", minutes=90)
    assert out["status"] == "accepted"
    assert out["submitted_at"]  # auto-filled
    # updating one field preserves the others
    out = store.set_outcome(f.id, notes="paid")
    assert out["bounty"] == 500 and out["currency"] == "INR" and out["minutes"] == 90
    assert store.get_outcome(f.id)["notes"] == "paid"


def test_outcome_validation(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    run = store.start_run("acme")
    f = finding("one")
    store.add_finding(f, run)
    with pytest.raises(ValueError):
        store.set_outcome(f.id, status="maybe")
    with pytest.raises(KeyError):
        store.set_outcome("deadbeef", status="accepted")
    # no outcome yet => unknown, not a failure
    assert store.get_outcome(f.id)["status"] == "unknown"


def test_metrics_acceptance_duplicates_and_bounty_per_hour(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    run = store.start_run("acme")
    a, d, u = finding("accepted", "IDOR"), finding("dupe", "CORS"), finding("open")
    for f in (a, d, u):
        store.add_finding(f, run)
    store.set_outcome(a.id, status="accepted", bounty=500, currency="INR", minutes=60)
    store.set_outcome(d.id, status="duplicate", minutes=30)

    data = collect(store)
    t = data["totals"]
    assert t["findings"] == 3
    assert t["accepted"] == 1 and t["duplicate"] == 1 and t["unknown"] == 1
    assert t["decided"] == 2
    assert t["acceptance_rate"] == 0.5
    assert t["duplicate_rate"] == 0.5
    assert t["bounty"] == 500
    assert t["bounty_per_hour"] == 333.33   # 500 / 1.5h

    text = format_metrics(data)
    assert "acceptance rate: 50%" in text
    assert "bounty per hour: 333.33" in text
    assert "by class" in text
    assert "acme" in text


def test_metrics_program_filter(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    run_a = store.start_run("acme")
    run_b = store.start_run("other")
    store.add_finding(finding("a"), run_a)
    store.add_finding(finding("b"), run_b)

    assert collect(store, program="acme")["totals"]["findings"] == 1
    assert collect(store)["totals"]["findings"] == 2
