import pytest

from bb.models import Evidence, Exchange, Finding
from bb.store import Store

def finding(**kw):
    base = dict(title="IDOR on /api/x", bug_class="IDOR", severity="high",
                host="lab.test", url="http://lab.test/api/x/1",
                summary="s", impact="i", remediation="r", steps=["one"])
    base.update(kw)
    return Finding(**base)


def test_findings_and_evidence_roundtrip(store):
    f = finding(evidence=[Evidence("owner", Exchange("GET", "http://lab.test/x", 200,
                                                     response_body='{"a":1}'))])
    store.add_finding(f, "run1")
    got = store.get_finding(f.id)
    assert got is not None
    assert got.evidence[0].exchange.status == 200
    assert got.evidence[0].exchange.response_body == '{"a":1}'


def test_queue_is_uuid_not_position(store):
    f1, f2 = finding(title="one"), finding(title="two")
    store.add_finding(f1, "r")
    store.add_finding(f2, "r")
    q1, new1 = store.queue_add(f1.id)
    q2, new2 = store.queue_add(f2.id)
    assert new1 and new2 and q1 != q2
    store.decide(q1, approved=False)
    # deciding by the second id still hits the second finding, not a shifted position
    item = store.decide(q2, approved=True)
    assert item["finding_id"] == f2.id
    assert store.get_finding(f1.id).status == "rejected"
    assert store.get_finding(f2.id).status == "confirmed"


def test_queue_dedupes_and_double_decide_refused(store):
    f = finding()
    store.add_finding(f, "r")
    q1, new1 = store.queue_add(f.id)
    q2, new2 = store.queue_add(f.id)
    assert q1 == q2 and new1 and not new2
    store.decide(q1, approved=True)
    with pytest.raises(ValueError):
        store.decide(q1, approved=True)


def test_unknown_queue_id(store):
    with pytest.raises(KeyError):
        store.decide("nope", approved=True)


def test_prefix_lookup(store):
    f = finding()
    store.add_finding(f, "r")
    qid, _ = store.queue_add(f.id)
    assert store.get_finding(f.id[:6]).id == f.id
    assert store.decide(qid[:5], approved=True)["finding_id"] == f.id


def test_scope_audit_records_deny(store):
    store.audit_scope("r1", "http://evil.test/", "DENY", "no rule", "evil.test")
    store.audit_scope("r1", "http://lab.test/", "ALLOW", "rule", "lab.test")
    counts = store.audit_counts("r1")
    assert counts == {"DENY": 1, "ALLOW": 1}


def test_findings_filter_and_sort(store):
    store.add_finding(finding(title="low", severity="low"), "r")
    store.add_finding(finding(title="critical", severity="critical"), "r")
    rows = store.findings(status="candidate")
    assert rows[0].severity == "critical"


def test_stats(tmp_path):
    s = Store(tmp_path / "s.db")
    s.add_finding(finding(), "r")
    st = s.stats()
    assert st["findings"] == 1
    s.close()


def test_exchanges_are_per_run(store):
    ex = Exchange("GET", "http://lab.test/x", 200, response_body="same")
    assert store.add_exchange("run1", "hunt", ex)
    assert not store.add_exchange("run1", "hunt", ex)      # deduped inside the run
    assert store.add_exchange("run2", "hunt", ex)         # recorded for the next run too
    assert len(store.exchanges("run1")) == 1
    assert len(store.exchanges("run2")) == 1


def test_find_duplicate(store):
    f = finding()
    store.add_finding(f, "r")
    assert store.find_duplicate(f.bug_class, f.url).id == f.id
    assert store.find_duplicate(f.bug_class, "http://lab.test/other") is None
