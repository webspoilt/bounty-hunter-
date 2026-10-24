from bb.telegram import TelegramError, TelegramGate


class FakeGate:
    def __init__(self):
        self.decided = []

    def pending(self):
        return [{"id": "abc123", "title": "<b>IDOR</b> & more", "severity": "high",
                 "bug_class": "IDOR", "url": "http://lab.test/x?a=1&b=2",
                 "summary": "role B <script>alert(1)</script>"}]

    def decide(self, queue_id, approved):
        if queue_id != "abc123":
            raise KeyError(queue_id)
        self.decided.append((queue_id, approved))
        return {"id": queue_id, "state": "approved", "finding_id": "f1"}


def make_gate(chats=(42,)):
    tg = TelegramGate("token", FakeGate(), set(chats))
    sent = []

    def fake_api(method, payload, timeout=30.0):
        sent.append((method, payload))
        return []

    tg._api = fake_api
    return tg, sent


def test_requires_an_allowlist():
    try:
        TelegramGate("token", FakeGate(), set())
    except TelegramError:
        pass
    else:
        raise AssertionError("empty allowlist should be refused")


def test_card_escapes_server_controlled_html():
    tg, _ = make_gate()
    text = tg.format_item(tg.gate.pending()[0])
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "&amp; more" in text


def test_unauthorised_chat_cannot_decide():
    tg, sent = make_gate(chats=(42,))
    tg._on_callback({"id": "cb1", "data": "approve:abc123",
                     "message": {"chat": {"id": 999}}})
    assert tg.gate.decided == []
    assert any(p.get("text") == "not authorised" for _, p in sent)


def test_authorised_callback_uses_queue_id():
    tg, sent = make_gate(chats=(42,))
    tg._on_callback({"id": "cb1", "data": "approve:abc123",
                     "message": {"chat": {"id": 42}}})
    assert tg.gate.decided == [("abc123", True)]
    assert any(m == "answerCallbackQuery" for m, _ in sent)


def test_stale_callback_is_reported_not_swallowed():
    tg, sent = make_gate(chats=(42,))
    tg._on_callback({"id": "cb2", "data": "reject:gone",
                     "message": {"chat": {"id": 42}}})
    assert tg.gate.decided == []
    assert any(p.get("text") == "already gone" for _, p in sent)


def test_push_pending_sends_one_card_per_item():
    tg, sent = make_gate(chats=(42,))
    assert tg.push_pending() == 1
    assert any(m == "sendMessage" for m, _ in sent)
