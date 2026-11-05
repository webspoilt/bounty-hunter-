from bb.kb import KnowledgeBase, chunk_text


class FakeLLM:
    def available(self):
        return True

    def embed(self, texts, **kw):
        return [[float(len(t) % 11), 1.0, 0.5] for t in texts]


def test_chunking():
    text = " ".join(f"word{i}" for i in range(400))
    chunks = chunk_text(text, size=200, overlap=40)
    assert len(chunks) > 1
    assert all(len(c) <= 200 for c in chunks)
    assert chunk_text("") == []


def test_add_and_query(tmp_path):
    kb = KnowledgeBase(tmp_path / "kb.json", llm=FakeLLM())
    added = kb.add_document("idor-writeup", "user B read user A invoice by changing the id")
    assert added == 1
    hits = kb.query("idor invoice", k=1)
    assert hits and hits[0]["title"] == "idor-writeup"


def test_rerun_ingest_does_not_duplicate(tmp_path):
    kb = KnowledgeBase(tmp_path / "kb.json", llm=FakeLLM())
    doc = ("playbook", "a long-ish body about object level authorization testing", {"team": "acme"})
    assert kb.add_documents([doc]) == 1
    assert kb.add_documents([doc]) == 0
    assert kb.stats()["chunks"] == 1


def test_metadata_filter(tmp_path):
    kb = KnowledgeBase(tmp_path / "kb.json", llm=FakeLLM())
    kb.add_documents([
        ("acme report", "acme idor invoice", {"team": "acme"}),
        ("other report", "other idor invoice", {"team": "other"}),
    ])
    hits = kb.query("idor invoice", k=5, where={"team": "acme"})
    assert len(hits) == 1 and hits[0]["title"] == "acme report"


def test_dimension_mismatch_fails_loudly(tmp_path):
    kb = KnowledgeBase(tmp_path / "kb.json", llm=FakeLLM())
    kb.add_document("doc", "some text about authorization")
    kb.entries[0]["vector"] = [1.0, 2.0]        # simulate a model switch
    try:
        kb.query("authorization")
    except ValueError as exc:
        assert "dimension" in str(exc)
    else:
        raise AssertionError("expected a dimension mismatch error")


def test_atomic_save_and_reload(tmp_path):
    path = tmp_path / "kb.json"
    kb = KnowledgeBase(path, llm=FakeLLM())
    kb.add_document("doc", "text")
    kb2 = KnowledgeBase(path, llm=FakeLLM())
    assert kb2.stats()["chunks"] == 1
    assert not path.with_suffix(".tmp").exists()
