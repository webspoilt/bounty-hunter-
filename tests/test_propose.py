import json

from bb import propose
from bb.scenario import load_scenario
from bb.scope import Scope


def entry(method, url, *, status=200, req_body=None, resp_body="", req_headers=None):
    return {
        "time": 8,
        "request": {"method": method, "url": url,
                    "headers": [{"name": k, "value": v}
                                for k, v in (req_headers or {}).items()],
                    "postData": {"mimeType": "application/json", "text": req_body}
                    if req_body is not None else {}},
        "response": {"status": status, "headers": [],
                     "content": {"mimeType": "application/json", "text": resp_body}},
    }


def write_har(tmp_path, entries):
    p = tmp_path / "capture.har"
    p.write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}), encoding="utf-8")
    return p


def full_har(tmp_path):
    auth = {"Authorization": "Bearer SECRET-TOKEN"}
    return write_har(tmp_path, [
        entry("POST", "https://lab.test/api/items", status=201,
              req_body='{"name":"mine"}', resp_body='{"data":{"id":7}}', req_headers=auth),
        entry("GET", "https://lab.test/api/items/7",
              resp_body='{"owner":"alice@lab.test","name":"mine"}'),
        entry("PATCH", "https://lab.test/api/items/7",
              req_body='{"name":"mine"}', resp_body="{}"),
        entry("DELETE", "https://lab.test/api/items/7", status=204),
        entry("GET", "https://lab.test/api/items/8", resp_body='{"owner":"bob@lab.test"}'),
        entry("POST", "https://evil.test/api/items", status=201,
              req_body='{"name":"x"}', resp_body='{"id":1}'),
    ])


def test_propose_read_and_write(tmp_path):
    har = full_har(tmp_path)
    scope = Scope.from_entries("p", ["lab.test"])
    result = propose.propose(har, scope, "p", out_dir=tmp_path / "out")

    assert result["index"]["entries"] == 6
    assert result["index"]["in_scope"] == 5
    assert result["index"]["denied"] == 1
    by_kind = {item["kind"]: item for item in result["written"]}
    assert set(by_kind) == {"idor_read", "idor_write"}

    out = tmp_path / "out"
    read = load_scenario(out / by_kind["idor_read"]["file"])
    assert read["claim"]["type"] == "idor_read"
    assert read["claim"]["owner_step"] == "owner_read"
    assert read["steps"][0]["id"] == "owner_read"
    assert read["steps"][1]["id"] == "attack_read"
    assert read["steps"][0]["path"].endswith("/api/items/7")

    write = load_scenario(out / by_kind["idor_write"]["file"])
    assert write["claim"]["type"] == "idor_write"
    assert {s["id"] for s in write["steps"]} == {
        "create", "owner_read", "attack_write", "owner_verify"}
    create = next(s for s in write["steps"] if s["id"] == "create")
    assert create["extract"] == {"item_id": "$.data.id"}
    attack = next(s for s in write["steps"] if s["id"] == "attack_write")
    assert "${item_id}" in attack["path"]
    assert attack["json"]["name"] == "${marker}"
    assert write["cleanup"][0]["method"] == "DELETE"
    assert "${item_id}" in write["cleanup"][0]["path"]

    # no credential or out-of-scope URL reaches a draft
    for item in result["written"]:
        text = (out / item["file"]).read_text(encoding="utf-8")
        assert "SECRET-TOKEN" not in text
        assert "evil.test" not in text
    review = (out / "REVIEW.md").read_text(encoding="utf-8")
    assert "captured session is the owner" in review
    assert "Nothing here was executed" in review


def test_create_without_followup_proposes_nothing(tmp_path):
    har = write_har(tmp_path, [
        entry("POST", "https://lab.test/api/items", status=201,
              req_body='{"name":"x"}', resp_body='{"id":1}'),
    ])
    result = propose.propose(har, Scope.from_entries("p", ["lab.test"]), "p",
                             out_dir=tmp_path / "out")
    assert result["written"] == []


def test_form_mutation_yields_read_only(tmp_path):
    har = write_har(tmp_path, [
        entry("POST", "https://lab.test/api/items", status=201,
              req_body='{"name":"mine"}', resp_body='{"id":7}'),
        entry("GET", "https://lab.test/api/items/7", resp_body='{"owner":"alice@lab.test"}'),
        entry("PATCH", "https://lab.test/api/items/7", req_body="quantity=3"),
    ])
    result = propose.propose(har, Scope.from_entries("p", ["lab.test"]), "p",
                             out_dir=tmp_path / "out")
    assert [item["kind"] for item in result["written"]] == ["idor_read"]


def test_limit_and_denied_entries(tmp_path):
    har = full_har(tmp_path)
    result = propose.propose(har, Scope.from_entries("p", ["lab.test"]), "p",
                             out_dir=tmp_path / "out", limit=1)
    assert len(result["written"]) == 1
    assert result["index"]["denied"] == 1
