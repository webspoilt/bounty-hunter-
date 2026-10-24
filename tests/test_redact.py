from bb.redact import (redact_body, redact_headers, redact_json, redact_url)


def test_header_redaction():
    h = redact_headers({"Authorization": "Bearer abc", "Cookie": "s=1",
                        "X-Api-Key": "k", "Content-Type": "application/json"})
    assert h["Authorization"] == "[REDACTED]"
    assert h["Cookie"] == "[REDACTED]"
    assert h["X-Api-Key"] == "[REDACTED]"
    assert h["Content-Type"] == "application/json"


def test_json_body_redaction_keeps_evidence():
    body = '{"email": "victim@lab.test", "token": "secret123", "id": 42}'
    out = redact_body(body)
    assert "secret123" not in out
    assert "victim@lab.test" in out
    assert "42" in out


def test_text_body_redaction():
    out = redact_body("Authorization: Bearer abcdefghijklmnop\nlogin ok")
    assert "abcdefghijklmnop" not in out
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
    assert "eyJhbGciOiJIUzI1NiJ9" not in redact_body(jwt)


def test_query_redaction():
    url = redact_url("https://lab.test/cb?code=SEKRET&state=ok")
    assert "SEKRET" not in url
    assert "state=ok" in url


def test_nested_redaction():
    obj = {"user": {"name": "a", "password": "p"}, "items": [{"api_key": "k"}]}
    out = redact_json(obj)
    assert out["user"]["password"] == "[REDACTED]"
    assert out["items"][0]["api_key"] == "[REDACTED]"
