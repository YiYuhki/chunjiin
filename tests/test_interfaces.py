from __future__ import annotations

import json

from fastapi.testclient import TestClient

from cdr.api import app
from cdr.cli import main

import samples

client = TestClient(app)


def test_api_health():
    assert client.get("/health").json()["status"] == "ok"
    assert "CDR" in client.get("/").text


def test_api_sanitize_returns_file():
    res = client.post("/api/v1/sanitize", files={"file": ("보고서.docm", samples.malicious_docm())})
    assert res.status_code == 200
    assert res.headers["x-cdr-status"] == "sanitized"
    assert "filename*=UTF-8''%EB%B3%B4%EA%B3%A0%EC%84%9C.docx" in res.headers["content-disposition"]
    assert res.content[:2] == b"PK"


def test_api_sanitize_blocked():
    res = client.post("/api/v1/sanitize", files={"file": ("a.exe", b"MZ" + b"\x00" * 100)})
    assert res.status_code == 422
    assert res.json()["status"] == "blocked"


def test_api_scan():
    res = client.post("/api/v1/scan", files={"file": ("x.pdf", samples.malicious_pdf())})
    body = res.json()
    assert body["status"] == "sanitized"
    assert body["max_severity"] == "critical"


def test_cli_sanitize(tmp_path, capsys):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "a.docm").write_bytes(samples.malicious_docm())
    (inbox / "b.pdf").write_bytes(samples.clean_pdf())
    (inbox / "c.exe").write_bytes(b"MZ" + b"\x00" * 100)
    out = tmp_path / "out"
    report = tmp_path / "report.json"

    code = main(["sanitize", str(inbox), "-o", str(out), "--report", str(report)])
    assert code == 2  # 차단 파일 존재
    assert sorted(p.name for p in out.iterdir()) == ["a.docx", "b.pdf"]
    data = json.loads(report.read_text(encoding="utf-8"))
    assert {d["status"] for d in data} == {"sanitized", "clean", "blocked"}
    assert "무해화 1" in capsys.readouterr().out


def test_cli_scan(tmp_path, capsys):
    f = tmp_path / "x.rtf"
    f.write_bytes(samples.malicious_rtf())
    assert main(["scan", str(f)]) == 0
    assert "template-injection" in capsys.readouterr().out
