# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from syrebrum_core import cli
from syrebrum_core.contracts import ContractError
from syrebrum_core.providers.ollama import BudgetExceeded, OllamaProvider, ProviderError


@pytest.mark.parametrize("url", ["http://10.0.0.2:11434", "http://example.com", "ftp://127.0.0.1",
                                 "http://127.0.0.1.nip.io:11434", "http://[::ffff:10.0.0.1]:11434",
                                 "http://127.0.0.1:11434/x", "http://127.0.0.1:11434?a=1",
                                 "http://127.0.0.1:11434/;p", "http://127.0.0.1:11434?", "http://127.0.0.1:11434#",
                                 "http://@127.0.0.1:11434", "http://127.0.0.1:99999", "http://127.0.0.1 :1",
                                 "http://user:pw@127.0.0.1:11434", "127.0.0.1:11434"])
def test_remote_or_bad_urls_refused(url):
    with pytest.raises(ContractError):
        OllamaProvider(url)


def test_remote_needs_opt_in():
    OllamaProvider("http://10.0.0.2:11434", allow_remote=True)


def _fake(body, status=200):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(status)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


def test_generate_and_budget():
    srv, url = _fake(json.dumps({"response": "hi"}).encode())
    p = OllamaProvider(url, max_calls=1)
    assert p.generate("llama3.1:8b", "hello") == "hi"
    with pytest.raises(BudgetExceeded):
        p.generate("llama3.1:8b", "hello")
    srv.shutdown()


@pytest.mark.parametrize("body", [b"nope", b"{}", b'{"response": 5}'])
def test_bad_replies(body):
    srv, url = _fake(body)
    with pytest.raises(ProviderError):
        OllamaProvider(url).generate("m", "x")
    srv.shutdown()


def test_redirect_not_followed():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    with pytest.raises(ProviderError):
        OllamaProvider(f"http://127.0.0.1:{srv.server_port}").generate("m", "x")
    srv.shutdown()


def test_prompt_limits():
    p = OllamaProvider()
    with pytest.raises(ContractError):
        p.generate("m", "")
    with pytest.raises(ContractError):
        p.generate("bad model name", "x")


def test_cli_end_to_end(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    assert cli.main(["--db", db, "submit", "core.echo", "--payload", '{"a":1}', "--key", "k1"]) == 0
    assert cli.main(["--db", db, "work"]) == 0
    assert cli.main(["--db", db, "verify"]) == 0
    capsys.readouterr()
    assert cli.main(["--db", db, "list"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["state"] == "succeeded"


def test_cli_check_denies_without_engine(capsys, monkeypatch):
    monkeypatch.delenv("SYREBRUM_FAILSTOP", raising=False)
    assert cli.main(["check", "fs.write", "/srv/data/x"]) == 3
    assert json.loads(capsys.readouterr().out)["verdict"] == "deny"


def test_cli_bad_input(tmp_path):
    assert cli.main(["--db", str(tmp_path / "c.db"), "submit", "core.echo", "--payload", "[1]"]) == 2
    assert cli.main(["--db", str(tmp_path / "c.db"), "submit", "bad kind"]) == 2


def test_cli_inventory(capsys):
    assert cli.main(["inventory"]) == 0
    assert json.loads(capsys.readouterr().out)["schema"] == "syrebrum.inventory/1"


def test_cli_expect_head(tmp_path, capsys):
    db = str(tmp_path / "c.db")
    cli.main(["--db", db, "submit", "core.echo"])
    cli.main(["--db", db, "submit", "core.echo"])
    capsys.readouterr()
    cli.main(["--db", db, "verify"])
    head = json.loads(capsys.readouterr().out)["head"]
    assert cli.main(["--db", db, "verify", "--expect-head", head]) == 0
    import sqlite3
    c = sqlite3.connect(db)
    c.execute("DELETE FROM receipts WHERE hash=?", (head,))
    c.execute("DELETE FROM jobs WHERE id=2")
    c.commit()
    c.close()
    assert cli.main(["--db", db, "verify", "--expect-head", head]) == 4


@pytest.mark.parametrize("url,want", [("http://localhost:11434", "http://127.0.0.1:11434"),
                                      ("http://LOCALHOST:11434/", "http://127.0.0.1:11434"),
                                      ("http://[::1]:11434", "http://[::1]:11434")])
def test_localhost_pinned_to_loopback_ip(url, want):
    assert OllamaProvider(url).base_url == want


def test_proxy_environment_ignored(monkeypatch):
    hits = []

    class Proxy(BaseHTTPRequestHandler):  # a local fake proxy that records any use
        def do_POST(self):
            hits.append(self.path)
            self.send_response(502)
            self.end_headers()

        def log_message(self, *a):
            pass
    proxy = HTTPServer(("127.0.0.1", 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    srv, url = _fake(json.dumps({"response": "direct"}).encode())
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(k, f"http://127.0.0.1:{proxy.server_port}")
    for k in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(k, raising=False)
    assert OllamaProvider(url, timeout_s=3).generate("m", "x") == "direct"
    assert hits == []
    srv.shutdown()
    proxy.shutdown()


def test_cli_verify_missing_db_fails(tmp_path):
    assert cli.main(["--db", str(tmp_path / "typo.db"), "verify"]) == 2
    assert not (tmp_path / "typo.db").exists()


def test_cli_bad_db_path_is_clean_error(tmp_path):
    (tmp_path / "dir.db").mkdir()
    assert cli.main(["--db", str(tmp_path / "dir.db"), "submit", "core.echo"]) == 2


def test_oversized_reply_rejected():
    srv, url = _fake(b'{"response": "' + b"a" * 1_100_000 + b'"}')
    with pytest.raises(ProviderError):
        OllamaProvider(url).generate("m", "x")
    srv.shutdown()


def test_deeply_nested_reply_rejected():
    srv, url = _fake(b"[" * 200000)
    with pytest.raises(ProviderError):
        OllamaProvider(url).generate("m", "x")
    srv.shutdown()


@pytest.mark.parametrize("kw", [{"max_calls": True}, {"max_calls": 1.5}, {"timeout_s": float("nan")}, {"timeout_s": 0}])
def test_provider_numeric_limits(kw):
    with pytest.raises(ContractError):
        OllamaProvider(**kw)


@pytest.mark.parametrize("flag", ["false", "true", 1, 0, None])
def test_allow_remote_must_be_bool(flag):
    with pytest.raises(ContractError):
        OllamaProvider("http://10.0.0.2:11434", allow_remote=flag)


def test_port_zero_rejected():
    with pytest.raises(ContractError):
        OllamaProvider("http://127.0.0.1:0")


def test_cli_huge_job_id_is_clean_error(tmp_path):
    db = str(tmp_path / "j.db")
    cli.main(["--db", db, "submit", "core.echo"])
    assert cli.main(["--db", db, "receipts", "--job", str(10**30)]) == 2


def test_cli_readonly_default_creates_nothing(tmp_path, monkeypatch):
    home = tmp_path / "nothere"
    monkeypatch.setenv("SYREBRUM_HOME", str(home))
    assert cli.main(["verify"]) == 2
    assert cli.main(["list"]) == 2
    assert not home.exists()


def test_utf16_reply_cannot_hide_nesting():
    from syrebrum_core.contracts import json_depth_ok
    s = '["\u2200",' + "[" * 2000 + "]" * 2000 + "]"
    raw = s.encode("utf-16-le")
    with pytest.raises(TypeError):  # bytes are refused: the scan and the parser must see one text
        json_depth_ok(raw, 8)
    assert json_depth_ok(s, 8) is False
    with pytest.raises(ValueError):  # what the provider parses: the strict UTF-8 text, not UTF-16
        json.loads(raw.decode("utf-8"))


@pytest.mark.parametrize("url", ["http://[::1%25lo]:11434", "http://127.0.0.1\\@x", "http://127.0.0.1:1\x00",
                                 "http://[::1%lo]:11434"])
def test_ollama_url_rejects_zone_ids_and_control_chars(url):
    from syrebrum_core.providers.ollama import OllamaProvider
    with pytest.raises(ContractError):
        OllamaProvider(url)


@pytest.mark.parametrize("addr", ["unix:", "unix:\x00abstract", "tcp://[::1%eth0]:9000", 5])
def test_failstop_address_rejects_odd_forms(addr):
    from syrebrum_core.failstop import SocketFailStop
    with pytest.raises(ContractError):
        SocketFailStop(addr)


@pytest.mark.parametrize("payload", ['{"a":1,"a":2}', '{"a":NaN}', "[1]", "[" * 100 + "]" * 100])
def test_cli_submit_rejects_loose_json(tmp_path, payload, capsys):
    assert cli.main(["--db", str(tmp_path / "x.db"), "submit", "core.echo", "--payload", payload]) == 2
