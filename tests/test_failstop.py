# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
import json
import os
import socket
import tempfile
import threading
import time

import pytest

from syrebrum_core.contracts import ContractError, Decision, Verdict
from syrebrum_core.failstop import (
    EffectRequest,
    NoFailStop,
    SocketFailStop,
    check,
    parse_decision,
)


def req(**kw):
    base = dict(principal="w1", tool="fs.write", target="/srv/data/x", idempotency_key="k1")
    base.update(kw)
    return EffectRequest(**base)


def reply(r, **kw):
    msg = {"v": "1", "verdict": "allow", "reason": "ok", "request_hash": r.request_hash, "policy_version": "p1",
           "approval_id": None}
    msg.update(kw)
    return json.dumps(msg).encode()


def test_no_engine_denies():
    assert check(NoFailStop(), req()).verdict is Verdict.DENY


def test_valid_allow():
    r = req()
    assert parse_decision(reply(r), r).allowed


@pytest.mark.parametrize("raw", [b"", b"not json", b"\xff\xfe", b"[]", b"null", b"x" * 20000])
def test_garbage_denies(raw):
    assert parse_decision(raw, req()).verdict is Verdict.DENY


@pytest.mark.parametrize("change", [
    {"v": "2"}, {"v": 1}, {"request_hash": "0" * 64}, {"verdict": "ALLOW"}, {"verdict": "yes"},
    {"reason": 5}, {"policy_version": None}, {"approval_id": 7},
])
def test_bad_fields_deny(change):
    r = req()
    assert parse_decision(reply(r, **change), r).verdict is Verdict.DENY


def test_missing_verdict_denies():
    r = req()
    msg = json.loads(reply(r))
    del msg["verdict"]
    assert parse_decision(json.dumps(msg).encode(), r).verdict is Verdict.DENY


def test_expired_allow_denies():
    r = req(expires_at=time.time() - 1)
    assert parse_decision(reply(r), r).verdict is Verdict.DENY


def test_hold_is_not_allowed():
    r = req()
    d = parse_decision(reply(r, verdict="hold"), r)
    assert d.verdict is Verdict.HOLD and not d.allowed


def test_hash_binds_every_field():
    a = req()
    for k, v in [("target", "/srv/data/y"), ("tool", "shell.run"), ("principal", "w2"), ("args", {"a": 1}),
                 ("tenant", "t2"), ("idempotency_key", "k2"), ("expires_at", a.expires_at + 1)]:
        assert req(**{k: v, **({"expires_at": a.expires_at} if k != "expires_at" else {})}).request_hash != a.request_hash


def test_client_exception_denies():
    class Boom:
        def decide(self, r):
            raise RuntimeError("x")
    assert check(Boom(), req()).verdict is Verdict.DENY


def test_client_wrong_type_or_hash_denies():
    class Liar:
        def decide(self, r):
            return Decision(Verdict.ALLOW, "ok", "0" * 64)
    class Junk:
        def decide(self, r):
            return {"verdict": "allow"}
    assert check(Liar(), req()).verdict is Verdict.DENY
    assert check(Junk(), req()).verdict is Verdict.DENY


@pytest.mark.parametrize("addr", ["tcp://10.0.0.5:9000", "tcp://example.com:9000", "tcp://127.0.0.1:0",
                                  "tcp://127.0.0.1:99999", "http://127.0.0.1:1", "127.0.0.1:1", "tcp://127.0.0.1:x"])
def test_bad_addresses_rejected(addr):
    with pytest.raises(ContractError):
        SocketFailStop(addr)


def _server(handler):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        conn, _ = srv.accept()
        with conn:
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            handler(conn, json.loads(data))
        srv.close()
    threading.Thread(target=run, daemon=True).start()
    return f"tcp://127.0.0.1:{srv.getsockname()[1]}"


def test_socket_roundtrip_allow():
    def h(conn, msg):
        conn.sendall(json.dumps({"v": "1", "verdict": "allow", "reason": "ok",
                                 "request_hash": msg["request_hash"], "policy_version": "p1", "approval_id": None}).encode() + b"\n")
    assert check(SocketFailStop(_server(h)), req()).allowed


def test_socket_engine_cannot_forge_hash_for_other_request():
    def h(conn, msg):
        conn.sendall(json.dumps({"v": "1", "verdict": "allow", "reason": "ok",
                                 "request_hash": "f" * 64, "policy_version": "p1", "approval_id": None}).encode() + b"\n")
    assert check(SocketFailStop(_server(h)), req()).verdict is Verdict.DENY


def test_socket_silent_engine_times_out():
    def h(conn, msg):
        time.sleep(1.5)
    assert check(SocketFailStop(_server(h), timeout_s=0.3), req()).verdict is Verdict.DENY


def test_socket_closed_without_answer():
    assert check(SocketFailStop(_server(lambda c, m: None)), req()).verdict is Verdict.DENY


def test_socket_unreachable():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert check(SocketFailStop(f"tcp://127.0.0.1:{port}"), req()).verdict is Verdict.DENY


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no unix sockets")
def test_unix_socket_missing_denies():
    path = os.path.join(tempfile.mkdtemp(), "none.sock")
    assert check(SocketFailStop("unix:" + path), req()).verdict is Verdict.DENY


def test_socket_partial_then_late_answer_denied():
    def h(conn, msg):
        body = json.dumps({"v": "1", "verdict": "allow", "reason": "ok", "request_hash": msg["request_hash"],
                           "policy_version": "p1", "approval_id": None}).encode()
        try:  # the client hangs up at its deadline; that's the expected outcome
            conn.sendall(body[:10])
            time.sleep(0.25)
            conn.sendall(body[10:20])
            time.sleep(0.25)
            conn.sendall(body[20:] + b"\n")
        except OSError:
            pass
    assert check(SocketFailStop(_server(h), timeout_s=0.3), req()).verdict is Verdict.DENY


@pytest.mark.parametrize("t", [0, -1, 61, True, "5", float("nan")])
def test_bad_timeouts_rejected(t):
    with pytest.raises(ContractError):
        SocketFailStop("tcp://127.0.0.1:9", timeout_s=t)


@pytest.mark.parametrize("drop", ["policy_version", "approval_id", "reason", "v", "request_hash"])
def test_missing_field_denies(drop):
    r = req()
    msg = json.loads(reply(r))
    del msg[drop]
    assert parse_decision(json.dumps(msg).encode(), r).verdict is Verdict.DENY


def test_unknown_field_denies():
    r = req()
    assert parse_decision(reply(r, extra=1), r).verdict is Verdict.DENY


def test_duplicate_field_denies():
    r = req()
    raw = reply(r)[:-1] + b', "verdict": "allow"}'
    assert parse_decision(raw, r).verdict is Verdict.DENY


@pytest.mark.parametrize("raw", [b'{"v": NaN}', b'{"v": Infinity}', b"[" * 100000, b'{"v": "\\ud800"}'], ids=["nan", "infinity", "deep", "lone-surrogate"])
def test_hostile_json_denies(raw):
    assert parse_decision(raw, req()).verdict is Verdict.DENY


def test_adapter_expired_allow_denied():
    class Late:
        def decide(self, r):
            return Decision(Verdict.ALLOW, "ok", r.request_hash)
    r = req(expires_at=time.time() - 1)
    assert check(Late(), r).verdict is Verdict.DENY


@pytest.mark.parametrize("bad", [
    lambda h: Decision(Verdict.ALLOW, None, h),
    lambda h: Decision("allow", "ok", h),
    lambda h: Decision(Verdict.ALLOW, "ok", h, None),
    lambda h: Decision(Verdict.ALLOW, "ok", h, "p", 5),
])
def test_adapter_malformed_decision_denied(bad):
    class A:
        def decide(self, r):
            return bad(r.request_hash)
    assert check(A(), req()).verdict is Verdict.DENY


def test_adapter_mutation_cannot_change_request():
    seen = {}

    class Mutator:
        def decide(self, r):
            seen["hash"] = r.request_hash
            r.args["evil"] = 1
            return Decision(Verdict.ALLOW, "ok", r.request_hash)
    r = req(args={"n": 1})
    d = check(Mutator(), r)
    assert d.request_hash == seen["hash"] and r.approved_args() == {"n": 1}


def test_caller_dict_mutation_ignored():
    a = {"n": 1}
    r = req(args=a)
    h = r.request_hash
    a["n"] = 2
    assert r.request_hash == h and r.approved_args() == {"n": 1}


@pytest.mark.parametrize("exp", [float("nan"), float("inf"), -5, True, "1", 1e12])
def test_bad_expiry_rejected(exp):
    with pytest.raises(ContractError):
        req(expires_at=exp)


@pytest.mark.parametrize("field", ["reason", "policy_version", "approval_id"])
def test_lone_surrogate_in_exact_allow_denies(field):
    r = req()
    raw = reply(r, **{field: "ok"}).replace(b'"ok"', b'"\\ud800"') if field == "reason" else \
        reply(r, **{field: "\ud800"}).replace(b"\\\\", b"\\")
    msg = json.loads(raw)  # really is an exact six-field ALLOW with a lone surrogate
    assert set(msg) == {"v", "verdict", "reason", "request_hash", "policy_version", "approval_id"}
    assert parse_decision(raw, r).verdict is Verdict.DENY


@pytest.mark.parametrize("bad", [dict(reason="\udfff"), dict(policy_version=""), dict(policy_version="\ud800"),
                                 dict(approval_id="\ud800"), dict(reason=b"ok"), dict(policy_version=None)])
def test_adapter_malformed_fields_deny(bad):
    r = req()
    fields = dict(reason="ok", policy_version="p1", approval_id=None)
    fields.update(bad)

    class Bad:
        def decide(self, q):
            return Decision(Verdict.ALLOW, fields["reason"], q.request_hash, fields["policy_version"],
                            fields["approval_id"])
    assert check(Bad(), r).verdict is Verdict.DENY


def test_deeply_nested_reply_denied_without_parsing():
    r = req()
    assert parse_decision(b"[" * 10000, r).verdict is Verdict.DENY
    assert parse_decision(b'{"v":' + b"[" * 5000 + b"]" * 5000 + b"}", r).verdict is Verdict.DENY


def test_adapter_cannot_extend_expiry_of_expired_request():
    import time as _t

    from syrebrum_core.contracts import Decision, Verdict
    from syrebrum_core.failstop import EffectRequest, check

    class Extend:
        def decide(self, r):
            r.__dict__["expires_at"] = 9e10
            return Decision(Verdict.ALLOW, "ok", r.request_hash, "p1")
    req = EffectRequest("u", "fs.write", "/srv/x", idempotency_key="k", expires_at=_t.time() - 5)
    assert check(Extend(), req).verdict is Verdict.DENY
