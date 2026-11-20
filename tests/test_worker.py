# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
from syrebrum_core.contracts import Decision, JobState, Task, Verdict
from syrebrum_core.jobs import JobBoard
from syrebrum_core.worker import Worker


class Allow:
    def __init__(self):
        self.seen = []

    def decide(self, r):
        self.seen.append(r)
        return Decision(Verdict.ALLOW, "ok", r.request_hash)


class Hold:
    def decide(self, r):
        return Decision(Verdict.HOLD, "waiting for owner", r.request_hash)


def setup(failstop=None):
    b = JobBoard(":memory:")
    w = Worker(b, "w1", failstop)
    ran = []
    w.register("demo.write", lambda t, a: ran.append((t, a)) or {"wrote": True}, effect=True, tool="fs.write")
    return b, w, ran


def test_effect_denied_without_failstop():
    b, w, ran = setup()
    b.submit(Task("demo.write", {"target": "/srv/data/x"}))
    j = w.run_once()
    assert j.state is JobState.DENIED and ran == [] and j.result["verdict"] == "deny"
    assert any(r.event == "denied" for r in b.receipts(j.id))


def test_effect_hold_does_not_run():
    b, w, ran = setup(Hold())
    b.submit(Task("demo.write", {"target": "/srv/data/x"}))
    assert w.run_once().state is JobState.DENIED and ran == []


def test_effect_without_target_denied():
    b, w, ran = setup(Allow())
    b.submit(Task("demo.write", {}))
    assert w.run_once().state is JobState.DENIED and ran == []


def test_effect_allowed_runs_once():
    fs = Allow()
    b, w, ran = setup(fs)
    b.submit(Task("demo.write", {"target": "/srv/data/x", "args": {"n": 1}}))
    j = w.run_once()
    assert j.state is JobState.SUCCEEDED and len(ran) == 1
    assert ran == [("/srv/data/x", {"n": 1})]
    assert fs.seen[0].tool == "fs.write" and fs.seen[0].target == "/srv/data/x" and fs.seen[0].args == {"n": 1}


def test_read_only_runs_without_failstop():
    b, w, _ = setup()
    b.submit(Task("core.echo", {"a": 1}))
    assert w.run_once().result == {"echo": {"a": 1}}


def test_handler_error_retries_then_fails():
    b = JobBoard(":memory:")
    w = Worker(b, "w1")
    w.register("demo.boom", lambda p: 1 / 0)
    b.submit(Task("demo.boom", max_attempts=2))
    assert w.run(10) == 2
    assert b.list()[0].state is JobState.FAILED


def test_unknown_kinds_left_alone():
    b = JobBoard(":memory:")
    b.submit(Task("other.kind"))
    assert Worker(b, "w1").run_once() is None
    assert b.list()[0].state is JobState.QUEUED


def test_inventory_job():
    b = JobBoard(":memory:")
    b.submit(Task("core.inventory"))
    r = Worker(b, "w1").run_once().result
    assert r["schema"] == "syrebrum.inventory/1" and r["host"].startswith("sha256:")


def test_effect_extra_fields_denied():
    b, w, ran = setup(Allow())
    b.submit(Task("demo.write", {"target": "/srv/data/x", "sneaky": "rm -rf /"}))
    assert w.run_once().state is JobState.DENIED and ran == []


def test_effect_non_dict_args_denied():
    b, w, ran = setup(Allow())
    b.submit(Task("demo.write", {"target": "/srv/data/x", "args": ["a"]}))
    assert w.run_once().state is JobState.DENIED and ran == []


def test_handler_cannot_mutate_approved_request():
    fs = Allow()
    b = JobBoard(":memory:")
    w = Worker(b, "w1", fs)
    w.register("demo.write", lambda t, a: a.update(evil=1) or {"ok": True}, effect=True)
    b.submit(Task("demo.write", {"target": "/srv/data/x", "args": {"n": 1}}))
    w.run_once()
    assert fs.seen[0].args == {"n": 1}


def test_cancel_during_decision_blocks_effect():
    b = JobBoard(":memory:")

    class CancelThenAllow:
        def decide(self, r):
            b.cancel(b.list()[0].id)
            return Decision(Verdict.ALLOW, "ok", r.request_hash)
    ran = []
    w = Worker(b, "w1", CancelThenAllow())
    w.register("demo.write", lambda t, a: ran.append(t) or {}, effect=True)
    b.submit(Task("demo.write", {"target": "/srv/data/x"}))
    assert w.run_once().state is JobState.CANCELLED and ran == []


def test_lease_expired_during_decision_blocks_effect():
    t = [1000.0]
    b = JobBoard(":memory:", clock=lambda: t[0])

    class SlowAllow:
        def decide(self, r):
            t[0] += 120
            return Decision(Verdict.ALLOW, "ok", r.request_hash)
    ran = []
    w = Worker(b, "w1", SlowAllow(), lease_s=60)
    w.register("demo.write", lambda t_, a: ran.append(t_) or {}, effect=True)
    b.submit(Task("demo.write", {"target": "/srv/data/x"}))
    w.run_once()
    assert ran == []


def test_inventory_runs_no_programs_and_no_network(monkeypatch):
    import socket
    import subprocess

    from syrebrum_core import inventory

    def boom(*a, **k):
        raise AssertionError("inventory tried to run a program or open a socket")
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr("os.system", boom)
    r = inventory.collect()
    assert r["os"]["system"] and r["host"].startswith("sha256:")


def test_inventory_flag_must_be_bool():
    b = JobBoard(":memory:")
    b.submit(Task("core.inventory", {"include_hostname": "false"}, max_attempts=1))
    assert Worker(b, "w1").run_once().state is JobState.FAILED


def test_allow_decision_recorded_in_receipt():
    b, w, ran = setup(Allow())
    b.submit(Task("demo.write", {"target": "/srv/data/x"}))
    j = w.run_once()
    rec = [r for r in b.receipts(j.id) if r.event == "succeeded"][0]
    assert rec.detail["decision"]["verdict"] == "allow" and rec.detail["decision"]["request_hash"]


def test_claimed_token_not_exposed_by_reads():
    b = JobBoard(":memory:")
    b.submit(Task("core.echo"))
    c = b.claim("w1")
    assert c.lease_token and b.get(c.id).lease_token is None and b.list()[0].lease_token is None


def test_malformed_allow_never_runs_handler():
    class SurrogateAllow:
        def decide(self, r):
            return Decision(Verdict.ALLOW, "\ud800", r.request_hash, "p1")
    b, w, ran = setup(SurrogateAllow())
    b.submit(Task("demo.write", {"target": "/srv/data/x"}))
    j = w.run_once()
    assert j.state is JobState.DENIED and ran == [] and b.verify()[0]


def test_approval_recorded_before_effect_even_if_handler_fails():
    b = JobBoard(":memory:")
    w = Worker(b, "w1", Allow())

    def boom(t, a):
        raise RuntimeError("disk full")
    w.register("demo.write", boom, effect=True, tool="fs.write")
    b.submit(Task("demo.write", {"target": "/srv/data/x"}, max_attempts=1))
    j = w.run_once()
    events = [r.event for r in b.receipts(j.id)]
    assert j.state is JobState.FAILED
    assert events.index("effect_authorized") < events.index("failed")
    auth = [r for r in b.receipts(j.id) if r.event == "effect_authorized"][0]
    assert auth.detail["decision"]["verdict"] == "allow"


def test_cancel_during_policy_wait_stops_effect():
    b = JobBoard(":memory:")

    class CancelThenAllow:
        def decide(self, r):
            b.cancel(1)
            return Decision(Verdict.ALLOW, "ok", r.request_hash)
    w = Worker(b, "w1", CancelThenAllow())
    ran = []
    w.register("demo.write", lambda t, a: ran.append(t) or {}, effect=True, tool="fs.write")
    b.submit(Task("demo.write", {"target": "/srv/data/x"}))
    j = w.run_once()
    assert ran == [] and j.state is JobState.CANCELLED


def test_adapter_mutating_request_cannot_change_what_runs():
    class Sneaky:
        def decide(self, r):
            h = r.request_hash
            r.__dict__["target"] = "/etc/passwd"
            r.__dict__["_args_json"] = '{"evil": true}'
            r.__dict__["expires_at"] = 9e10
            return Decision(Verdict.ALLOW, "ok", h, "p1")
    b, w, ran = setup(Sneaky())
    b.submit(Task("demo.write", {"target": "/srv/safe", "args": {"n": 1}}))
    j = w.run_once()
    assert ran == [("/srv/safe", {"n": 1})] and j.state is JobState.SUCCEEDED


def test_effect_with_unrecordable_result_is_not_rerun():
    b = JobBoard(":memory:")
    w = Worker(b, "w1", Allow())
    calls = []
    w.register("demo.write", lambda t, a: calls.append(t) or {"x": "\ud800"}, effect=True, tool="fs.write")
    b.submit(Task("demo.write", {"target": "/srv/x"}, max_attempts=3))
    j = w.run_once()
    assert len(calls) == 1 and j.state is JobState.FAILED and w.run_once() is None
    assert "effect ran" in j.result["error"]


def test_overlong_target_denied_not_retried():
    b, w, ran = setup(Allow())
    b.submit(Task("demo.write", {"target": "x" * 2000}, max_attempts=3))
    j = w.run_once()
    assert j.state is JobState.DENIED and ran == [] and j.attempts == 1


def test_finished_effect_edited_to_expired_lease_is_not_rerun():
    b, w, ran = setup(Allow())
    b.submit(Task("demo.write", {"target": "/srv/x"}))
    assert w.run_once().state is JobState.SUCCEEDED
    b._db.execute("UPDATE jobs SET state='leased', lease_expires=0 WHERE id=1")
    assert w.run_once() is None and len(ran) == 1
    assert b.verify()[0] is False


def test_effect_not_rerun_when_recording_fails():
    import sqlite3
    b = JobBoard(":memory:")
    w = Worker(b, "w1", Allow())
    calls = []
    w.register("demo.write", lambda t, a: calls.append(t) or {}, effect=True, tool="fs.write")
    b.submit(Task("demo.write", {"target": "/srv/x"}, max_attempts=2))

    def locked(*a, **k):
        raise sqlite3.OperationalError("database is locked")
    b.complete = locked
    j = w.run_once()
    assert j.state is JobState.FAILED and w.run_once() is None and calls == ["/srv/x"]
