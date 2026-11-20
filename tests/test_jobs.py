# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0

import os
import sqlite3

import pytest

from syrebrum_core.contracts import ContractError, JobState, Task
from syrebrum_core.jobs import JobBoard, LeaseLost


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def board():
    c = Clock()
    b = JobBoard(":memory:", clock=c)
    b.clock = c
    yield b
    b.close()


def test_happy_path(board):
    j = board.submit(Task("core.echo", {"a": 1}))
    c = board.claim("w1")
    assert c.id == j.id and c.state is JobState.LEASED
    done = board.complete(c.id, c.lease_token, {"ok": True})
    assert done.state is JobState.SUCCEEDED and done.result == {"ok": True}
    assert board.claim("w1") is None
    assert board.verify_receipts()[0]


def test_idempotent_submit(board):
    a = board.submit(Task("core.echo", {"a": 1}, "same"))
    b = board.submit(Task("core.echo", {"a": 2}, "same"))
    assert a.id == b.id and len(board.list()) == 1


def test_wrong_token_and_stale_lease(board):
    board.submit(Task("core.echo"))
    c = board.claim("w1", lease_s=10)
    with pytest.raises(LeaseLost):
        board.complete(c.id, "nope", {})
    board.clock.t += 11
    with pytest.raises(LeaseLost):
        board.complete(c.id, c.lease_token, {})
    c2 = board.claim("w2", lease_s=10)  # reclaimed after expiry
    assert c2.id == c.id and c2.attempts == 2 and c2.lease_token != c.lease_token
    with pytest.raises(LeaseLost):
        board.complete(c.id, c.lease_token, {})  # old worker cannot finish
    board.complete(c2.id, c2.lease_token, {})


def test_retries_then_failed(board):
    board.submit(Task("core.echo", max_attempts=2))
    c = board.claim("w1")
    assert board.fail(c.id, c.lease_token, "boom").state is JobState.QUEUED
    c = board.claim("w1")
    assert board.fail(c.id, c.lease_token, "boom").state is JobState.FAILED
    assert board.claim("w1") is None


def test_expired_lease_exhausts_attempts(board):
    board.submit(Task("core.echo", max_attempts=1))
    board.claim("w1", lease_s=5)
    board.clock.t += 6
    assert board.claim("w1") is None
    assert board.list()[0].state is JobState.FAILED


def test_heartbeat_extends(board):
    board.submit(Task("core.echo"))
    c = board.claim("w1", lease_s=10)
    board.clock.t += 8
    board.heartbeat(c.id, c.lease_token, lease_s=10)
    board.clock.t += 8
    board.complete(c.id, c.lease_token, {})


def test_cancel(board):
    j = board.submit(Task("core.echo"))
    assert board.cancel(j.id).state is JobState.CANCELLED
    assert board.claim("w1") is None
    assert board.cancel(j.id).state is JobState.CANCELLED


def test_cancel_while_leased_blocks_finish(board):
    board.submit(Task("core.echo"))
    c = board.claim("w1")
    board.cancel(c.id)
    with pytest.raises(LeaseLost):
        board.complete(c.id, c.lease_token, {})


def test_kind_filter(board):
    board.submit(Task("a.one"))
    board.submit(Task("b.two"))
    assert board.claim("w1", kinds=["b.two"]).kind == "b.two"


def test_input_validation(board):
    with pytest.raises(ContractError):
        board.submit({"kind": "x"})
    with pytest.raises(ContractError):
        board.claim("bad worker")
    with pytest.raises(ContractError):
        board.claim("w1", lease_s=0)
    with pytest.raises(ContractError):
        board.claim("w1", kinds=["x' OR 1=1 --"])
    board.submit(Task("core.echo"))
    c = board.claim("w1")
    with pytest.raises(ContractError):
        board.complete(c.id, c.lease_token, ["not", "dict"])
    with pytest.raises(ContractError):
        board.complete(c.id, c.lease_token, {"x": "a" * 300_000})


def _tamper(board, sql):
    board._db.execute(sql)


@pytest.mark.parametrize("sql", [
    "UPDATE receipts SET detail='{}' WHERE seq=1",
    "UPDATE receipts SET event='succeeded' WHERE seq=2",
    "DELETE FROM receipts WHERE seq=2",
    "UPDATE receipts SET at=at+1 WHERE seq=3",
])
def test_tampering_detected(board, sql):
    board.submit(Task("core.echo"))
    c = board.claim("w1")
    board.complete(c.id, c.lease_token, {})
    board.submit(Task("core.echo"))
    assert board.verify_receipts()[0]
    _tamper(board, sql)
    assert not board.verify_receipts()[0]


def test_two_connections_never_double_claim(tmp_path):
    db = tmp_path / "j.db"
    a, b = JobBoard(db), JobBoard(db)
    for i in range(20):
        a.submit(Task("core.echo", {"i": i}))
    seen = []
    for _ in range(10):
        for brd in (a, b):
            j = brd.claim("w")
            if j:
                seen.append(j.id)
    assert len(seen) == len(set(seen)) == 20
    ok, _ = a.verify_receipts()
    assert ok
    a.close(), b.close()


def test_file_db_persists(tmp_path):
    db = tmp_path / "j.db"
    a = JobBoard(db)
    a.submit(Task("core.echo", {}, "k"))
    a.close()
    b = JobBoard(db)
    assert len(b.list()) == 1 and b.verify_receipts()[0]
    b.close()


def test_head_detects_truncation(board):
    board.submit(Task("core.echo"))
    board.submit(Task("core.echo"))
    n, h = board.head()
    board._db.execute("DELETE FROM receipts WHERE seq=?", (n,))
    assert not board.verify()[0]               # job 2 now has no receipt
    board._db.execute("DELETE FROM jobs WHERE id=2")
    assert board.verify()[0]                   # removing both: the chain alone can't see it
    assert not board.verify(expect_head=h)[0]  # a saved head can



def test_busy_begin_releases_lock(tmp_path):
    import threading
    db = tmp_path / "busy.db"
    a = JobBoard(db)
    blocker = sqlite3.connect(str(db), isolation_level=None, timeout=0)
    blocker.execute("BEGIN IMMEDIATE")
    a._db.execute("PRAGMA busy_timeout=50")
    with pytest.raises(sqlite3.OperationalError):
        a.submit(Task("core.echo"))
    blocker.execute("ROLLBACK")
    blocker.close()
    out = []
    t = threading.Thread(target=lambda: out.append(a.submit(Task("core.echo"))))
    t.start()
    t.join(5)
    assert out and out[0].state is JobState.QUEUED
    a.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_db_file_is_private(tmp_path):
    os.chmod(tmp_path, 0o755)  # noqa: S103 - test needs a world-readable dir
    old = os.umask(0o022)
    try:
        b = JobBoard(tmp_path / "p.db")
        b.submit(Task("core.echo"))
        b.close()
    finally:
        os.umask(old)
    assert (os.stat(tmp_path / "p.db").st_mode & 0o777) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_db_symlink_refused(tmp_path):
    (tmp_path / "real.db").write_bytes(b"")
    os.symlink(tmp_path / "real.db", tmp_path / "link.db")
    with pytest.raises(ContractError):
        JobBoard(tmp_path / "link.db")


def test_verify_detects_payload_and_result_edits(board):
    board.submit(Task("core.echo", {"a": 1}))
    c = board.claim("w1")
    board.complete(c.id, c.lease_token, {"ok": True})
    board.submit(Task("core.echo", {"b": 2}))
    assert board.verify()[0]
    board._db.execute("UPDATE jobs SET payload='{\"b\":3}' WHERE id=2")
    assert not board.verify()[0]
    board._db.execute("UPDATE jobs SET payload='{\"b\":2}' WHERE id=2")
    board._db.execute("UPDATE jobs SET result='{\"ok\":false}' WHERE id=1")
    assert not board.verify()[0]


def test_verify_detects_inserted_job(board):
    board.submit(Task("core.echo"))
    board._db.execute("INSERT INTO jobs(kind,payload,state,max_attempts,created,updated) "
                      "VALUES ('core.echo','{}','queued',3,0,0)")
    assert not board.verify()[0]


def test_verify_genesis_anchor(board):
    assert board.verify(expect_head="0" * 64)[0]


@pytest.mark.parametrize("tok", ["", "x" * 32, "é" * 32, None, 5, "A" * 32])
def test_bad_tokens_are_lease_lost(board, tok):
    board.submit(Task("core.echo"))
    c = board.claim("w1")
    with pytest.raises(LeaseLost):
        board.complete(c.id, tok, {})


def test_readonly_refuses_missing_and_writes(tmp_path):
    with pytest.raises(ContractError):
        JobBoard(tmp_path / "missing.db", readonly=True)
    JobBoard(tmp_path / "x.db").close()
    ro = JobBoard(tmp_path / "x.db", readonly=True)
    with pytest.raises(ContractError):
        ro.submit(Task("core.echo"))
    assert ro.verify()[0]
    ro.close()


def test_concurrent_threads_never_double_claim(tmp_path):
    import threading
    db = tmp_path / "c.db"
    seed = JobBoard(db)
    for i in range(60):
        seed.submit(Task("core.echo", {"i": i}))
    claimed, errors = [], []

    def work():
        b = JobBoard(db)
        try:
            while True:
                j = b.claim("w")
                if j is None:
                    return
                claimed.append(j.id)
                b.complete(j.id, j.lease_token, {})
        except Exception as e:  # noqa: BLE001
            errors.append(e)
        finally:
            b.close()
    ts = [threading.Thread(target=work) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    assert not errors and sorted(claimed) == list(range(1, 61))
    assert seed.verify()[0]
    seed.close()


def _proc_worker(db, q):
    try:
        from syrebrum_core.jobs import JobBoard as JB
        b = JB(db)
        got = []
        while (j := b.claim("p")) is not None:
            got.append(j.id)
            b.complete(j.id, j.lease_token, {})
        b.close()
        q.put(got)
    except BaseException as exc:  # noqa: BLE001 - report child errors to the test
        q.put(f"{type(exc).__name__}: {exc}")


def test_concurrent_processes_never_double_claim(tmp_path):
    import multiprocessing as mp
    db = str(tmp_path / "p.db")
    seed = JobBoard(db)
    for i in range(40):
        seed.submit(Task("core.echo", {"i": i}))
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    ps = [ctx.Process(target=_proc_worker, args=(db, q)) for _ in range(3)]
    for p in ps:
        p.start()
    outs = [q.get(timeout=60) for _ in ps]
    assert all(isinstance(o, list) for o in outs), outs
    got = [i for o in outs for i in o]
    for p in ps:
        p.join(30)
    assert sorted(got) == list(range(1, 41)) and seed.verify()[0]
    seed.close()


def test_verify_detects_kind_change_and_removed_job(board):
    board.submit(Task("core.echo"))
    board.submit(Task("core.echo"))
    board._db.execute("UPDATE jobs SET kind='core.inventory' WHERE id=1")
    assert not board.verify()[0]
    board._db.execute("UPDATE jobs SET kind='core.echo' WHERE id=1")
    board._db.execute("DELETE FROM jobs WHERE id=1")
    ok, msg, *_ = board.verify()
    assert not ok and "removed" in msg


@pytest.mark.parametrize("jid", [0, -1, 2**63, 10**30, True, "1"])
def test_bad_job_ids_rejected(board, jid):
    with pytest.raises(ContractError):
        board.get(jid)
    with pytest.raises(ContractError):
        board.receipts(jid)


def test_payload_changed_after_task_creation_still_capped(board):
    t = Task("core.echo", {})
    t.payload["big"] = "x" * 70_000
    with pytest.raises(ContractError):
        board.submit(t)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_folder_writable_by_others_refused(tmp_path):
    d = tmp_path / "shared"
    d.mkdir()
    os.chmod(d, 0o777)  # noqa: S103 - the unsafe case under test
    with pytest.raises(ContractError):
        JobBoard(d / "x.db")
    os.chmod(d, 0o1777)  # noqa: S103 - sticky, like /tmp: also refused (side files can be squatted)
    with pytest.raises(ContractError):
        JobBoard(d / "x.db")
    os.chmod(d, 0o700)
    JobBoard(d / "x.db").close()
    os.chmod(d, 0o777)  # noqa: S103
    with pytest.raises(ContractError):  # read-only opens are checked too
        JobBoard(d / "x.db", readonly=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks")
def test_sidecar_symlink_refused(tmp_path):
    (tmp_path / "elsewhere").write_text("")
    os.symlink(tmp_path / "elsewhere", tmp_path / "x.db-wal")
    with pytest.raises(ContractError):
        JobBoard(tmp_path / "x.db")


@pytest.mark.parametrize("finish", ["cancel", "complete"])
def test_finished_job_edited_back_to_queued_is_not_run(board, finish):
    j = board.submit(Task("core.echo"))
    if finish == "cancel":
        board.cancel(j.id)
    else:
        c = board.claim("w")
        board.complete(c.id, c.lease_token, {})
    board._db.execute("UPDATE jobs SET state='queued' WHERE id=?", (j.id,))
    assert board.claim("w") is None
    ok, msg, *_ = board.verify()
    assert not ok and "state" in msg


def test_job_inserted_outside_core_is_not_run(board):
    board._db.execute("INSERT INTO jobs(kind,payload,state,max_attempts,created,updated) "
                      "VALUES ('core.echo','{}','queued',3,0,0)")
    assert board.claim("w") is None


def test_verify_accepts_every_normal_state(board):
    a = board.submit(Task("core.echo"))
    board.submit(Task("core.echo"))
    c = board.claim("w")
    assert c.id == a.id and board.verify()[0]
    board.fail(c.id, c.lease_token, "x")
    assert board.verify()[0]
    c = board.claim("w", lease_s=1)
    board.clock.t += 5
    board.claim("w")
    assert board.verify()[0]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_existing_db_readable_by_others_refused(tmp_path):
    JobBoard(tmp_path / "x.db").close()
    os.chmod(tmp_path / "x.db", 0o644)
    for ro in (False, True):
        with pytest.raises(ContractError):
            JobBoard(tmp_path / "x.db", readonly=ro)


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks")
def test_readonly_refuses_sidecar_symlink(tmp_path):
    JobBoard(tmp_path / "x.db").close()
    (tmp_path / "elsewhere").write_text("")
    os.symlink(tmp_path / "elsewhere", tmp_path / "x.db-wal")
    with pytest.raises(ContractError):
        JobBoard(tmp_path / "x.db", readonly=True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX advisory locks")
def test_opening_second_board_keeps_first_boards_locks(tmp_path):
    """Opening a board must not open and close extra descriptors on the database:
    that silently drops this process's SQLite locks (and can corrupt the file)."""
    import subprocess
    import sys
    db = tmp_path / "x.db"
    a = JobBoard(db)
    a._db.execute("BEGIN IMMEDIATE")  # hold the write lock
    try:
        JobBoard(db, readonly=True).close()
        from syrebrum_core import jobs as jm
        jm._check_files(db, create=True)
        probe = ("import sqlite3,sys\n"
                 "c=sqlite3.connect(sys.argv[1],timeout=0,isolation_level=None)\n"
                 "try:\n c.execute('BEGIN IMMEDIATE'); print('GOT')\n"
                 "except sqlite3.OperationalError: print('LOCKED')\n")
        out = subprocess.run([sys.executable, "-c", probe, str(db)], capture_output=True, text=True,  # noqa: S603
                             timeout=30).stdout.strip()
        assert out == "LOCKED"
    finally:
        a._db.execute("ROLLBACK")
        a.close()


def test_verify_reports_hand_edited_values_instead_of_crashing(board):
    board.submit(Task("core.echo", {"a": 1}))
    board._db.execute("UPDATE jobs SET payload=X'ff' WHERE id=1")
    assert board.verify()[0] is False
    board._db.execute("UPDATE jobs SET payload='{\"a\":1}' WHERE id=1")
    assert board.verify()[0]
    board._db.execute("UPDATE receipts SET detail='123' WHERE seq=1")
    assert board.verify()[0] is False


def test_final_failure_is_not_retried(board):
    board.submit(Task("core.echo", max_attempts=5))
    c = board.claim("w")
    j = board.fail(c.id, c.lease_token, "x", final=True)
    assert j.state is JobState.FAILED and board.claim("w") is None and board.verify()[0]


def test_lease_expiry_on_last_attempt_is_a_failed_receipt(board):
    board.submit(Task("core.echo", max_attempts=1))
    board.claim("w", lease_s=1)
    board.clock.t += 5
    assert board.claim("w") is None
    assert [r.event for r in board.receipts(1)][-1] == "failed"
    assert board.get(1).state is JobState.FAILED and board.verify()[0]


def test_verify_rejects_impossible_event_order(board):
    import json as _j

    from syrebrum_core.jobs import _receipt_hash
    board.submit(Task("core.echo"))
    c = board.claim("w")
    board.complete(c.id, c.lease_token, {})
    # Forge a well-hashed receipt that resurrects the finished job.
    seq, head = board.head()
    d = _j.dumps({"worker": "x", "attempt": 2}, sort_keys=True, separators=(",", ":"))
    board._db.execute("INSERT INTO receipts(job_id,event,detail,at,prev_hash,hash) VALUES (1,'leased',?,1.0,?,?)",
                      (d, head, _receipt_hash(1, "leased", d, 1.0, head)))
    board._db.execute("UPDATE jobs SET state='leased' WHERE id=1")
    ok, msg, *_ = board.verify()
    assert not ok and "can't follow" in msg


def test_authorize_twice_under_one_lease_is_refused(board):
    board.submit(Task("core.echo", {"a": 1}))
    j = board.claim("w")
    board.authorize(j.id, j.lease_token, {})
    with pytest.raises(ContractError):
        board.authorize(j.id, j.lease_token, {})
    board.complete(j.id, j.lease_token, {}, {})
    assert board.verify()[0]
