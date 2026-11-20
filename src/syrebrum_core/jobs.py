# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
"""Local job board on SQLite, with leases, retries and tamper-evident receipts.

- A job is claimed with a *lease*. If the worker dies, the lease expires and
  another worker may claim the job again (up to max_attempts).
- Only the worker holding the current lease token can finish a job.
- Every state change appends a receipt. Each receipt contains the hash of the
  previous one, so editing or deleting history breaks verify_receipts().
- Submitting the same idempotency_key twice returns the original job.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    MAX_PAYLOAD_BYTES,
    TERMINAL_STATES,
    ContractError,
    JobState,
    Task,
    canonical_json,
    check_id,
    sha256_hex,
)

GENESIS = "0" * 64
_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  idempotency_key TEXT UNIQUE,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL,
  lease_owner TEXT,
  lease_token TEXT,
  lease_expires REAL,
  result TEXT,
  created REAL NOT NULL,
  updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  event TEXT NOT NULL,
  detail TEXT NOT NULL,
  at REAL NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state, lease_expires);
CREATE INDEX IF NOT EXISTS receipts_job ON receipts(job_id, seq);
"""


def _check_parent(path: Path) -> None:
    """The folder must be yours (or root's) and writable only by its owner (POSIX).

    Shared folders such as /tmp are refused even with the sticky bit: other users
    could create SQLite's -wal or -shm file there before Core does.
    """
    st = os.stat(path.parent if str(path.parent) else ".")
    if st.st_uid not in (os.getuid(), 0):
        raise ContractError(f"refusing to use {path}: its folder belongs to another user")
    if st.st_mode & 0o022:
        raise ContractError(f"refusing to use {path}: its folder is writable by other users")


def _check_existing(path: Path) -> bool:
    """lstat-only check of an existing file: a regular file we own, not a symlink.

    Never opens the file. Opening and closing another descriptor on a SQLite file
    would drop this process's POSIX locks on it and could corrupt the database.
    Returns False if the file doesn't exist.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        raise ContractError(f"refusing to use {path}: it is a symbolic link")
    if not stat.S_ISREG(st.st_mode):
        raise ContractError(f"refusing to use {path}: not a regular file")
    if st.st_uid != os.getuid():
        raise ContractError(f"refusing to use {path}: owned by another user")
    if st.st_mode & 0o077:
        raise ContractError(f"refusing to use {path}: readable or writable by other users (chmod 600 it)")
    return True


_SIDECARS = ("-wal", "-shm", "-journal")


def _check_files(path: Path, create: bool) -> None:
    """Check the folder, the database and SQLite's side files before connecting.

    A new database is created owner-only (0600) with O_EXCL; SQLite gives its
    -wal and -shm files the database file's permissions.
    """
    if os.name != "posix":
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ContractError(f"refusing to use {path}: not a regular file")
        return  # Windows: files inherit the folder's ACLs; keep the database in your profile
    _check_parent(path)
    if not _check_existing(path):
        if not create:
            raise ContractError(f"no job database at {path}")
        try:
            os.close(os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
        except FileExistsError:
            raise ContractError(f"refusing to use {path}: it appeared while being created") from None
        _check_existing(path)
    for suffix in _SIDECARS:
        _check_existing(Path(str(path) + suffix))


class LeaseLost(RuntimeError):
    """The caller no longer holds the lease (expired or taken over)."""


@dataclass(frozen=True)
class Job:
    id: int
    kind: str
    payload: dict
    state: JobState
    attempts: int
    max_attempts: int
    lease_token: str | None
    lease_expires: float | None
    result: dict | None


@dataclass(frozen=True)
class Receipt:
    seq: int
    job_id: int
    event: str
    detail: dict
    at: float
    prev_hash: str
    hash: str


def _receipt_hash(job_id: int, event: str, detail: str, at: float, prev_hash: str) -> str:
    return sha256_hex({"job_id": job_id, "event": event, "detail": detail, "at": at, "prev": prev_hash})


def _text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_TOKEN_RE = re.compile(r"[0-9a-f]{32}")
_FINISH_EVENTS = {"succeeded", "denied", "failed", "retry"}
_TERMINAL_EVENTS = {"succeeded", "denied", "failed", "cancelled"}
# State each job must be in, given the last receipt written for it.
_STATE_AFTER = {"submitted": {"queued"}, "leased": {"leased"}, "effect_authorized": {"leased"},
                "retry": {"queued"}, "lease_expired": {"queued"},
                **{e: {e} for e in _TERMINAL_EVENTS}}
_QUEUED_EVENTS = {"submitted", "retry", "lease_expired"}
_LEASED_EVENTS = {"leased", "effect_authorized"}
_AFTER_LEASE = {"succeeded", "denied", "failed", "retry", "lease_expired", "cancelled"}
# Which event may follow which, per job. Nothing follows a terminal event.
_NEXT = {None: {"submitted"}, "submitted": {"leased", "cancelled"}, "retry": {"leased", "cancelled"},
         "lease_expired": {"leased", "cancelled"}, "leased": _AFTER_LEASE | {"effect_authorized"},
         "effect_authorized": _AFTER_LEASE, **{e: set() for e in _TERMINAL_EVENTS}}


class JobBoard:
    """A job board backed by one SQLite file.

    Lease tokens are returned only by claim(). They prove which worker holds a
    job; they are not an authorization system against people who can read the
    database file.
    """

    def __init__(self, path: str | Path = ":memory:", clock=time.time, *, readonly: bool = False) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self.readonly = readonly
        memory = str(path) == ":memory:"
        if readonly:
            if memory or not Path(path).is_file() or Path(path).is_symlink():
                raise ContractError(f"no job database at {path}")
            _check_files(Path(path), create=False)
            uri = Path(path).resolve().as_uri() + "?mode=ro"
            self._db = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=False, timeout=30)
        else:
            if not memory:
                _check_files(Path(path), create=True)
            self._db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False, timeout=30)
        self._db.row_factory = sqlite3.Row
        if not readonly:
            self._db.execute("PRAGMA journal_mode=MEMORY" if memory else "PRAGMA journal_mode=WAL")
            self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- internal -----------------------------------------------------------
    def _tx(self):
        if self.readonly:
            raise ContractError("this job board was opened read-only")
        return _Tx(self._db, self._lock)

    def _snapshot(self):
        """A consistent read: one transaction, under the lock."""
        return _Tx(self._db, self._lock, begin="BEGIN")

    def _receipt(self, job_id: int, event: str, detail: dict) -> None:
        row = self._db.execute("SELECT hash FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        at = round(self._clock(), 6)
        d = canonical_json(detail)
        self._db.execute("INSERT INTO receipts(job_id,event,detail,at,prev_hash,hash) VALUES (?,?,?,?,?,?)",
                         (job_id, event, d, at, prev, _receipt_hash(job_id, event, d, at, prev)))

    @staticmethod
    def _job(row: sqlite3.Row, with_token: bool = False) -> Job:
        return Job(row["id"], row["kind"], json.loads(row["payload"]), JobState(row["state"]), row["attempts"],
                   row["max_attempts"], row["lease_token"] if with_token else None, row["lease_expires"],
                   json.loads(row["result"]) if row["result"] is not None else None)

    def _row(self, job_id: int) -> sqlite3.Row:
        _check_job_id(job_id)
        row = self._db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise KeyError(job_id)
        return row

    # -- public API ---------------------------------------------------------
    def submit(self, task: Task) -> Job:
        if not isinstance(task, Task):
            raise ContractError("submit() needs a Task")
        body = canonical_json(task.payload)  # serialized once; the same bytes are stored and hashed
        if len(body.encode("utf-8")) > MAX_PAYLOAD_BYTES:  # re-checked: a Task's dict can change after creation
            raise ContractError(f"payload is over {MAX_PAYLOAD_BYTES} bytes")
        with self._tx():
            if task.idempotency_key is not None:
                row = self._db.execute("SELECT * FROM jobs WHERE idempotency_key=?", (task.idempotency_key,)).fetchone()
                if row:
                    return self._job(row)
            now = self._clock()
            cur = self._db.execute(
                "INSERT INTO jobs(kind,payload,idempotency_key,state,max_attempts,created,updated) VALUES (?,?,?,?,?,?,?)",
                (task.kind, body, task.idempotency_key, JobState.QUEUED.value, task.max_attempts, now, now))
            self._receipt(cur.lastrowid, "submitted", {"kind": task.kind, "payload_sha256": _text_sha256(body)})
            return self._job(self._row(cur.lastrowid))

    def get(self, job_id: int) -> Job:
        with self._snapshot():
            return self._job(self._row(job_id))

    def list(self, state: JobState | None = None, limit: int = 100) -> list[Job]:
        n = max(1, min(int(limit), 10000))
        with self._snapshot():
            if state is None:
                rows = self._db.execute("SELECT * FROM jobs ORDER BY id LIMIT ?", (n,)).fetchall()
            else:
                rows = self._db.execute("SELECT * FROM jobs WHERE state=? ORDER BY id LIMIT ?",
                                        (JobState(state).value, n)).fetchall()
            return [self._job(r) for r in rows]

    def claim(self, worker: str, kinds: list[str] | None = None, lease_s: float = 60.0) -> Job | None:
        """Lease the oldest runnable job. Expired leases are reclaimed first.
        The returned Job is the only place the lease token appears."""
        check_id("worker", worker)
        _check_lease(lease_s)
        wanted = {check_id("kind", k) for k in kinds} if kinds else None
        with self._tx():
            self._expire_leases()
            row = None
            for r in self._db.execute("SELECT * FROM jobs WHERE state=? ORDER BY id", (JobState.QUEUED.value,)):
                if (wanted is None or r["kind"] in wanted) and not self._finished_by_receipt(r["id"]):
                    row = r
                    break
            if row is None:
                return None
            token, now = secrets.token_hex(16), self._clock()
            self._db.execute("UPDATE jobs SET state=?, attempts=attempts+1, lease_owner=?, lease_token=?, "
                             "lease_expires=?, updated=? WHERE id=?",
                             (JobState.LEASED.value, worker, token, now + lease_s, now, row["id"]))
            self._receipt(row["id"], "leased", {"worker": worker, "attempt": row["attempts"] + 1})
            return self._job(self._row(row["id"]), with_token=True)

    def _last_event(self, job_id: int) -> str | None:
        last = self._db.execute("SELECT event FROM receipts WHERE job_id=? ORDER BY seq DESC LIMIT 1",
                                (job_id,)).fetchone()
        return None if last is None else last["event"]

    def _finished_by_receipt(self, job_id: int) -> bool:
        """True unless the receipts say this job is waiting to run. Guards against
        a job row being edited (for example back to queued) outside Core."""
        return self._last_event(job_id) not in _QUEUED_EVENTS

    def heartbeat(self, job_id: int, token: str, lease_s: float = 60.0) -> None:
        _check_lease(lease_s)
        with self._tx():
            self._require_lease(job_id, token)
            now = self._clock()
            self._db.execute("UPDATE jobs SET lease_expires=?, updated=? WHERE id=?", (now + lease_s, now, job_id))

    def authorize(self, job_id: int, token: str, decision: dict, lease_s: float = 60.0) -> None:
        """Record an ALLOW under the lease, just before the effect runs, and
        extend the lease. This proves approval, not that the effect happened.
        Raises LeaseLost if the job was cancelled or taken over meanwhile."""
        _check_lease(lease_s)
        if not isinstance(decision, dict):
            raise ContractError("decision must be a JSON object")
        with self._tx():
            self._require_lease(job_id, token)
            if self._last_event(job_id) == "effect_authorized":
                raise ContractError("effect already authorized under this lease")
            now = self._clock()
            self._db.execute("UPDATE jobs SET lease_expires=?, updated=? WHERE id=?", (now + lease_s, now, job_id))
            self._receipt(job_id, "effect_authorized", {"decision": decision})

    def complete(self, job_id: int, token: str, result: dict, decision: dict | None = None) -> Job:
        """Record success. For effect jobs, pass the ALLOW decision so it is in the receipt."""
        return self._finish(job_id, token, JobState.SUCCEEDED, result, decision)

    def deny(self, job_id: int, token: str, decision: dict) -> Job:
        """Record that policy refused the job's effect. Never retried."""
        return self._finish(job_id, token, JobState.DENIED, decision, decision)

    def fail(self, job_id: int, token: str, error: str, *, final: bool = False) -> Job:
        """Record a failure. The job is re-queued until max_attempts is used up,
        or not at all with final=True (for example, after an effect may have run)."""
        body = canonical_json({"error": str(error)[:2000]})
        with self._tx():
            row = self._require_lease(job_id, token)
            state = JobState.FAILED if final or row["attempts"] >= row["max_attempts"] else JobState.QUEUED
            self._db.execute("UPDATE jobs SET state=?, lease_owner=NULL, lease_token=NULL, lease_expires=NULL, "
                             "result=?, updated=? WHERE id=?", (state.value, body, self._clock(), job_id))
            self._receipt(job_id, "failed" if state is JobState.FAILED else "retry",
                          {"attempt": row["attempts"], "error": str(error)[:200], "result_sha256": _text_sha256(body)})
            return self._job(self._row(job_id))

    def cancel(self, job_id: int) -> Job:
        with self._tx():
            row = self._row(job_id)
            if JobState(row["state"]) in TERMINAL_STATES:
                return self._job(row)
            self._db.execute("UPDATE jobs SET state=?, lease_owner=NULL, lease_token=NULL, lease_expires=NULL, "
                             "updated=? WHERE id=?", (JobState.CANCELLED.value, self._clock(), job_id))
            self._receipt(job_id, "cancelled", {})
            return self._job(self._row(job_id))

    def receipts(self, job_id: int | None = None) -> list[Receipt]:
        with self._snapshot():
            if job_id is None:
                rows = self._db.execute("SELECT * FROM receipts ORDER BY seq").fetchall()
            else:
                _check_job_id(job_id)
                rows = self._db.execute("SELECT * FROM receipts WHERE job_id=? ORDER BY seq", (job_id,)).fetchall()
            return [Receipt(r["seq"], r["job_id"], r["event"], json.loads(r["detail"]), r["at"], r["prev_hash"],
                            r["hash"]) for r in rows]

    def verify(self, expect_head: str | None = None) -> tuple[bool, str, int, str]:
        """Check the receipts and every job against them. Returns (ok, message, count, head).
        Never raises on a hand-edited database; it reports it as not ok."""
        try:
            return self._verify(expect_head)
        except (TypeError, ValueError, AttributeError, KeyError, ContractError, RecursionError):
            # Values a hand-edited database can hold (BLOBs, NULLs, non-object JSON).
            return False, "the database holds values Core never writes; it was altered", 0, GENESIS

    def _verify(self, expect_head: str | None) -> tuple[bool, str, int, str]:
        """Check the receipt chain, and that every job's kind, payload, result and
        state match what the receipts recorded. Returns (ok, message, count, head).

        Not covered: attempt counts, lease details and timestamps.

        expect_head: a head hash saved earlier. It must still be in the chain,
        which detects deletion of receipts up to that point (not later ones).
        """
        with self._snapshot():
            prev, last_seq, seen_anchor = GENESIS, 0, expect_head in (None, GENESIS)
            payloads: dict[int, str] = {}
            results: dict[int, str | None] = {}
            last_event: dict[int, str] = {}
            for r in self._db.execute("SELECT * FROM receipts ORDER BY seq"):
                if r["seq"] != last_seq + 1:
                    return False, f"receipt {last_seq + 1} is missing", last_seq, prev
                if r["prev_hash"] != prev:
                    return False, f"receipt {r['seq']} does not follow receipt {last_seq}", last_seq, prev
                if r["hash"] != _receipt_hash(r["job_id"], r["event"], r["detail"], r["at"], r["prev_hash"]):
                    return False, f"receipt {r['seq']} was altered", last_seq, prev
                detail = json.loads(r["detail"])
                if r["event"] == "submitted":
                    payloads[r["job_id"]] = (detail.get("payload_sha256"), detail.get("kind"))
                    results[r["job_id"]] = None
                elif r["event"] in _FINISH_EVENTS:
                    results[r["job_id"]] = detail.get("result_sha256")
                if r["event"] not in _NEXT.get(last_event.get(r["job_id"]), ()):
                    return False, f"receipt {r['seq']} ({r['event']}) can't follow the job's earlier events", \
                        last_seq, prev
                last_event[r["job_id"]] = r["event"]
                prev, last_seq = r["hash"], r["seq"]
                seen_anchor = seen_anchor or r["hash"] == expect_head
            if not seen_anchor:
                return False, "the saved head is no longer in the chain; history was removed", last_seq, prev
            jobs = self._db.execute("SELECT id, kind, payload, result, state FROM jobs ORDER BY id")
            n = 0
            for j in jobs:  # streamed, not loaded all at once
                if j["id"] not in payloads:
                    return False, f"job {j['id']} has no receipts (it was added outside Core)", last_seq, prev
                want_payload, want_kind = payloads.pop(j["id"])
                if _text_sha256(j["payload"]) != want_payload or j["kind"] != want_kind:
                    return False, f"job {j['id']} payload or kind was changed", last_seq, prev
                want = results[j["id"]]
                have = None if j["result"] is None else _text_sha256(j["result"])
                if have != want:
                    return False, f"job {j['id']} result was changed", last_seq, prev
                if j["state"] not in _STATE_AFTER.get(last_event[j["id"]], ()):
                    return False, f"job {j['id']} state does not match its receipts", last_seq, prev
                n += 1
            if payloads:
                return False, f"job {min(payloads)} was removed", last_seq, prev
            return True, f"{last_seq} receipts and {n} jobs verified", last_seq, prev

    def verify_receipts(self) -> tuple[bool, str]:
        ok, msg, _, _ = self.verify()
        return ok, msg

    def head(self) -> tuple[int, str]:
        """(count, hash) of the newest receipt. Save it somewhere else and pass it
        to verify(expect_head=...) later to detect removed history."""
        with self._snapshot():
            row = self._db.execute("SELECT seq, hash FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
            return (row["seq"], row["hash"]) if row else (0, GENESIS)

    # -- helpers ------------------------------------------------------------
    def _finish(self, job_id: int, token: str, state: JobState, result: dict, decision: dict | None) -> Job:
        if not isinstance(result, dict):
            raise ContractError("result must be a JSON object")
        body = canonical_json(result)
        if len(body.encode("utf-8")) > 256 * 1024:
            raise ContractError("result is larger than 256 KiB")
        detail = {"result_sha256": _text_sha256(body)}
        if decision is not None:
            detail["decision"] = {k: decision.get(k) for k in
                                  ("verdict", "reason", "request_hash", "policy_version", "approval_id")}
        with self._tx():
            self._require_lease(job_id, token)
            self._db.execute("UPDATE jobs SET state=?, lease_owner=NULL, lease_token=NULL, lease_expires=NULL, "
                             "result=?, updated=? WHERE id=?", (state.value, body, self._clock(), job_id))
            self._receipt(job_id, state.value, detail)
            return self._job(self._row(job_id))

    def _require_lease(self, job_id: int, token: str) -> sqlite3.Row:
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise LeaseLost(f"job {job_id}: lease not held")
        try:
            row = self._row(job_id)
        except KeyError:
            raise LeaseLost(f"job {job_id}: no such job") from None
        if (row["state"] != JobState.LEASED.value or row["lease_token"] is None
                or not secrets.compare_digest(row["lease_token"], token) or row["lease_expires"] < self._clock()):
            raise LeaseLost(f"job {job_id}: lease not held")
        return row

    def _expire_leases(self) -> None:
        now = self._clock()
        for row in self._db.execute("SELECT * FROM jobs WHERE state=? AND lease_expires<?",
                                    (JobState.LEASED.value, now)).fetchall():
            if self._last_event(row["id"]) not in _LEASED_EVENTS:
                continue  # the row says leased but the receipts don't: leave it for verify to report
            detail = {"worker": row["lease_owner"], "attempt": row["attempts"]}
            if row["attempts"] >= row["max_attempts"]:
                state, event = JobState.FAILED, "failed"
                detail.update(reason="lease expired",
                              result_sha256=None if row["result"] is None else _text_sha256(row["result"]))
            else:
                state, event = JobState.QUEUED, "lease_expired"
            self._db.execute("UPDATE jobs SET state=?, lease_owner=NULL, lease_token=NULL, lease_expires=NULL, "
                             "updated=? WHERE id=?", (state.value, now, row["id"]))
            self._receipt(row["id"], event, detail)


def _check_job_id(job_id) -> None:
    if isinstance(job_id, bool) or not isinstance(job_id, int) or not 1 <= job_id <= 2**63 - 1:
        raise ContractError("job id must be a positive integer")


def _check_lease(lease_s) -> None:
    if isinstance(lease_s, bool) or not isinstance(lease_s, (int, float)) or not 1 <= lease_s <= 3600:
        raise ContractError("lease_s must be a number from 1 to 3600 seconds")


class _Tx:
    """BEGIN IMMEDIATE so two processes can't claim the same job."""

    def __init__(self, db: sqlite3.Connection, lock: threading.RLock, begin: str = "BEGIN IMMEDIATE") -> None:
        self.db, self.lock, self.outer, self.begin = db, lock, False, begin

    def __enter__(self):
        self.lock.acquire()
        try:
            self.outer = not self.db.in_transaction
            if self.outer:
                self.db.execute(self.begin)
        except BaseException:
            self.lock.release()  # never keep the lock if BEGIN fails (e.g. database busy)
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.outer:
                if exc_type is None:
                    try:
                        self.db.execute("COMMIT")
                    except BaseException:
                        if self.db.in_transaction:
                            self.db.execute("ROLLBACK")
                        raise
                elif self.db.in_transaction:
                    self.db.execute("ROLLBACK")
        finally:
            self.lock.release()
        return False
