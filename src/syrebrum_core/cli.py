# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
"""Command line: syrebrum-core <command>. Run with --help for details.

Exit codes: 0 ok, 2 bad input or unusable database, 3 effect denied,
4 verification failed.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

from . import __version__
from . import inventory as inv
from .contracts import ContractError, JobState, Task, parse_json_object
from .failstop import EffectRequest, NoFailStop, SocketFailStop, check
from .jobs import JobBoard
from .worker import Worker


def _default_db(create: bool) -> Path:
    """Where the database lives. Read-only commands never create or change anything."""
    custom = os.environ.get("SYREBRUM_HOME")
    p = Path(custom) if custom else Path.home() / ".syrebrum"
    if create:
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not custom and os.name == "posix" and not p.is_symlink() and p.stat().st_uid == os.getuid():
            p.chmod(0o700)  # our own ~/.syrebrum folder: owner-only; a custom folder is checked, not changed
    return p / "core.db"


def _failstop(addr: str | None):
    addr = addr or os.environ.get("SYREBRUM_FAILSTOP")
    return SocketFailStop(addr) if addr else NoFailStop()


def _out(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="syrebrum-core", description="Local job runner with fail-closed effects.")
    p.add_argument("--version", action="version", version=f"syrebrum-core {__version__}")
    p.add_argument("--db", help="job database path (default: ~/.syrebrum/core.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("submit", help="queue a job")
    s.add_argument("kind")
    s.add_argument("--payload", default="{}", help="JSON object")
    s.add_argument("--key", help="idempotency key")
    s.add_argument("--max-attempts", type=int, default=3)

    ls = sub.add_parser("list", help="list jobs")
    ls.add_argument("--state", choices=[s.value for s in JobState])

    w = sub.add_parser("work", help="run queued jobs")
    w.add_argument("--worker", default="local-worker")
    w.add_argument("--max-jobs", type=int, default=100)
    w.add_argument("--failstop", help="unix:/path or tcp://127.0.0.1:PORT (default: effects disabled)")

    sub.add_parser("inventory", help="print a read-only machine inventory")
    v = sub.add_parser("verify", help="verify the receipt chain")
    v.add_argument("--expect-head", help="hash printed by an earlier verify; detects deleted receipts")
    r = sub.add_parser("receipts", help="show receipts")
    r.add_argument("--job", type=int)

    e = sub.add_parser("check", help="ask FailStop about an effect without running it")
    e.add_argument("tool")
    e.add_argument("target")
    e.add_argument("--failstop")

    a = p.parse_args(argv)
    try:
        if a.cmd == "inventory":
            _out(inv.collect())
            return 0
        if a.cmd == "check":
            req = EffectRequest(principal="cli", tool=a.tool, target=a.target, idempotency_key="cli-check")
            d = check(_failstop(a.failstop), req)
            _out(d.to_dict())
            return 0 if d.allowed else 3
        readonly = a.cmd in ("list", "receipts", "verify")
        db = Path(a.db) if a.db else _default_db(create=not readonly)
        board = JobBoard(db, readonly=readonly)  # read-only commands never create or change the database
        try:
            if a.cmd == "submit":
                payload = parse_json_object(a.payload)
                job = board.submit(Task(a.kind, payload, a.key, a.max_attempts))
                _out({"id": job.id, "state": job.state.value})
            elif a.cmd == "list":
                _out([{"id": j.id, "kind": j.kind, "state": j.state.value, "attempts": j.attempts}
                      for j in board.list(JobState(a.state) if a.state else None)])
            elif a.cmd == "work":
                n = Worker(board, a.worker, _failstop(a.failstop)).run(a.max_jobs)
                _out({"processed": n})
            elif a.cmd == "receipts":
                _out([r.__dict__ for r in board.receipts(a.job)])
            elif a.cmd == "verify":
                ok, msg, count, head = board.verify(a.expect_head)
                _out({"ok": ok, "message": msg, "count": count, "head": head})
                return 0 if ok else 4
        finally:
            board.close()
        return 0
    except (ContractError, ValueError, RecursionError, OSError, sqlite3.Error) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
