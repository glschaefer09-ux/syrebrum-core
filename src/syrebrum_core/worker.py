# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
"""Runs jobs from the board.

A read-only handler is called as fn(payload) -> dict. An effect handler is
called as fn(target, args) -> dict with exactly the target and args that
FailStop approved; effect job payloads may contain only "target" and "args". Before an effect handler runs, the worker
asks FailStop. Only ALLOW runs it. HOLD and DENY end the job as DENIED with the
decision recorded in the receipt, so you can see exactly why nothing happened.

Delivery is at-least-once: if a worker crashes after an effect but before
recording success, the job is retried with a new request and a new decision.
Effect handlers should be idempotent (use the target as the natural key).
"""
from __future__ import annotations

import copy
import time
from collections.abc import Callable
from dataclasses import dataclass

from . import inventory
from .contracts import ContractError, Verdict, check_id
from .failstop import EffectRequest, FailStopClient, NoFailStop, check
from .jobs import Job, JobBoard, LeaseLost

Handler = Callable[..., dict]
EFFECT_KEYS = {"target", "args"}


def _effect_input(payload: dict) -> tuple[str, dict, str | None]:
    """Effect payloads are exactly {"target": str, "args": {...}} (args optional)."""
    extra = set(payload) - EFFECT_KEYS
    if extra:
        return "", {}, f"effect payload has unexpected fields: {sorted(extra)}"
    target, args = payload.get("target"), payload.get("args", {})
    if not isinstance(target, str) or not target:
        return "", {}, "effect payload needs a non-empty string target"
    if not isinstance(args, dict):
        return "", {}, "effect args must be a JSON object"
    return target, args, None


@dataclass(frozen=True)
class _Reg:
    fn: Handler
    effect: bool
    tool: str


def _echo(payload: dict) -> dict:
    return {"echo": payload}


def _inventory(payload: dict) -> dict:
    flag = payload.get("include_hostname", False)
    if type(flag) is not bool:
        raise ContractError("include_hostname must be true or false")
    return inventory.collect(include_hostname=flag)


class Worker:
    def __init__(self, board: JobBoard, worker_id: str, failstop: FailStopClient | None = None,
                 lease_s: float = 60.0) -> None:
        self.board, self.worker_id = board, check_id("worker", worker_id)
        self.failstop = failstop if failstop is not None else NoFailStop()
        self.lease_s = lease_s
        self._handlers: dict[str, _Reg] = {}
        self.register("core.echo", _echo)
        self.register("core.inventory", _inventory)

    def register(self, kind: str, fn: Handler, *, effect: bool = False, tool: str | None = None) -> None:
        """Register a handler. Effect handlers need a FailStop tool name (defaults to the kind)."""
        check_id("kind", kind)
        if kind in self._handlers:
            raise ContractError(f"handler for {kind!r} already registered")
        self._handlers[kind] = _Reg(fn, effect, check_id("tool", tool or kind))

    def run_once(self) -> Job | None:
        job = self.board.claim(self.worker_id, kinds=sorted(self._handlers), lease_s=self.lease_s)
        if job is None:
            return None
        reg = self._handlers[job.kind]
        token = job.lease_token
        effect_ran = False
        try:
            if not reg.effect:
                result = reg.fn(copy.deepcopy(job.payload))
            else:
                # The handler receives exactly what FailStop approved, nothing more.
                target, args, problem = _effect_input(job.payload)
                if problem:
                    return self.board.deny(job.id, token, {"verdict": "deny", "reason": problem})
                try:
                    req = EffectRequest(principal=self.worker_id, tool=reg.tool, target=target, args=args,
                                        idempotency_key=f"job-{job.id}-attempt-{job.attempts}")
                except ContractError as exc:  # e.g. target too long: permanently invalid, never retried
                    return self.board.deny(job.id, token, {"verdict": "deny", "reason": str(exc)[:500]})
                # Private copies of exactly what is hashed, taken before the policy call.
                approved_target, approved_args, approved_until = req.target, req.approved_args(), req.expires_at
                decision = check(self.failstop, req)
                if decision.verdict is not Verdict.ALLOW:
                    return self.board.deny(job.id, token, decision.to_dict())
                # Fence: record the approval under the lease. Raises LeaseLost if the job
                # was cancelled or taken over while we waited for FailStop.
                self.board.authorize(job.id, token, decision.to_dict(), self.lease_s)
                if time.time() > approved_until:
                    return self.board.deny(job.id, token, {"verdict": "deny", "reason": "approval expired"})
                result = reg.fn(approved_target, approved_args)
                # The effect has run. From here on, any failure to record it fails the
                # job for good rather than retrying it and running the effect again.
                effect_ran = True
                if not isinstance(result, dict):
                    raise ContractError("handler must return a dict")
                return self.board.complete(job.id, token, result, decision.to_dict())
            if not isinstance(result, dict):
                raise ContractError("handler must return a dict")
            return self.board.complete(job.id, token, result)
        except LeaseLost:
            return self.board.get(job.id)
        except Exception as exc:  # noqa: BLE001 - any handler error is a job failure
            note = "effect ran but its result was not recorded: " if effect_ran else ""
            try:
                return self.board.fail(job.id, token, f"{note}{type(exc).__name__}: {exc}", final=effect_ran)
            except LeaseLost:
                return self.board.get(job.id)

    def run(self, max_jobs: int = 100) -> int:
        """Run until the queue is empty or max_jobs have been processed."""
        n = 0
        while n < max_jobs and self.run_once() is not None:
            n += 1
        return n
