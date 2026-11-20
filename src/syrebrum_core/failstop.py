# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
"""FailStop protocol v1: ask a policy engine before any effect.

An *effect* is anything that changes the world: writing files outside a job's
scratch space, running commands, sending messages, calling paid APIs.

Syrebrum Core does not decide whether an effect is allowed. It asks a FailStop
engine (a separate product) and obeys the answer. The rule is **fail closed**:
no engine, no answer, a late answer, a malformed answer, or an answer about a
different request all mean DENY.

Wire format: one JSON object per line, UTF-8, over a Unix socket or a loopback
TCP socket.

  request:  {"v": "1", "type": "decide", "request": {...EffectRequest...}, "request_hash": "<sha256>"}
  response: {"v": "1", "verdict": "allow|hold|deny", "reason": "...", "request_hash": "<sha256>",
             "policy_version": "...", "approval_id": "..." | null}
"""
from __future__ import annotations

import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field
from typing import Protocol

from . import PROTOCOL_VERSION
from .contracts import (
    ContractError,
    Decision,
    Verdict,
    _no_constants,
    _no_duplicates,
    canonical_json,
    check_id,
    check_payload,
    is_unicode_text,
    json_depth_ok,
    sha256_hex,
)

MAX_RESPONSE_BYTES = 16 * 1024
DEFAULT_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class EffectRequest:
    """Everything the policy engine needs, bound together by one hash.

    The request is frozen at construction: args are snapshotted as canonical
    JSON and the hash is computed once. Mutating the dict you passed in, or
    the one returned by .args, changes nothing that is checked or dispatched.
    """
    principal: str          # who is asking (user or worker id)
    tool: str               # what kind of effect, e.g. "fs.write", "shell.run"
    target: str             # what it acts on, e.g. a path or host name
    args: dict = field(default_factory=dict)
    idempotency_key: str = ""
    tenant: str = "local"
    expires_at: float = 0.0  # unix seconds; 0 means now + 60 s

    def __post_init__(self) -> None:
        check_id("principal", self.principal)
        check_id("tool", self.tool)
        check_id("tenant", self.tenant)
        check_id("idempotency_key", self.idempotency_key)
        if not isinstance(self.target, str) or not 0 < len(self.target) <= 1024:
            raise ContractError("target must be a string of 1-1024 characters")
        check_payload(self.args)
        exp = self.expires_at
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or exp != exp or not 0 <= exp < 1e11:
            raise ContractError("expires_at must be a finite unix time in seconds")
        if exp == 0:
            exp = time.time() + 60
        object.__setattr__(self, "expires_at", round(float(exp), 3))
        snapshot = canonical_json(self.args)
        object.__setattr__(self, "args", json.loads(snapshot))
        object.__setattr__(self, "_args_json", snapshot)
        object.__setattr__(self, "_hash", sha256_hex({"v": PROTOCOL_VERSION, **self.to_dict()}))

    def to_dict(self) -> dict:
        return {"principal": self.principal, "tool": self.tool, "target": self.target,
                "args": json.loads(self._args_json), "idempotency_key": self.idempotency_key,
                "tenant": self.tenant, "expires_at": self.expires_at}

    def approved_args(self) -> dict:
        """A fresh copy of exactly the args that were hashed."""
        return json.loads(self._args_json)

    @property
    def request_hash(self) -> str:
        return self._hash

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at


class FailStopClient(Protocol):
    def decide(self, request: EffectRequest) -> Decision: ...


def deny(request: EffectRequest, reason: str) -> Decision:
    return Decision(Verdict.DENY, reason, request.request_hash)


class NoFailStop:
    """Used when no FailStop engine is configured. Every effect is denied."""

    def decide(self, request: EffectRequest) -> Decision:
        return deny(request, "no FailStop engine is configured; effects are disabled")


_REPLY_FIELDS = {"v", "verdict", "reason", "request_hash", "policy_version", "approval_id"}


def parse_decision(raw: bytes, request: EffectRequest) -> Decision:
    """Turn an engine's reply into a Decision. Anything unexpected is DENY."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_RESPONSE_BYTES:
        return deny(request, "FailStop reply too large or not bytes")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        return deny(request, "FailStop reply is not UTF-8")
    if not json_depth_ok(text, 4):
        return deny(request, "FailStop reply is nested too deeply")
    try:
        msg = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (ValueError, RecursionError):
        return deny(request, "FailStop reply is not valid JSON")
    if not isinstance(msg, dict) or set(msg) != _REPLY_FIELDS:
        return deny(request, "FailStop reply must have exactly the v1 fields")
    if msg["v"] != PROTOCOL_VERSION:
        return deny(request, "FailStop reply has the wrong protocol version")
    if msg["request_hash"] != request.request_hash:
        return deny(request, "FailStop reply is about a different request")
    if type(msg["verdict"]) is not str or msg["verdict"] not in ("allow", "hold", "deny"):
        return deny(request, "FailStop reply has an unknown verdict")
    return _validated(request, Verdict(msg["verdict"]), msg["reason"], msg["policy_version"], msg["approval_id"])


def _validated(request: EffectRequest, verdict, reason, policy_version, approval_id) -> Decision:
    """One set of field rules for wire replies and in-process adapters.
    Returns a fresh Decision built only from checked values."""
    if (type(verdict) is not Verdict or not is_unicode_text(reason)
            or not is_unicode_text(policy_version) or not policy_version
            or not (approval_id is None or is_unicode_text(approval_id))):
        return deny(request, "FailStop reply has malformed fields")
    if verdict is Verdict.ALLOW and request.expired:
        return deny(request, "request expired before it was allowed")
    return Decision(verdict, reason[:500], request.request_hash, policy_version[:64],
                    approval_id[:128] if approval_id else None)


class SocketFailStop:
    """Talks to a FailStop engine on this machine.

    address: "unix:/path/to/socket" or "tcp://127.0.0.1:PORT" (loopback only).
    """

    def __init__(self, address: str, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or not 0 < timeout_s <= 60:
            raise ContractError("timeout_s must be a number from 0 to 60 seconds")
        self.timeout_s = float(timeout_s)
        if not isinstance(address, str) or any(ord(c) < 33 or ord(c) == 127 for c in address):
            raise ContractError("FailStop address must be a string without spaces or control characters")
        if address.startswith("unix:"):
            self._family, self._addr = getattr(socket, "AF_UNIX", None), address[5:]
            if not self._addr:
                raise ContractError("FailStop unix: address needs a socket path")
            if self._family is None:
                raise ContractError("Unix sockets are not available on this platform; use tcp://127.0.0.1:PORT")
        elif address.startswith("tcp://"):
            host, _, port = address[6:].rpartition(":")
            host = host.strip("[]")
            try:
                if "%" in host:  # IPv6 zone IDs aren't needed for loopback
                    raise ValueError
                if not ipaddress.ip_address(host).is_loopback:
                    raise ValueError
                port_n = int(port)
                if not 0 < port_n < 65536:
                    raise ValueError
            except ValueError:
                raise ContractError("FailStop TCP address must be a loopback IP and port") from None
            self._family = socket.AF_INET6 if ":" in host else socket.AF_INET
            self._addr = (host, port_n)
        else:
            raise ContractError("FailStop address must start with unix: or tcp://")

    def decide(self, request: EffectRequest) -> Decision:
        line = json.dumps({"v": PROTOCOL_VERSION, "type": "decide", "request": request.to_dict(),
                           "request_hash": request.request_hash}).encode("utf-8") + b"\n"
        deadline = time.monotonic() + self.timeout_s

        def remaining() -> float:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError
            return left

        buf = b""
        try:
            with socket.socket(self._family, socket.SOCK_STREAM) as s:
                s.settimeout(remaining())
                s.connect(self._addr)
                s.settimeout(remaining())
                s.sendall(line)
                while b"\n" not in buf:
                    s.settimeout(remaining())
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > MAX_RESPONSE_BYTES:
                        return deny(request, "FailStop reply too large")
                remaining()  # an answer that arrives after the deadline doesn't count
        except TimeoutError:
            return deny(request, "FailStop did not answer in time")
        except OSError as exc:
            return deny(request, f"FailStop unreachable ({type(exc).__name__})")
        if b"\n" not in buf:
            return deny(request, "FailStop closed the connection without an answer")
        return parse_decision(buf.split(b"\n", 1)[0], request)


def check(client: FailStopClient, request: EffectRequest) -> Decision:
    """Ask the engine; any exception, wrong type or late/expired answer becomes DENY.

    Python adapters run in-process and synchronously: they are trusted code
    for timing (use SocketFailStop for an engine you don't control), but their
    answers are validated exactly like a wire reply.
    """
    if not isinstance(request, EffectRequest):
        raise ContractError("check() needs an EffectRequest")
    want = request.request_hash  # captured before the adapter runs
    # The adapter gets its own copy, so it can't change the request the caller
    # will dispatch (even by writing to the frozen object's __dict__).
    view = EffectRequest(**request.to_dict())
    if view.request_hash != want:
        return deny(request, "request changed before it was checked")
    try:
        decision = client.decide(view)
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        return deny(request, f"FailStop client error ({type(exc).__name__})")
    if (type(decision) is not Decision or type(decision.request_hash) is not str
            or decision.request_hash != want):
        return deny(request, "FailStop client returned an invalid decision")
    return _validated(request, decision.verdict, decision.reason, decision.policy_version, decision.approval_id)
