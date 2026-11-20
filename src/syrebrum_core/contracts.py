# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
"""Versioned data contracts shared by every Syrebrum component.

All values are plain JSON types so that any language can implement them.
Validation is strict: unknown fields and wrong types are rejected.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = 1
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
MAX_PAYLOAD_BYTES = 64 * 1024


class ContractError(ValueError):
    """Raised when data does not match a contract."""


MAX_DEPTH = 32


def check_plain_json(value: Any, depth: int = 0) -> None:
    """Only JSON types: object (string keys), array, string, finite number, true, false, null."""
    if depth > MAX_DEPTH:
        raise ContractError(f"JSON is nested deeper than {MAX_DEPTH} levels")
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise ContractError("string is not valid Unicode (lone surrogate)") from None
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ContractError("NaN and Infinity are not allowed")
        return
    if isinstance(value, list):
        for v in value:
            check_plain_json(v, depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ContractError(f"object keys must be strings (got {type(k).__name__})")
            check_plain_json(k, depth + 1)
            check_plain_json(v, depth + 1)
        return
    raise ContractError(f"{type(value).__name__} is not a JSON type")


def is_unicode_text(value: Any) -> bool:
    """True for a str that is valid Unicode (encodes as UTF-8; no lone surrogates)."""
    if type(value) is not str:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def json_depth_ok(text: str, max_depth: int = MAX_DEPTH) -> bool:
    """Check JSON nesting depth without parsing, so a hostile reply can't exhaust
    the parser's stack (deep nesting can crash some Python builds outright).

    Takes text only, and the caller must parse that same text: json.loads(bytes)
    also accepts UTF-16 and UTF-32, which would read differently from this scan.
    """
    if type(text) is not str:
        raise TypeError("json_depth_ok needs the decoded str that will be parsed")
    depth, in_str, esc = 0, False, False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                return False
        elif ch in "]}":
            depth -= 1
    return True


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate field {k!r}")
        out[k] = v
    return out


def _no_constants(name):
    raise ValueError(f"{name} is not allowed")


def parse_json_object(text: str, max_depth: int = MAX_DEPTH) -> dict:
    """Strictly parse a JSON object from untrusted text: valid Unicode, bounded
    nesting, no duplicate keys, no NaN or Infinity."""
    if not is_unicode_text(text):
        raise ContractError("JSON must be valid Unicode text")
    if not json_depth_ok(text, max_depth):
        raise ContractError("JSON is nested too deeply")
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (ValueError, RecursionError) as exc:
        raise ContractError(f"invalid JSON: {exc}") from None
    if not isinstance(value, dict):
        raise ContractError("JSON must be an object")
    return value


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no spaces, UTF-8, no NaN. Rejects non-JSON values."""
    check_plain_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def check_id(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ContractError(f"{name} must be 1-128 chars of letters, digits, . _ : - (got {value!r})")
    return value


def check_payload(value: Any) -> dict:
    if not isinstance(value, dict):
        raise ContractError("payload must be a JSON object")
    try:
        size = len(canonical_json(value).encode("utf-8"))
    except ContractError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise ContractError(f"payload is not plain JSON: {exc}") from None
    if size > MAX_PAYLOAD_BYTES:
        raise ContractError(f"payload is {size} bytes; limit is {MAX_PAYLOAD_BYTES}")
    return value


class Verdict(str, Enum):
    ALLOW = "allow"
    HOLD = "hold"   # waiting for an owner's approval; treat as "not now"
    DENY = "deny"


class JobState(str, Enum):
    QUEUED = "queued"
    LEASED = "leased"
    SUCCEEDED = "succeeded"
    FAILED = "failed"        # retries exhausted
    DENIED = "denied"        # an effect was refused by policy
    CANCELLED = "cancelled"


TERMINAL_STATES = {JobState.SUCCEEDED, JobState.FAILED, JobState.DENIED, JobState.CANCELLED}


@dataclass(frozen=True)
class Task:
    kind: str
    payload: dict = field(default_factory=dict)
    idempotency_key: str | None = None
    max_attempts: int = 3

    def __post_init__(self) -> None:
        check_id("kind", self.kind)
        check_payload(self.payload)
        if self.idempotency_key is not None:
            check_id("idempotency_key", self.idempotency_key)
        if not isinstance(self.max_attempts, int) or isinstance(self.max_attempts, bool) or not 1 <= self.max_attempts <= 20:
            raise ContractError("max_attempts must be an integer from 1 to 20")


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    request_hash: str
    policy_version: str = "none"
    approval_id: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW
