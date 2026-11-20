# SPDX-FileCopyrightText: 2026 CCD Enterprise & Development LLC
# SPDX-License-Identifier: Apache-2.0
import pytest

from syrebrum_core.contracts import (
    ContractError,
    Task,
    canonical_json,
    check_id,
    check_payload,
    sha256_hex,
)


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'
    assert sha256_hex({"a": 1, "b": 2}) == sha256_hex({"b": 2, "a": 1})


@pytest.mark.parametrize("bad", ["", " x", "a b", "../etc", "x" * 129, None, 5, "-lead", "abc\n", "abc\r\n"])
def test_bad_ids_rejected(bad):
    with pytest.raises(ContractError):
        check_id("id", bad)


def test_payload_limits():
    with pytest.raises(ContractError):
        check_payload([])
    with pytest.raises(ContractError):
        check_payload({"x": float("nan")})
    with pytest.raises(ContractError):
        check_payload({"x": object()})
    with pytest.raises(ContractError):
        check_payload({"x": "a" * (65 * 1024)})


@pytest.mark.parametrize("n", [0, 21, True, 1.5])
def test_task_max_attempts(n):
    with pytest.raises(ContractError):
        Task("core.echo", {}, None, n)


def test_non_string_keys_rejected():
    with pytest.raises(ContractError):
        canonical_json({1: "a"})
    with pytest.raises(ContractError):
        check_payload({"a": {2: "b"}})


def test_deep_nesting_rejected():
    v = {}
    cur = v
    for _ in range(40):
        cur["a"] = {}
        cur = cur["a"]
    with pytest.raises(ContractError):
        check_payload(v)


def test_lone_surrogate_rejected():
    with pytest.raises(ContractError):
        canonical_json({"a": "\ud800"})


# Test vectors for other implementations (also listed in docs/SPEC.md).
VECTORS = [
    ({}, "{}", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
    ({"b": 1, "a": [True, None, "x"]}, '{"a":[true,null,"x"],"b":1}', None),
    ({"t": "é"}, '{"t":"é"}', None),
    ({"f": 1.5, "i": 10}, '{"f":1.5,"i":10}', None),
]


@pytest.mark.parametrize("value,text,digest", VECTORS)
def test_canonical_vectors(value, text, digest):
    assert canonical_json(value) == text
    if digest:
        assert sha256_hex(value) == digest


def test_json_depth_scanner():
    from syrebrum_core.contracts import json_depth_ok
    assert json_depth_ok('{"a": [1, {"b": 2}]}', 3)
    assert not json_depth_ok('{"a": [1, {"b": [2]}]}', 3)
    assert json_depth_ok('{"a": "[[[[[[\\"[[[[["}', 1)  # brackets and escaped quotes inside strings don't count
    assert not json_depth_ok("[" * 100, 32)
