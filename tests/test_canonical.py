"""Canonical JSON and hashing tests."""

from __future__ import annotations

import pytest

from oept.canonical import CanonicalizationError, canonicalize_json
from oept.hashing import sha256_bytes, sha256_canonical_json, sha256_file


def test_insertion_order_independent():
    first = {"b": 1, "a": [1, 2, {"z": None, "y": True}]}
    second = {"a": [1, 2, {"y": True, "z": None}], "b": 1}
    assert canonicalize_json(first) == canonicalize_json(second)


def test_changed_value_changes_digest():
    from oept.hashing import sha256_canonical_json

    assert sha256_canonical_json({"a": 1}) != sha256_canonical_json({"a": 2})


def test_canonical_bytes_shape():
    assert canonicalize_json({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'
    assert canonicalize_json({}) == b"{}"
    assert canonicalize_json([1, True, None, "s"]) == b'[1,true,null,"s"]'


def test_float_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize_json({"a": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonicalize_json({"a": 1.5})
    with pytest.raises(CanonicalizationError):
        canonicalize_json([float("inf")])


def test_non_string_key_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize_json({1: "x"})


def test_foreign_objects_rejected():
    import datetime
    import decimal

    with pytest.raises(CanonicalizationError):
        canonicalize_json({"a": decimal.Decimal("1.0")})
    with pytest.raises(CanonicalizationError):
        canonicalize_json({"a": datetime.datetime.now()})
    with pytest.raises(CanonicalizationError):
        canonicalize_json({"a": b"bytes"})
    with pytest.raises(CanonicalizationError):
        canonicalize_json({"a": {1, 2}})


def test_tuple_serializes_as_list():
    assert canonicalize_json((1, 2)) == b"[1,2]"


def test_sha256_helpers():
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert len(sha256_canonical_json({"x": 1})) == 64


def test_sha256_file(tmp_path):
    target = tmp_path / "data.bin"
    target.write_bytes(b"a" * 10000)
    assert sha256_file(target) == sha256_bytes(b"a" * 10000)


def test_unicode_canonical():
    assert canonicalize_json({"name": "Müller-✓-€"}) == ('{"name":"Müller-✓-€"}'.encode())
    # determinism across key order with non-ASCII content
    assert canonicalize_json({"b": "✓", "a": "€"}) == canonicalize_json({"a": "€", "b": "✓"})


def test_large_integers_fail_explicitly():
    # The JCS backend routes integers through binary64: beyond 2**53
    # values round silently and magnitudes >= 10**21 render in scientific
    # notation (forbidden by RFC 8785). OEPT rejects them loudly instead.
    assert canonicalize_json({"n": 2**53 - 1}) == b'{"n":9007199254740991}'
    assert canonicalize_json({"n": -(2**53 - 1)}) == (b'{"n":-9007199254740991}')
    for bad in (2**53, -(2**53), 10**21, 2**200, {"nested": [10**30]}):
        with pytest.raises(CanonicalizationError):
            canonicalize_json(bad)


def test_accepted_integers_round_trip_exactly():
    import json
    import random

    random.seed(20260905)
    for _ in range(500):
        n = random.randint(-(2**53 - 1), 2**53 - 1)
        assert json.loads(canonicalize_json({"n": n})) == {"n": n}
    assert canonicalize_json({"name": "Müller-✓-€"}) == ('{"name":"Müller-✓-€"}'.encode())
    # determinism across key order with non-ASCII content
    assert canonicalize_json({"b": "✓", "a": "€"}) == canonicalize_json({"a": "€", "b": "✓"})
