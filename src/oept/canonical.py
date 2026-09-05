"""Deterministic canonical JSON (RFC 8785 / JCS).

OEPT does not implement its own canonicalizer. Canonical bytes are produced
by the maintained ``jcs`` package (RFC 8785 JSON Canonicalization Scheme).
If ``jcs`` cannot serialize a value, OEPT fails explicitly instead of
falling back to an incompatible rendering.

Supported value domain (the only domain OEPT schemas admit):
  None, bool, int, str, list, tuple (as list), dict with str keys.

Anything else — float (including NaN/Infinity), bytes, Decimal, datetime,
set, custom objects — raises CanonicalizationError. Callers serialize
Decimals as strings and datetimes as UTC ISO-8601 strings BEFORE calling
into this module; that rule is enforced, not assumed.
"""
from __future__ import annotations

from typing import Any

import jcs

from .errors import OeptError


class CanonicalizationError(OeptError):
    """A value outside the canonical domain was supplied."""


def _check_domain(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise CanonicalizationError(
            f"{path}: float is not in the canonical domain "
            "(serialize Decimals as strings, reject NaN/Infinity)"
        )
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check_domain(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"{path}: non-string dict key {key!r} is not canonical"
                )
        for key, item in value.items():
            _check_domain(item, f"{path}.{key}")
        return
    raise CanonicalizationError(
        f"{path}: type {type(value).__name__} is not in the canonical domain"
    )


def canonicalize_json(value: Any) -> bytes:
    """Return RFC 8785 canonical bytes (UTF-8) for a domain value."""
    _check_domain(value)
    try:
        result = jcs.canonicalize(value)
    except Exception as exc:
        raise CanonicalizationError(
            f"JCS serialization failed: {exc}"
        ) from exc
    if isinstance(result, str):
        return result.encode("utf-8")
    return bytes(result)
