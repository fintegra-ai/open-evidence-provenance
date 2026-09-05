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

Known JCS limitation (failed explicitly, never silently): the ``jcs``
library routes integers through binary64 floating point. Beyond 2**53,
values round (9007199254740993 renders as ...992; 2**63-1 renders as
...6000) and magnitudes >= 10**21 render in scientific notation, which
RFC 8785 forbids for integers. OEPT therefore rejects integers outside
±(2**53 - 1) outright — callers needing larger magnitudes must use
decimal strings, exactly like Decimal values.
"""

from __future__ import annotations

from typing import Any

import jcs

from .errors import OeptError

#: Largest integer magnitude serializable exactly. Every integer with
#: |n| <= 2**53 - 1 is exactly representable in binary64, and the JCS
#: backend renders this range in plain decimal notation. Anything larger
#: is rejected (silent rounding or scientific notation). Enforced below,
#: not assumed.
_MAX_EXACT_JCS_INT = 2**53 - 1


class CanonicalizationError(OeptError):
    """A value outside the canonical domain was supplied."""


def _check_domain(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > _MAX_EXACT_JCS_INT:
            raise CanonicalizationError(
                f"{path}: integer magnitude exceeds the exactly "
                "serializable JCS range (use a decimal string instead)"
            )
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
                raise CanonicalizationError(f"{path}: non-string dict key {key!r} is not canonical")
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
        raise CanonicalizationError(f"JCS serialization failed: {exc}") from exc
    if isinstance(result, str):
        return result.encode("utf-8")
    return bytes(result)
