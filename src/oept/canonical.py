"""Deterministic canonical JSON (RFC 8785 / JCS).

OEPT does not implement its own canonicalizer. Canonical bytes are produced
by the maintained ``jcs`` package (RFC 8785 JSON Canonicalization Scheme).
If ``jcs`` cannot serialize a value, OEPT fails explicitly instead of
falling back to an incompatible rendering.

Supported value domain (the only domain OEPT schemas admit):
  None, bool, int, str, list, tuple (as list), dict with str keys,
  and finite floats.

Float rule (round 3, P0 — design decision, RFC 8785 §3.2.2.3): finite
floats are ACCEPTED and serialize with ECMAScript ``Number::toString``
semantics (``1.5`` → ``1.5``, ``1e21`` → ``1e+21``, ``-0.0`` → ``0``),
exactly as the OEVP reference (``oev.canonical``) and the independent
Node.js verifier already do. The previous rule rejected every float;
that made OEPT the outlier against both peers and against the RFC it
claims, and forced callers to string-encode naturally numeric evidence.
Non-finite floats (NaN, ±Infinity) are still rejected: RFC 8785 §3.2.2.3
requires a compliant implementation to terminate with an error on them.
Integer-valued floats such as ``1.0`` serialize as ``1`` (ECMAScript
``Number::toString``); callers that need to distinguish ``1`` from
``1.0`` must use a decimal string. Decimal values are still serialized
as strings by callers BEFORE calling into this module; datetimes as UTC
ISO-8601 strings.

Lone surrogates (RFC 8785 §3.2.2.2): a string or object key containing
an unpaired surrogate (e.g. U+D800 with no following U+DC00–U+DFFF)
MUST cause termination with an error — such data has no UTF-8 encoding
and different implementations would otherwise repair it differently
(U+FFFD substitution vs ``\\uXXXX`` escaping), breaking signatures.
OEPT rejects them explicitly with a stable error instead of leaking a
codec error. The same rule is enforced by OEVP (``oev.canonical``) and
by the independent Node.js verifier (``src/jcs.js`` / ``src/safeJson.js``).

Known JCS limitation (failed explicitly, never silently): the ``jcs``
library routes integers through binary64 floating point. Beyond 2**53,
values round (9007199254740993 renders as ...992; 2**63-1 renders as
...6000) and magnitudes >= 10**21 render in scientific notation, which
RFC 8785 forbids for integers. OEPT therefore rejects integers outside
±(2**53 - 1) outright — callers needing larger magnitudes must use
decimal strings, exactly like Decimal values.
"""

from __future__ import annotations

import math
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


def _check_no_lone_surrogates(value: str, path: str) -> None:
    """Reject unpaired surrogates (RFC 8785 §3.2.2.2) with a stable error."""
    i = 0
    while i < len(value):
        cp = ord(value[i])
        if 0xD800 <= cp <= 0xDBFF:
            nxt = ord(value[i + 1]) if i + 1 < len(value) else -1
            if not 0xDC00 <= nxt <= 0xDFFF:
                raise CanonicalizationError(
                    f"{path}: lone surrogate U+{cp:04X} is not in the canonical domain "
                    "(RFC 8785 §3.2.2.2: unpaired surrogates must terminate with an error)"
                )
            i += 2
            continue
        if 0xDC00 <= cp <= 0xDFFF:
            raise CanonicalizationError(
                f"{path}: lone surrogate U+{cp:04X} is not in the canonical domain "
                "(RFC 8785 §3.2.2.2: unpaired surrogates must terminate with an error)"
            )
        i += 1


def _check_domain(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _check_no_lone_surrogates(value, path)
        return
    if isinstance(value, int):
        if abs(value) > _MAX_EXACT_JCS_INT:
            raise CanonicalizationError(
                f"{path}: integer magnitude exceeds the exactly "
                "serializable JCS range (use a decimal string instead)"
            )
        return
    if isinstance(value, float):
        # RFC 8785 §3.2.2.3: finite floats serialize per ECMAScript
        # Number::toString; NaN/Infinity must terminate with an error.
        if math.isnan(value) or math.isinf(value):
            raise CanonicalizationError(
                f"{path}: non-finite float {value!r} is not in the canonical domain "
                "(RFC 8785 §3.2.2.3)"
            )
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check_domain(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: non-string dict key {key!r} is not canonical")
            _check_no_lone_surrogates(key, f"{path} (key)")
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
