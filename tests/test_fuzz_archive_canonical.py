"""Seeded stdlib fuzz/property tests: canonical JSON and hostile archive members.

Deterministic by construction: every random choice draws from a local
``random.Random`` instance with a fixed seed. No network, no new
dependencies, no wall-clock or timing assertions.
"""

from __future__ import annotations

import io
import json
import random
import warnings
import zipfile
from pathlib import Path
from typing import Any

from oept.bundle import BundleBuilder
from oept.canonical import canonicalize_json
from oept.verify import verify_bundle_bytes

CREATED_AT = "2026-01-01T00:00:00Z"

_CANONICAL_SEED = 20261101
_ARCHIVE_SEED = 20261102
_CANONICAL_ITERATIONS = 200
_ARCHIVE_ITERATIONS = 150

# Keys and strings chosen to exercise non-ASCII, quote/backslash escaping,
# control characters, and empty strings in JCS output.
_UNICODE_POOL = [
    "α",
    "数据",
    "🌱",
    "café",
    'q"uote',
    "back\\slash",
    "line\nbreak",
    "tab\there",
    "nul\x00byte",
    "",
    "a",
    "ß",
    "Íñdé",
]

_SMALL_VALUES: list[Any] = [None, True, False, 0, 1, -1, 255, -(2**53) + 1, 2**53 - 1, 10**15]
_SMALL_VALUES += [10**9 + i for i in range(4)]


def _make_structure(rng: random.Random, depth: int) -> Any:
    """Random value inside the OEPT canonical domain (no floats, no huge ints)."""
    if depth <= 0:
        choice = rng.randrange(3)
        if choice == 0:
            return rng.choice(_SMALL_VALUES)
        if choice == 1:
            return rng.choice(_UNICODE_POOL)
        return rng.choice(_UNICODE_POOL) + str(rng.randrange(10**6))

    choice = rng.randrange(3)
    if choice == 0:
        return {
            rng.choice(_UNICODE_POOL) or f"k{rng.randrange(10**6)}": _make_structure(rng, depth - 1)
            for _ in range(rng.randrange(1, 5))
        }
    if choice == 1:
        return [_make_structure(rng, depth - 1) for _ in range(rng.randrange(0, 5))]
    return {
        rng.choice(_UNICODE_POOL) or f"k{rng.randrange(10**6)}": _make_structure(rng, depth - 1)
        for _ in range(rng.randrange(1, 5))
    }


def _shuffle_keys(value: Any, rng: random.Random) -> Any:
    """Rebuild containers with randomized insertion order (content unchanged)."""
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {key: _shuffle_keys(item, rng) for key, item in items}
    if isinstance(value, list):
        return [_shuffle_keys(item, rng) for item in value]
    return value


def test_canonical_json_deterministic_and_idempotent() -> None:
    rng = random.Random(_CANONICAL_SEED)
    for _ in range(_CANONICAL_ITERATIONS):
        structure = _make_structure(rng, rng.randrange(0, 4))

        first = canonicalize_json(structure)
        # Determinism: a copy with different key insertion order canonicalises
        # to identical bytes.
        reshuffled = _shuffle_keys(json.loads(first), rng)
        assert canonicalize_json(reshuffled) == first
        # Idempotency: canonicalising the canonical output is a fixed point.
        assert canonicalize_json(json.loads(first)) == first


def _base_bundle_bytes() -> bytes:
    builder = BundleBuilder(bundle_id="fuzz", created_at=CREATED_AT)
    builder.add_file("facts.json", b"[]")
    builder.add_file("provenance.json", b"[]")
    builder.add_file("evidence/a.txt", b"payload")
    return builder.build_zip_bytes()


def _append_member(blob: bytes, name: str, data: bytes, *, symlink: bool = False) -> bytes:
    """Append one raw member to a finished archive (hostile-member injection)."""
    buffer = io.BytesIO(blob)
    with warnings.catch_warnings():
        # zipfile warns on duplicate member names; the duplicate is the point.
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "a") as archive:
            if symlink:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = 0o120777 << 16
                archive.writestr(info, "evidence/a.txt")
            else:
                archive.writestr(name, data)
    return buffer.getvalue()


def _hostile_member(rng: random.Random) -> tuple[str, bytes, bool, str]:
    """Return (member name, member bytes, is_symlink, class label).

    NUL-byte member names are not covered here: CPython's zipfile truncates
    names at NUL when writing, so that class cannot be delivered through the
    archive-write path; OEPT's NUL guard defends raw-crafted archives instead.
    """
    word = f"evil{rng.randrange(10**6)}"
    kind = rng.randrange(7)
    if kind == 0:
        return f"../{word}", b"x", False, "traversal"
    if kind == 1:
        return f"a{rng.randrange(9)}/../../{word}", b"x", False, "traversal-deep"
    if kind == 2:
        return f"dir\\..\\{word}", b"x", False, "backslash"
    if kind == 3:
        return f"/{word}", b"x", False, "absolute"
    if kind == 4:
        return f"C:\\{word}", b"x", False, "windows-drive"
    if kind == 5:
        return f"a//{word}", b"x", False, "empty-segment"
    return f"evidence/link{rng.randrange(10**6)}.txt", b"evidence/a.txt", True, "symlink"


def test_hostile_archive_members_fail_closed(tmp_path: Path) -> None:
    rng = random.Random(_ARCHIVE_SEED)
    seen_kinds: set[str] = set()
    for _ in range(_ARCHIVE_ITERATIONS):
        name, data, is_symlink, kind = _hostile_member(rng)
        blob = _append_member(_base_bundle_bytes(), name, data, symlink=is_symlink)
        target = tmp_path / "hostile.zip"
        target.write_bytes(blob)
        result = verify_bundle_bytes(blob)
        # Fail closed: never VALID_*, always the archive-safety terminal status.
        assert result.status == "UNSAFE_ARCHIVE", f"{name!r} ({kind}) was not refused"
        assert result.ok is False
        assert result.notes
        seen_kinds.add(kind)
    # Every hostile class deliverable through the write path was exercised.
    assert seen_kinds == {
        "traversal",
        "traversal-deep",
        "backslash",
        "absolute",
        "windows-drive",
        "empty-segment",
        "symlink",
    }


def test_duplicate_members_fail_closed(tmp_path: Path) -> None:
    rng = random.Random(_ARCHIVE_SEED + 1)
    for _ in range(10):
        name = rng.choice(["facts.json", "provenance.json", "evidence/a.txt"])
        blob = _append_member(_base_bundle_bytes(), name, b"duplicate-content")
        result = verify_bundle_bytes(blob)
        assert result.status == "UNSAFE_ARCHIVE", f"duplicate {name!r} was not refused"
        assert result.ok is False
