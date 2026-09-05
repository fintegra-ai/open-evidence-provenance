"""SHA-256 helpers.

Digests are lowercase hexadecimal strings. These functions hash bytes;
callers canonicalize structured values via oept.canonical first.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .canonical import canonicalize_json

_CHUNK_SIZE = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of in-memory bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = _CHUNK_SIZE) -> str:
    """Hex SHA-256 of a file, streamed in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_canonical_json(value: Any) -> str:
    """Hex SHA-256 over RFC 8785 canonical bytes of a domain value."""
    return sha256_bytes(canonicalize_json(value))
