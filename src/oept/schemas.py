"""Access to the versioned OEPT JSON Schemas.

Schemas live in the top-level ``schemas/`` directory so they are usable
independently of Python (any JSON Schema validator, any language).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from .errors import OeptError

SCHEMA_NAMES = (
    "evidence-object",
    "evidence-version",
    "provenance-pointer",
    "fact",
    "rule-trace",
    "bundle-manifest",
    "verification-result",
)

_SCHEMA_FILES = {
    "evidence-object": "evidence-object.schema.json",
    "evidence-version": "evidence-version.schema.json",
    "provenance-pointer": "provenance-pointer.schema.json",
    "fact": "fact.schema.json",
    "rule-trace": "rule-trace.schema.json",
    "bundle-manifest": "bundle-manifest.schema.json",
    "verification-result": "verification-result.schema.json",
}


def schemas_dir() -> Path:
    """Directory holding the schema files (repo layout or installed data)."""
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent.parent / "schemas",
        Path(__file__).resolve().parents[2] / "schemas",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise OeptError("OEPT schemas directory not found")


def list_schemas() -> list[str]:
    """Names of all published schemas."""
    return list(SCHEMA_NAMES)


@lru_cache(maxsize=None)
def load_schema(name: str) -> dict[str, Any]:
    """Load one schema by short name (e.g. ``bundle-manifest``)."""
    if name not in _SCHEMA_FILES:
        raise OeptError(
            f"unknown schema {name!r}; known: {', '.join(SCHEMA_NAMES)}")
    import json

    path = schemas_dir() / _SCHEMA_FILES[name]
    try:
        return dict(json.loads(path.read_bytes().decode("utf-8")))
    except OSError as exc:
        raise OeptError(f"cannot read schema {name}: {exc}") from exc
    except ValueError as exc:
        raise OeptError(f"schema {name} is not valid JSON: {exc}") from exc


def validate_against_schema(name: str, value: Any) -> list[str]:
    """Validate a value; returns a list of human-readable error strings."""
    import jsonschema

    schema = load_schema(name)
    validator = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(str(p) for p in e.path)}: {e.message}"
            for e in validator.iter_errors(value)]
