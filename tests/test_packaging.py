"""Packaging integrity: installed copies stay in sync with canonical trees."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _tree_files(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts:
            continue
        if path.is_file() and path.suffix != ".py" and path.name != "__init__.py":
            result[path.relative_to(root).as_posix()] = path.read_bytes()
    return result


def test_schemas_sync_with_package_data():
    canonical = _tree_files(ROOT / "schemas")
    packaged = dict(_tree_files(ROOT / "src" / "oept" / "data" / "schemas"))
    assert set(canonical) == set(packaged), (
        f"schema drift: {set(canonical) ^ set(packaged)}; "
        "re-run conformance/make_fixtures.py or copy by hand"
    )
    for key in canonical:
        assert canonical[key] == packaged[key], f"schema content drift: {key}"


def test_conformance_sync_with_package_data():
    canonical = _tree_files(ROOT / "conformance" / "fixtures")
    packaged = _tree_files(ROOT / "src" / "oept" / "data" / "conformance")
    assert set(canonical) == set(packaged), (
        f"corpus drift: {set(canonical) ^ set(packaged)}; re-run conformance/make_fixtures.py"
    )
    for key in canonical:
        assert canonical[key] == packaged[key], f"corpus content drift: {key}"
