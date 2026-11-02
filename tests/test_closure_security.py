"""Regression cases for malformed manifests and unreadable ZIP members."""

from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from oept.bundle import BundleBuilder
from oept.errors import ValidationError
from oept.verify import VerifierOptions, verify_bundle_bytes, verify_bundle_dir


def archive(manifest: dict, *, evidence: bool = True) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("facts.json", b"[]")
        zf.writestr("provenance.json", b"[]")
        if evidence:
            zf.writestr("evidence/a.txt", b"hello")
    return buffer.getvalue()


def manifest() -> dict:
    b = BundleBuilder("regression", created_at="2026-11-02T00:00:00Z")
    b.add_file("facts.json", b"[]").add_file("provenance.json", b"[]")
    b.add_evidence("a.txt", b"hello")
    return b.manifest_dict()


@pytest.mark.parametrize(
    "field,value",
    [
        ("bundle_spec_version", []),
        ("bundle_spec_version", {}),
        ("bundle_id", None),
        ("bundle_id", ""),
        ("created_at", 1),
        ("files", [{"path": 1, "sha256": 4, "size_bytes": -1}]),
        ("files", [{"path": "a", "sha256": "0" * 64, "size_bytes": True}]),
        ("files", [{"path": "a", "sha256": "0" * 64, "size_bytes": 1, "extra": 2}]),
    ],
)
def test_schema_invalid_manifests_fail_closed(field, value, tmp_path: Path):
    m = manifest() | {field: value}
    blob = archive(m)
    assert verify_bundle_bytes(blob).status == "MALFORMED_BUNDLE"
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        zf.extractall(tmp_path)
    assert verify_bundle_dir(tmp_path).status == "MALFORMED_BUNDLE"


def test_missing_required_members_even_when_manifest_omits_them():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest() | {"files": []}))
    result = verify_bundle_bytes(buffer.getvalue())
    assert result.status == "MISSING_FILE"
    assert set(result.missing) == {"facts.json", "provenance.json", "evidence/"}


def test_byte_api_enforces_archive_size():
    assert (
        verify_bundle_bytes(
            archive(manifest()), options=VerifierOptions(max_archive_bytes=1)
        ).status
        == "UNSAFE_ARCHIVE"
    )


def test_corrupt_member_crc_returns_verdict():
    blob = bytearray(archive(manifest()))
    offset = blob.index(b"hello")
    blob[offset] ^= 1
    assert verify_bundle_bytes(bytes(blob)).status == "MALFORMED_BUNDLE"


def test_encrypted_member_refused_before_read():
    blob = bytearray(archive(manifest()))
    offset = blob.index(b"PK\x01\x02")
    flags = struct.unpack_from("<H", blob, offset + 8)[0]
    struct.pack_into("<H", blob, offset + 8, flags | 1)
    assert verify_bundle_bytes(bytes(blob)).status == "UNSAFE_ARCHIVE"


@pytest.mark.parametrize("path", ["C:", "C:file.txt", "C:/file.txt"])
def test_builder_rejects_drive_paths(path):
    with pytest.raises(ValidationError):
        BundleBuilder("bad").add_file(path, b"x")
