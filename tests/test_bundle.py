"""Bundle builder, manifest determinism, and signing tests."""

from __future__ import annotations

import json

import pytest

from oept.bundle import BUNDLE_SPEC_VERSION, BundleBuilder, build_bundle
from oept.errors import ValidationError
from oept.hashing import sha256_bytes
from oept.signing import generate_keypair, sign_manifest


def _members() -> dict[str, bytes]:
    return {
        "facts.json": b"[]",
        "provenance.json": b"[]",
        "evidence/a.txt": b"hello",
    }


def test_manifest_creation_sorted():
    builder = BundleBuilder(bundle_id="demo", created_at="2026-01-01T00:00:00Z")
    for path, data in _members().items():
        builder.add_file(path, data)
    manifest = builder.manifest_dict()
    assert manifest["bundle_spec_version"] == "oept-bundle/0.1"
    assert manifest["bundle_id"] == "demo"
    paths = [e["path"] for e in manifest["files"]]
    assert paths == sorted(paths)
    for entry in manifest["files"]:
        assert entry["sha256"] == sha256_bytes(_members()[entry["path"]])
        assert entry["size_bytes"] == len(_members()[entry["path"]])


def test_manifest_requires_facts_and_provenance():
    builder = BundleBuilder(bundle_id="x", created_at="2026-01-01T00:00:00Z")
    builder.add_file("evidence/a.txt", b"hi")
    with pytest.raises(ValidationError):
        builder.manifest_dict()


def test_duplicate_member_rejected():
    builder = BundleBuilder(bundle_id="x", created_at="2026-01-01T00:00:00Z")
    builder.add_file("facts.json", b"[]")
    with pytest.raises(ValidationError):
        builder.add_file("facts.json", b"[]")


def test_manifest_member_rejected():
    builder = BundleBuilder(bundle_id="x", created_at="2026-01-01T00:00:00Z")
    with pytest.raises(ValidationError):
        builder.add_file("manifest.json", b"{}")


def test_unsafe_member_paths_rejected():
    builder = BundleBuilder(bundle_id="x", created_at="2026-01-01T00:00:00Z")
    for bad in ("../evil.txt", "/abs.txt", "a\\b.txt", "", "a/../b.txt", "signatures/manifest.sig"):
        with pytest.raises(ValidationError):
            builder.add_file(bad, b"x")


def test_deterministic_manifest_bytes():
    def manifest() -> bytes:
        builder = BundleBuilder(bundle_id="det", created_at="2026-01-01T00:00:00Z")
        for path in ("provenance.json", "facts.json", "evidence/a.txt"):
            builder.add_file(path, _members()[path])
        return builder.manifest_bytes()

    assert manifest() == manifest()


def test_deterministic_zip_bytes_same_interpreter(tmp_path):
    first = build_bundle(_members(), bundle_id="det", created_at="2026-01-01T00:00:00Z")
    second = build_bundle(
        {k: _members()[k] for k in reversed(list(_members()))},
        bundle_id="det",
        created_at="2026-01-01T00:00:00Z",
    )
    assert first == second
    target = tmp_path / "bundle.zip"
    target.write_bytes(first)
    assert target.read_bytes() == first


def test_signed_bundle_carries_key_id_and_sig_member():
    import io
    import zipfile

    private_pem, _public_pem = generate_keypair()
    builder = BundleBuilder(bundle_id="sig", created_at="2026-01-01T00:00:00Z", key_id="test-key-1")
    for path, data in _members().items():
        builder.add_file(path, data)
    signature = sign_manifest(builder.manifest_bytes(), private_pem)
    blob = builder.build_zip_bytes(signature)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        names = set(archive.namelist())
    assert "signatures/manifest.sig" in names
    assert "manifest.json" in names
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(blob)).read("manifest.json"))
    assert manifest["key_id"] == "test-key-1"
    # The signature envelope is not part of the signed file table.
    assert "signatures/manifest.sig" not in [e["path"] for e in manifest["files"]]


def test_build_bundle_requires_key_id_for_signatures():
    _private_pem, _public_pem = generate_keypair()
    with pytest.raises(ValidationError):
        build_bundle(
            _members(),
            bundle_id="x",
            created_at="2026-01-01T00:00:00Z",
            signature=b"fake-signature",
        )


def test_spec_version_constant():
    assert BUNDLE_SPEC_VERSION == "oept-bundle/0.1"
