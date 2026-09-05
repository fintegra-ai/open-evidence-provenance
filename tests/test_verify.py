"""Verifier behavior tests: statuses, trust model, hostile archives."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from oept.bundle import (
    FIXED_EXTERNAL_ATTR,
    FIXED_ZIP_DATE_TIME,
    BundleBuilder,
)
from oept.signing import TrustedKey, generate_keypair, sign_manifest
from oept.verify import (
    VerifierOptions,
    verify_bundle,
    verify_bundle_bytes,
)

CREATED_AT = "2026-01-01T00:00:00Z"


def _base(unsigned: bool = True, bundle_id: str = "t", key_id: str = "") -> BundleBuilder:
    builder = BundleBuilder(bundle_id=bundle_id, created_at=CREATED_AT, key_id=key_id or None)
    builder.add_file("facts.json", b"[]")
    builder.add_file("provenance.json", b"[]")
    builder.add_file("evidence/a.txt", b"hello")
    return builder


def _zip_bytes(builder: BundleBuilder, signature: bytes | None = None) -> bytes:
    return builder.build_zip_bytes(signature)


def _keypair() -> tuple[bytes, bytes, list[TrustedKey]]:
    private_pem, public_pem = generate_keypair()
    keys = [TrustedKey(key_id="k1", public_key_pem=public_pem)]
    return private_pem, public_pem, keys


def _write(tmp_path, data: bytes, name: str = "b.zip"):
    target = tmp_path / name
    target.write_bytes(data)
    return target


def test_valid_unsigned(tmp_path):
    result = verify_bundle(_write(tmp_path, _zip_bytes(_base())))
    assert result.status == "VALID_UNSIGNED"
    assert result.ok is True


def test_valid_signed(tmp_path):
    private_pem, _public_pem, keys = _keypair()
    builder = _base(key_id="k1")
    signature = sign_manifest(builder.manifest_bytes(), private_pem)
    result = verify_bundle(_write(tmp_path, _zip_bytes(builder, signature)), keys)
    assert result.status == "VALID_SIGNED"
    assert result.signature_checked is True
    assert result.trusted_key_id == "k1"
    assert result.ok is True


def test_unknown_signing_key(tmp_path):
    private_pem, _public_pem, _keys = _keypair()
    builder = _base(key_id="k1")
    signature = sign_manifest(builder.manifest_bytes(), private_pem)
    result = verify_bundle(_write(tmp_path, _zip_bytes(builder, signature)), [])
    assert result.status == "SIGNATURE_KEY_UNKNOWN"
    assert result.ok is False


def test_wrong_trusted_key(tmp_path):
    private_pem, _public_pem, _keys = _keypair()
    _other_private, other_public, _other = _keypair()
    builder = _base(key_id="k1")
    signature = sign_manifest(builder.manifest_bytes(), private_pem)
    wrong = [TrustedKey(key_id="other", public_key_pem=other_public)]
    result = verify_bundle(_write(tmp_path, _zip_bytes(builder, signature)), wrong)
    assert result.status == "SIGNATURE_INVALID"
    assert result.ok is False


def test_embedded_key_not_trusted(tmp_path):
    # A bundle that ships its own key-info is still untrusted without
    # caller-supplied trust roots: key-info.json is advisory metadata.
    private_pem, public_pem, _keys = _keypair()
    builder = _base(key_id="k1")
    builder.add_file(
        "signatures/key-info.json",
        json.dumps({"key_id": "k1", "public_key_pem": public_pem.decode()}).encode(),
    )
    signature = sign_manifest(builder.manifest_bytes(), private_pem)
    result = verify_bundle(_write(tmp_path, _zip_bytes(builder, signature)), [])
    assert result.status == "SIGNATURE_KEY_UNKNOWN"
    # ...while the same bundle verifies against the explicit trust root.
    keys = [TrustedKey(key_id="k1", public_key_pem=public_pem)]
    again = verify_bundle(_write(tmp_path, _zip_bytes(builder, signature), name="b2.zip"), keys)
    assert again.status == "VALID_SIGNED"


def test_tampered_evidence(tmp_path):
    blob = bytearray(_zip_bytes(_base()))
    blob = _replace_member(bytes(blob), "evidence/a.txt", b"tampered")
    result = verify_bundle(_write(tmp_path, bytes(blob)))
    assert result.status == "HASH_MISMATCH"
    assert result.mismatches and result.mismatches[0]["path"] == "evidence/a.txt"


def test_tampered_manifest(tmp_path):
    blob = _replace_member(
        _zip_bytes(_base()), "manifest.json", b'{"bundle_spec_version": "oept-bundle/0.1"}'
    )
    result = verify_bundle(_write(tmp_path, blob))
    # Required fields are gone -> malformed manifest.
    assert result.status == "MALFORMED_BUNDLE"


def test_missing_file(tmp_path):
    blob = _drop_member(_zip_bytes(_base()), "evidence/a.txt")
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "MISSING_FILE"
    assert "evidence/a.txt" in result.missing


def test_unexpected_file(tmp_path):
    blob = _append_member(_zip_bytes(_base()), "evidence/extra.txt", b"x")
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "UNEXPECTED_FILE"
    assert "evidence/extra.txt" in result.unexpected


def test_unsafe_path_traversal(tmp_path):
    blob = _append_member(_zip_bytes(_base()), "../evil.txt", b"x")
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "UNSAFE_ARCHIVE"


def test_unsafe_absolute_path(tmp_path):
    blob = _append_member(_zip_bytes(_base()), "/abs.txt", b"x")
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "UNSAFE_ARCHIVE"


def test_windows_traversal(tmp_path):
    blob = _append_member(_zip_bytes(_base()), "a\\..\\evil.txt", b"x")
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "UNSAFE_ARCHIVE"


def test_symlink_entry(tmp_path):
    info = zipfile.ZipInfo("evidence/link.txt")
    info.create_system = 3
    info.external_attr = 0o120777 << 16
    buffer = io.BytesIO(_zip_bytes(_base()))
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr(info, "evidence/a.txt")
    result = verify_bundle(_write(tmp_path, buffer.getvalue()))
    assert result.status == "UNSAFE_ARCHIVE"


def test_duplicate_entry(tmp_path):
    buffer = io.BytesIO(_zip_bytes(_base()))
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr("evidence/a.txt", b"hello")
    result = verify_bundle(_write(tmp_path, buffer.getvalue()))
    assert result.status == "UNSAFE_ARCHIVE"


def test_entry_count_limit(tmp_path):
    blob = _zip_bytes(_base())
    options = VerifierOptions(max_entries=2)
    result = verify_bundle_bytes(blob, options=options)
    assert result.status == "UNSAFE_ARCHIVE"


def test_member_size_limit(tmp_path):
    blob = _zip_bytes(_base())
    options = VerifierOptions(max_single_member_bytes=2)
    result = verify_bundle_bytes(blob, options=options)
    assert result.status == "UNSAFE_ARCHIVE"


def test_unsupported_version(tmp_path):
    builder = _base()
    manifest = builder.manifest_dict()
    manifest["bundle_spec_version"] = "oept-bundle/9.9"
    from oept.canonical import canonicalize_json

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in ("facts.json", "provenance.json", "evidence/a.txt"):
            item = zipfile.ZipInfo(path, date_time=FIXED_ZIP_DATE_TIME)
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = FIXED_EXTERNAL_ATTR
            item.create_system = 3
            archive.writestr(
                item,
                {"facts.json": b"[]", "provenance.json": b"[]", "evidence/a.txt": b"hello"}[path],
            )
        item = zipfile.ZipInfo("manifest.json", date_time=FIXED_ZIP_DATE_TIME)
        item.compress_type = zipfile.ZIP_DEFLATED
        item.external_attr = FIXED_EXTERNAL_ATTR
        item.create_system = 3
        archive.writestr(item, canonicalize_json(manifest))
    result = verify_bundle(_write(tmp_path, buffer.getvalue()))
    assert result.status == "UNSUPPORTED_SPEC_VERSION"


def test_malformed_manifest(tmp_path):
    blob = _replace_member(_zip_bytes(_base()), "manifest.json", b"{oops")
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "MALFORMED_BUNDLE"


def test_duplicate_json_keys_in_manifest(tmp_path):
    raw = (
        b'{"bundle_spec_version":"oept-bundle/0.1","bundle_id":"x",'
        b'"created_at":"2026-01-01T00:00:00Z","files":[],'
        b'"files":[{"path":"facts.json","sha256":"' + b"0" * 64 + b'"}]}'
    )
    blob = _replace_member(_zip_bytes(_base()), "manifest.json", raw)
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "MALFORMED_BUNDLE"
    assert any("duplicate" in note for note in result.notes)


def _manifest_with(members_blob: bytes, mutate) -> bytes:
    import json as _json

    source = zipfile.ZipFile(io.BytesIO(members_blob))
    manifest = _json.loads(source.read("manifest.json"))
    mutate(manifest)
    members = {
        info.filename: source.read(info.filename)
        for info in source.infolist()
        if info.filename != "manifest.json"
    }
    from oept.canonical import canonicalize_json as _canonical

    members["manifest.json"] = _canonical(manifest)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(members):
            archive.writestr(path, members[path])
    return buffer.getvalue()


def test_manifest_listing_itself_is_malformed(tmp_path):
    blob = _manifest_with(
        _zip_bytes(_base()),
        lambda manifest: manifest["files"].append(
            {"path": "manifest.json", "sha256": "0" * 64, "size_bytes": 1}
        ),
    )
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "MALFORMED_BUNDLE"


def test_manifest_listing_signature_is_malformed(tmp_path):
    blob = _manifest_with(
        _zip_bytes(_base()),
        lambda manifest: manifest["files"].append(
            {
                "path": "signatures/manifest.sig",
                "sha256": "0" * 64,
                "size_bytes": 1,
            }
        ),
    )
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "MALFORMED_BUNDLE"


def test_unknown_manifest_fields_ignored(tmp_path):
    blob = _manifest_with(
        _zip_bytes(_base()),
        lambda manifest: manifest.update({"future_field": {"a": [1, 2]}}),
    )
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "VALID_UNSIGNED"


def test_trailing_data_after_central_directory(tmp_path):
    blob = _zip_bytes(_base()) + b"\x00" * 64
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "MALFORMED_BUNDLE"
    assert any("trailing" in note for note in result.notes)


def test_leading_data_before_first_record(tmp_path):
    blob = b"JUNK" + _zip_bytes(_base())
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "MALFORMED_BUNDLE"


def test_hostile_member_names(tmp_path):
    hostile = [
        "//server/share.txt",
        "evidence\\..\\evil.txt",
        "./evidence/a.txt",
        "evidence//b.txt",
    ]
    for name in hostile:
        blob = _append_member(_zip_bytes(_base()), name, b"x")
        result = verify_bundle(_write(tmp_path, blob))
        assert result.status in ("UNSAFE_ARCHIVE", "MALFORMED_BUNDLE"), name


def test_case_sensitive_member_names(tmp_path):
    # EVIDENCE/a.txt is a different, undeclared member — never confused
    # with evidence/a.txt.
    blob = _append_member(_zip_bytes(_base()), "EVIDENCE/a.txt", b"x")
    result = verify_bundle(_write(tmp_path, blob))
    assert result.status == "UNEXPECTED_FILE"


def test_bare_directory_entry_rejected(tmp_path):
    buffer = io.BytesIO(_zip_bytes(_base()))
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr(zipfile.ZipInfo("evidence/subdir/"), b"")
    result = verify_bundle(_write(tmp_path, buffer.getvalue()))
    assert result.status == "UNSAFE_ARCHIVE"


def test_configurable_limits_enforced(tmp_path):
    blob = _zip_bytes(_base())
    assert (
        verify_bundle_bytes(blob, options=VerifierOptions(max_entries=2)).status == "UNSAFE_ARCHIVE"
    )
    assert (
        verify_bundle_bytes(blob, options=VerifierOptions(max_single_member_bytes=1)).status
        == "UNSAFE_ARCHIVE"
    )
    assert (
        verify_bundle_bytes(blob, options=VerifierOptions(max_total_uncompressed_bytes=5)).status
        == "UNSAFE_ARCHIVE"
    )


def test_zip_comment_is_legitimate(tmp_path):
    buffer = io.BytesIO(_zip_bytes(_base()))
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.comment = b"legitimate archive comment"
    result = verify_bundle(_write(tmp_path, buffer.getvalue()))
    assert result.status == "VALID_UNSIGNED"


def test_not_a_zip(tmp_path):
    target = tmp_path / "nope.zip"
    target.write_bytes(b"definitely not a zip file")
    result = verify_bundle(target)
    assert result.status == "MALFORMED_BUNDLE"


def test_result_serializes_to_schema(tmp_path):
    from oept.schemas import validate_against_schema

    result = verify_bundle(_write(tmp_path, _zip_bytes(_base())))
    assert validate_against_schema("verification-result", result.to_dict()) == []


def test_duplicate_trust_key_ids_rejected(tmp_path):
    from oept.errors import ConfigurationError
    from oept.signing import load_trust_keys

    _private_pem, public_pem = generate_keypair()
    trust_file = tmp_path / "trust.json"
    trust_file.write_text(
        json.dumps(
            [
                {"key_id": "same", "public_key_pem": public_pem.decode()},
                {"key_id": "same", "public_key_pem": public_pem.decode()},
            ]
        )
    )
    with pytest.raises(ConfigurationError):
        load_trust_keys(trust_file)


def test_verify_unpacked_directory(tmp_path):
    import zipfile

    from oept.verify import verify_bundle_dir

    blob = _zip_bytes(_base())
    target = tmp_path / "unpacked"
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        archive.extractall(target)
    result = verify_bundle_dir(target)
    assert result.status == "VALID_UNSIGNED"
    assert result.ok is True


def test_verify_unpacked_directory_tampered(tmp_path):
    import zipfile

    from oept.verify import verify_bundle_dir

    blob = _zip_bytes(_base())
    target = tmp_path / "unpacked"
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        archive.extractall(target)
    (target / "evidence" / "a.txt").write_bytes(b"tampered")
    result = verify_bundle_dir(target)
    assert result.status == "HASH_MISMATCH"


# --- local ZIP surgery helpers (tests only) ---


def _replace_member(blob: bytes, name: str, data: bytes) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(blob))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in source.infolist():
            payload = data if info.filename == name else source.read(info.filename)
            fresh = zipfile.ZipInfo(info.filename, date_time=FIXED_ZIP_DATE_TIME)
            fresh.compress_type = zipfile.ZIP_DEFLATED
            fresh.external_attr = FIXED_EXTERNAL_ATTR
            fresh.create_system = 3
            archive.writestr(fresh, payload)
    return buffer.getvalue()


def _drop_member(blob: bytes, name: str) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(blob))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for info in source.infolist():
            if info.filename == name:
                continue
            fresh = zipfile.ZipInfo(info.filename, date_time=FIXED_ZIP_DATE_TIME)
            fresh.compress_type = zipfile.ZIP_DEFLATED
            fresh.external_attr = FIXED_EXTERNAL_ATTR
            fresh.create_system = 3
            archive.writestr(fresh, source.read(info.filename))
    return buffer.getvalue()


def _append_member(blob: bytes, name: str, data: bytes) -> bytes:
    buffer = io.BytesIO(blob)
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()
