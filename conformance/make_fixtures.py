"""Build the OEPT conformance corpus deterministically.

Regenerates conformance/fixtures/* from fixed inputs (fixed timestamps,
fixed content). The Ed25519 test key is generated once and reused so
fixtures are byte-stable across runs.

The test key is TEST ONLY, publicly compromised by definition, and must
NEVER be used for real signatures. See conformance/test-only-keys/README.md.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from oept.bundle import (  # noqa: E402
    FIXED_EXTERNAL_ATTR,
    FIXED_ZIP_DATE_TIME,
    BundleBuilder,
)
from oept.signing import generate_keypair, sign_manifest  # noqa: E402

CREATED_AT = "2026-01-01T00:00:00Z"

FACTS = {
    "facts": [
        {
            "id": "fact_01",
            "fact_type": "document.total",
            "subject": "doc:report-2026-001",
            "revisions": [
                {
                    "id": "frev_01",
                    "fact_id": "fact_01",
                    "value": "1250.00",
                    "value_type": "decimal",
                    "observed_at": "2026-01-01T00:00:00Z",
                }
            ],
        }
    ]
}

PROVENANCE = {
    "pointers": [
        {
            "id": "prov_01",
            "fact_revision_id": "frev_01",
            "evidence_version_id": "ever_01",
            "locator_type": "text_line",
            "locator": "line=42",
            "method": "manual-extraction@1.0",
            "note": "conformance fixture",
        }
    ]
}

EVIDENCE = {
    "evidence/report-2026-001.txt": (b"Conformance source document.\nTotal: 1250.00\n"),
    "evidence/readme.txt": b"OEPT conformance evidence member.\n",
}


def _base_builder(bundle_id: str = "conformance-demo") -> BundleBuilder:
    builder = BundleBuilder(bundle_id=bundle_id, created_at=CREATED_AT)
    builder.add_file("facts.json", json.dumps(FACTS, indent=2, sort_keys=True).encode())
    builder.add_file("provenance.json", json.dumps(PROVENANCE, indent=2, sort_keys=True).encode())
    for path in sorted(EVIDENCE):
        builder.add_file(path, EVIDENCE[path])
    return builder


def _write_fixture(
    name: str, bundle_bytes: bytes, expected_status: str, trust_keys: object = None
) -> None:
    target = ROOT / "conformance" / "fixtures" / name
    target.mkdir(parents=True, exist_ok=True)
    (target / "bundle.zip").write_bytes(bundle_bytes)
    (target / "expected-result.json").write_text(
        json.dumps({"status": expected_status}, indent=2) + "\n", encoding="utf-8"
    )
    trust_path = target / "trust-keys.json"
    if trust_keys is None:
        if trust_path.exists():
            trust_path.unlink()
    else:
        trust_path.write_text(json.dumps(trust_keys, indent=2) + "\n", encoding="utf-8")


def _zip_with_extra_members(base: bytes, extra: list[tuple[str, bytes]]) -> bytes:
    """Return a copy of a ZIP with additional raw members appended.

    Used for hostile-structure fixtures (unsafe paths, duplicates,
    unexpected members). Members use default timestamps; only the base
    payload needs determinism.
    """
    buffer = io.BytesIO(base)
    with zipfile.ZipFile(buffer, "a", zipfile.ZIP_DEFLATED) as archive:
        for name, data in extra:
            archive.writestr(name, data)
    return buffer.getvalue()


def _zip_with_replaced_member(base: bytes, name: str, data: bytes) -> bytes:
    """Return a copy of a ZIP with one member's bytes replaced."""
    source = zipfile.ZipFile(io.BytesIO(base))
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


def _zip_without_member(base: bytes, name: str) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(base))
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


def ensure_test_key() -> tuple[Path, Path]:
    """Load or generate the TEST-ONLY conformance signing key."""
    key_dir = ROOT / "conformance" / "test-only-keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    private_path = key_dir / "conformance-test-only-signing.key"
    public_path = key_dir / "conformance-test-only-signing.pub"
    if not private_path.exists():
        private_pem, public_pem = generate_keypair()
        private_path.write_bytes(private_pem)
        public_path.write_bytes(public_pem)
    return private_path, public_path


def main() -> int:
    private_path, public_path = ensure_test_key()
    private_pem = private_path.read_bytes()
    public_pem = public_path.read_bytes().decode("utf-8")
    trust = [{"key_id": "conformance-test-key", "public_key_pem": public_pem}]

    unsigned = _base_builder().build_zip_bytes()
    _write_fixture("01-valid-unsigned", unsigned, "VALID_UNSIGNED")

    signed_builder = _base_builder()
    signed_builder.key_id = "conformance-test-key"
    signature = sign_manifest(signed_builder.manifest_bytes(), private_pem)
    signed = signed_builder.build_zip_bytes(signature)
    _write_fixture("02-valid-signed", signed, "VALID_SIGNED", trust_keys=trust)

    tampered = _zip_with_replaced_member(
        unsigned, "evidence/report-2026-001.txt", b"Conformance source document.\nTotal: 9999.99\n"
    )
    _write_fixture("03-tampered-artifact", tampered, "HASH_MISMATCH")

    missing = _zip_without_member(unsigned, "evidence/readme.txt")
    _write_fixture("04-missing-member", missing, "MISSING_FILE")

    unsafe = _zip_with_extra_members(unsigned, [("../evil.txt", b"x")])
    _write_fixture("05-unsafe-path", unsafe, "UNSAFE_ARCHIVE")

    bad_sig = bytearray(sign_manifest(signed_builder.manifest_bytes(), private_pem))
    bad_sig[0] ^= 0xFF
    broken = signed_builder.build_zip_bytes(bytes(bad_sig))
    _write_fixture("06-signature-invalid", broken, "SIGNATURE_INVALID", trust_keys=trust)

    _write_fixture("07-unknown-key", signed, "SIGNATURE_KEY_UNKNOWN")

    extra = _zip_with_extra_members(unsigned, [("evidence/unlisted.txt", b"not in manifest")])
    _write_fixture("08-unexpected-member", extra, "UNEXPECTED_FILE")

    future_builder = _base_builder(bundle_id="future-bundle")
    future_manifest = future_builder.manifest_dict()
    future_manifest["bundle_spec_version"] = "oept-bundle/9.9"
    from oept.canonical import canonicalize_json

    future_members = dict(future_builder._files)
    future_members["manifest.json"] = canonicalize_json(future_manifest)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(future_members):
            info = zipfile.ZipInfo(path, date_time=FIXED_ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = FIXED_EXTERNAL_ATTR
            info.create_system = 3
            archive.writestr(info, future_members[path])
    _write_fixture("09-unsupported-version", buffer.getvalue(), "UNSUPPORTED_SPEC_VERSION")

    malformed = _zip_with_replaced_member(unsigned, "manifest.json", b"{not valid json,,,")
    _write_fixture("10-malformed-manifest", malformed, "MALFORMED_BUNDLE")

    # Worked example for the README quickstart.
    examples = ROOT / "examples"
    (examples / "evidence-project" / "evidence").mkdir(parents=True, exist_ok=True)
    (examples / "evidence-project" / "facts.json").write_text(
        json.dumps(FACTS, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (examples / "evidence-project" / "provenance.json").write_text(
        json.dumps(PROVENANCE, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for path, data in EVIDENCE.items():
        (examples / "evidence-project" / path).write_bytes(data)
    shutil.copyfile(
        ROOT / "conformance" / "fixtures" / "01-valid-unsigned" / "bundle.zip",
        examples / "valid-unsigned.zip",
    )

    # Mirror the corpus + schemas into package data so installed wheels
    # carry them (single generation command => no drift at build time).
    # Marker __init__.py files keep the data importable; they are not
    # part of the mirrored payload and are recreated here, not copied.
    pkg_data = ROOT / "src" / "oept" / "data"
    mirror_tree(ROOT / "conformance" / "fixtures", pkg_data / "conformance")
    mirror_tree(ROOT / "schemas", pkg_data / "schemas")
    (pkg_data / "__init__.py").write_text(
        '"""OEPT package data (schemas, conformance corpus)."""\n',
        encoding="utf-8",
    )
    (pkg_data / "schemas" / "__init__.py").write_text(
        '"""Versioned OEPT JSON Schemas (installed copies; canonical '
        'source: top-level schemas/)."""\n',
        encoding="utf-8",
    )

    print("conformance fixtures written (10) + examples/valid-unsigned.zip")
    return 0


def mirror_tree(source: Path, target: Path) -> None:
    """Byte-exact mirror of a directory tree (package-data copies)."""
    import shutil as _shutil

    if target.exists():
        _shutil.rmtree(target)
    _shutil.copytree(source, target)


if __name__ == "__main__":
    raise SystemExit(main())
