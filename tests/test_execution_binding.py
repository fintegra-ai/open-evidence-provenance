# SPDX-License-Identifier: Apache-2.0

"""Tests for the optional HEA ``execution_binding`` manifest field.

The field is a pointer to an OEVP Historical Execution Attestation run,
not proof: OEPT checks format only (HEA design §3.3). A bundle cannot
bind its own execution — the execution ID derives from the bundle digest,
and adding the binding changes the digest (tested explicitly below).
"""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from oept.bundle import BundleBuilder, validate_execution_binding
from oept.errors import ValidationError
from oept.hashing import sha256_bytes
from oept.schemas import validate_against_schema
from oept.verify import verify_bundle_bytes, verify_bundle_dir

EXECUTION_ID = "exec_" + "a" * 32
COMMITMENT_DIGEST = "sha256:" + "b" * 64


def _builder() -> BundleBuilder:
    builder = BundleBuilder(bundle_id="hea-binding-test")
    builder.add_file("facts.json", b'{"fact": 1}')
    builder.add_file("provenance.json", b'{"source": "test"}')
    builder.add_evidence("a.bin", b"evidence")
    return builder


def _manifest_of(data: bytes) -> dict[str, Any]:
    with zipfile.ZipFile(BytesIO(data)) as zf:
        return dict(json.loads(zf.read("manifest.json")))


def test_no_binding_by_default() -> None:
    assert "execution_binding" not in _builder().manifest_dict()


def test_binding_is_recorded_in_manifest() -> None:
    manifest = _builder().set_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST).manifest_dict()
    assert manifest["execution_binding"] == {
        "execution_id": EXECUTION_ID,
        "commitment_digest": COMMITMENT_DIGEST,
    }


def test_binding_via_constructor_field() -> None:
    builder = _builder()
    builder.execution_binding = validate_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST)
    assert builder.manifest_dict()["execution_binding"]["execution_id"] == EXECUTION_ID


def test_binding_is_deterministic() -> None:
    first = _builder().set_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST).build_zip_bytes()
    second = _builder().set_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST).build_zip_bytes()
    assert first == second


@pytest.mark.parametrize(
    "execution_id",
    [
        "",
        "exec_" + "A" * 32,
        "exec_" + "a" * 31,
        "exec_" + "a" * 33,
        "exec_" + "g" * 32,
        "att_" + "a" * 32,
    ],
)
def test_invalid_execution_id_rejected(execution_id: str) -> None:
    with pytest.raises(ValidationError, match="execution_id"):
        validate_execution_binding(execution_id, COMMITMENT_DIGEST)
    with pytest.raises(ValidationError, match="execution_id"):
        _builder().set_execution_binding(execution_id, COMMITMENT_DIGEST)


@pytest.mark.parametrize(
    "commitment_digest",
    [
        "",
        "sha256:" + "B" * 64,
        "sha256:" + "b" * 63,
        "sha256:" + "b" * 65,
        "b" * 64,
        "sha256:" + "z" * 64,
    ],
)
def test_invalid_commitment_digest_rejected(commitment_digest: str) -> None:
    with pytest.raises(ValidationError, match="commitment_digest"):
        validate_execution_binding(EXECUTION_ID, commitment_digest)


def test_binding_does_not_change_member_digests() -> None:
    plain = _builder().manifest_dict()
    bound = _builder().set_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST).manifest_dict()
    assert plain["files"] == bound["files"]
    assert plain["bundle_id"] == bound["bundle_id"]


def test_bound_bundle_has_a_different_digest_than_unbound() -> None:
    """Adding the binding changes the bundle digest: no self-binding.

    The execution ID is derived from the bundle digest, so a manifest
    that carried the digest of its own bundle would be a SHA-256 fixed
    point. The binding therefore always points at the execution of the
    bundle as built WITHOUT the binding.
    """
    unbound = _builder().build_zip_bytes()
    bound = _builder().set_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST).build_zip_bytes()
    assert sha256_bytes(unbound) != sha256_bytes(bound)


def test_verify_accepts_well_formed_binding() -> None:
    data = _builder().set_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST).build_zip_bytes()
    result = verify_bundle_bytes(data)
    assert result.status == "VALID_UNSIGNED", result.notes


def test_verify_accepts_bundle_without_binding() -> None:
    result = verify_bundle_bytes(_builder().build_zip_bytes())
    assert result.status == "VALID_UNSIGNED", result.notes


def _tampered_manifest(data: bytes, binding: object) -> bytes:
    with zipfile.ZipFile(BytesIO(data)) as zf:
        members = {name: zf.read(name) for name in zf.namelist()}
    manifest = json.loads(members["manifest.json"])
    manifest["execution_binding"] = binding
    members["manifest.json"] = json.dumps(manifest, sort_keys=True).encode()
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, content in sorted(members.items()):
            zf.writestr(name, content)
    return buffer.getvalue()


def test_verify_rejects_malformed_execution_id() -> None:
    data = _tampered_manifest(
        _builder().build_zip_bytes(),
        {"execution_id": "exec_" + "A" * 32, "commitment_digest": COMMITMENT_DIGEST},
    )
    result = verify_bundle_bytes(data)
    assert result.status == "MALFORMED_BUNDLE"
    assert any("execution_binding" in note for note in result.notes)


def test_verify_rejects_malformed_commitment_digest() -> None:
    data = _tampered_manifest(
        _builder().build_zip_bytes(),
        {"execution_id": EXECUTION_ID, "commitment_digest": "not-a-digest"},
    )
    result = verify_bundle_bytes(data)
    assert result.status == "MALFORMED_BUNDLE"


def test_verify_rejects_binding_with_extra_keys() -> None:
    data = _tampered_manifest(
        _builder().build_zip_bytes(),
        {
            "execution_id": EXECUTION_ID,
            "commitment_digest": COMMITMENT_DIGEST,
            "extra": "smuggled",
        },
    )
    result = verify_bundle_bytes(data)
    assert result.status == "MALFORMED_BUNDLE"


def test_verify_rejects_non_object_binding() -> None:
    data = _tampered_manifest(_builder().build_zip_bytes(), "exec_" + "a" * 32)
    result = verify_bundle_bytes(data)
    assert result.status == "MALFORMED_BUNDLE"


def test_verify_dir_path_checks_binding_too(tmp_path: Path) -> None:

    data = _builder().set_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST).build_zip_bytes()
    good_dir = tmp_path / "good"
    with zipfile.ZipFile(BytesIO(data)) as zf:
        zf.extractall(good_dir)
    assert verify_bundle_dir(good_dir).status == "VALID_UNSIGNED"

    bad = _tampered_manifest(
        _builder().build_zip_bytes(),
        {"execution_id": "wrong", "commitment_digest": COMMITMENT_DIGEST},
    )
    bad_dir = tmp_path / "bad"
    with zipfile.ZipFile(BytesIO(bad)) as zf:
        zf.extractall(bad_dir)
    result = verify_bundle_dir(bad_dir)
    assert result.status == "MALFORMED_BUNDLE"
    assert any("execution_binding" in note for note in result.notes)


def test_schema_rejects_malformed_binding() -> None:
    manifest = _builder().manifest_dict()
    manifest["execution_binding"] = {
        "execution_id": "wrong",
        "commitment_digest": COMMITMENT_DIGEST,
    }
    errors = validate_against_schema("bundle-manifest", manifest)
    assert errors, "schema should reject a malformed execution_id"


def test_schema_accepts_well_formed_binding() -> None:
    manifest = _builder().set_execution_binding(EXECUTION_ID, COMMITMENT_DIGEST).manifest_dict()
    assert validate_against_schema("bundle-manifest", manifest) == []
