"""Builder/verifier consistency and honest CLI reporting."""

from pathlib import Path

import pytest

from oept.bundle import BundleBuilder
from oept.cli import _render_human
from oept.errors import ValidationError
from oept.models import VerificationResult
from oept.verify import verify_bundle_dir


def test_builder_requires_evidence_member() -> None:
    builder = BundleBuilder("empty")
    builder.add_file("facts.json", b"[]").add_file("provenance.json", b"[]")
    with pytest.raises(ValidationError, match="evidence/"):
        builder.build_zip_bytes()


@pytest.mark.parametrize(
    "status", ["MALFORMED_BUNDLE", "UNSAFE_ARCHIVE", "UNSUPPORTED_SPEC_VERSION"]
)
def test_cli_does_not_claim_unexecuted_digests_passed(status: str) -> None:
    assert "Member digests: NOT EVALUATED" in _render_human(
        "bad.zip", VerificationResult(status=status)
    )


def test_directory_root_symlink_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)
    assert verify_bundle_dir(link).status == "UNSAFE_ARCHIVE"
