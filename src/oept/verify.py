"""Offline evidence-bundle verifier (oept-bundle/0.1).

Verification order (each step fails closed with a terminal status):
  1. open the archive; reject unreadable archives (MALFORMED_BUNDLE)
  2. inspect member names before reading content
  3. reject duplicate members (UNSAFE_ARCHIVE)
  4. reject unsafe paths: absolute, traversal, backslash, NUL,
     Windows drive shapes (UNSAFE_ARCHIVE)
  5. reject symlink entries (UNSAFE_ARCHIVE)
  6. enforce entry-count and size limits (UNSAFE_ARCHIVE)
  7. require manifest.json (MALFORMED_BUNDLE)
  8. parse manifest JSON safely (MALFORMED_BUNDLE)
  9. validate the manifest against its schema (MALFORMED_BUNDLE)
  10. require a supported spec version (UNSUPPORTED_SPEC_VERSION)
  11. compare declared vs actual member set, honoring the signature
      envelope (MISSING_FILE / UNEXPECTED_FILE)
  12. recompute SHA-256 for every declared member (HASH_MISMATCH)
  13. verify the Ed25519 signature when present (SIGNATURE_INVALID /
      SIGNATURE_KEY_UNKNOWN / VALID_SIGNED)
  14. otherwise VALID_UNSIGNED, or SIGNATURE_NOT_PRESENT detail preserved
      by callers that need the unsigned-vs-never-signed distinction

Members are verified directly from ZIP streams; nothing is extracted to
arbitrary filesystem paths.

What verification proves (and does not prove) is documented in
spec/threat-model.md and repeated in every human-readable report footer.
"""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .canonical import CanonicalizationError, canonicalize_json
from .errors import OeptError
from .hashing import sha256_bytes
from .models import VerificationResult
from .signing import TrustedKey, verify_manifest_signature

BUNDLE_SPEC_VERSION = "oept-bundle/0.1"
SUPPORTED_SPEC_VERSIONS = frozenset({BUNDLE_SPEC_VERSION})

VERIFIER_VERSION = "oept-verify/0.1.0"

SIGNATURE_MEMBER = "signatures/manifest.sig"
KEY_INFO_MEMBER = "signatures/key-info.json"

DEFAULT_MAX_ENTRIES = 10_000
DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_SINGLE_MEMBER_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class VerifierOptions:
    """Resource limits for archive inspection (all configurable)."""

    max_entries: int = DEFAULT_MAX_ENTRIES
    max_total_uncompressed_bytes: int = DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES
    max_single_member_bytes: int = DEFAULT_MAX_SINGLE_MEMBER_BYTES


def _fail(
    status: str,
    notes: list[str],
    bundle_spec_version: str | None = None,
    bundle_id: str | None = None,
    signing_state: str | None = None,
) -> VerificationResult:
    return VerificationResult(
        status=status,
        bundle_spec_version=bundle_spec_version,
        bundle_id=bundle_id,
        signing_state=signing_state,
        notes=notes,
    )


def _member_is_safe(name: str) -> str | None:
    """Return an error reason, or None when the member name is safe."""
    if not name:
        return "empty archive member name"
    if "\x00" in name:
        return f"NUL byte in archive member name: {name!r}"
    if name.startswith("/") or "\\" in name:
        return f"absolute or backslash archive path: {name!r}"
    if len(name) > 2 and name[1] == ":":
        return f"Windows drive path in archive: {name!r}"
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return f"traversal or empty segment in archive path: {name!r}"
    if len(name) > 512:
        return f"archive member path too long: {name!r}"
    return None


def _inspect_archive(zf: zipfile.ZipFile, options: VerifierOptions) -> str | None:
    infos = zf.infolist()
    if len(infos) > options.max_entries:
        return f"archive exceeds {options.max_entries} entries"
    seen: set[str] = set()
    total = 0
    for info in infos:
        name = info.filename
        if name in seen:
            return f"duplicate archive member: {name!r}"
        seen.add(name)
        reason = _member_is_safe(name)
        if reason is not None:
            return reason
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            return f"symlink archive member not allowed: {name!r}"
        if info.file_size > options.max_single_member_bytes:
            return f"archive member exceeds single-member limit ({info.file_size} bytes): {name!r}"
        total += info.file_size
        if total > options.max_total_uncompressed_bytes:
            return "archive decompressed size exceeds safety limit"
    return None


def _read_member(zf: zipfile.ZipFile, name: str) -> bytes:
    # Direct stream read; never extracted to disk.
    with zf.open(name, "r") as handle:
        return handle.read()


def _manifest_schema_errors(manifest: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest.json must be a JSON object"]
    for field in ("bundle_spec_version", "bundle_id", "created_at", "files"):
        if field not in manifest:
            errors.append(f"manifest.json is missing required field: {field}")
    if "files" in manifest and not isinstance(manifest["files"], list):
        errors.append("manifest.json field 'files' must be a list")
        return errors
    if isinstance(manifest.get("files"), list):
        seen: set[str] = set()
        for entry in manifest["files"]:
            if not isinstance(entry, dict):
                errors.append("manifest file entries must be objects")
                continue
            for field in ("path", "sha256", "size_bytes"):
                if field not in entry:
                    errors.append(f"manifest file entry is missing field: {field}")
            path = entry.get("path")
            if isinstance(path, str):
                if path in seen:
                    errors.append(f"manifest lists duplicate path: {path!r}")
                seen.add(path)
                reason = _member_is_safe(path)
                if reason is not None:
                    errors.append(f"manifest lists unsafe path: {reason}")
            digest = entry.get("sha256")
            if isinstance(digest, str) and (
                len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
            ):
                errors.append(f"manifest entry has malformed sha256: {digest!r}")
    return errors


class MemberReader(Protocol):
    """Minimal interface for reading named members (ZIP or directory)."""

    def read(self, name: str) -> bytes:
        """Return member bytes; raise KeyError when absent."""
        ...  # pragma: no cover - protocol


def _verify_members(
    names: set[str],
    reader: MemberReader,
    manifest: dict[str, Any],
    options: VerifierOptions,
) -> VerificationResult:
    declared = {str(e["path"]): str(e["sha256"]) for e in manifest["files"]}
    # Signature envelope members are recognized, not "unexpected". The
    # signature itself is verified cryptographically in the next step;
    # key-info.json, when present, SHOULD additionally be a listed file
    # (bound to the signed payload) but its key_id is never trusted.
    envelope = {SIGNATURE_MEMBER}
    actual = set(names) - {"manifest.json"}
    missing = sorted(set(declared) - actual)
    unexpected = sorted(actual - set(declared) - envelope)
    result = VerificationResult(
        status="VALID",
        bundle_spec_version=str(manifest.get("bundle_spec_version")),
        bundle_id=str(manifest.get("bundle_id")),
        signing_state=("SIGNED" if SIGNATURE_MEMBER in actual else "UNSIGNED"),
    )
    if missing:
        result = VerificationResult(
            status="MISSING_FILE",
            bundle_spec_version=result.bundle_spec_version,
            bundle_id=result.bundle_id,
            signing_state=result.signing_state,
            missing=missing,
            notes=[f"declared member absent from archive: {m}" for m in missing],
        )
        return result
    if unexpected:
        result = VerificationResult(
            status="UNEXPECTED_FILE",
            bundle_spec_version=result.bundle_spec_version,
            bundle_id=result.bundle_id,
            signing_state=result.signing_state,
            unexpected=unexpected,
            notes=[f"archive member not declared in manifest: {m}" for m in unexpected],
        )
        return result
    mismatches: list[dict[str, Any]] = []
    for path in sorted(declared):
        try:
            data = reader.read(path)
        except KeyError:
            mismatches.append({"path": path, "expected": declared[path], "actual": None})
            continue
        actual_digest = sha256_bytes(data)
        if actual_digest != declared[path]:
            mismatches.append({"path": path, "expected": declared[path], "actual": actual_digest})
    if mismatches:
        return VerificationResult(
            status="HASH_MISMATCH",
            bundle_spec_version=result.bundle_spec_version,
            bundle_id=result.bundle_id,
            signing_state=result.signing_state,
            mismatches=mismatches,
            notes=[f"digest mismatch: {m['path']}" for m in mismatches],
        )
    return result


def _verify_signature(
    names: set[str],
    reader: MemberReader,
    manifest: dict[str, Any],
    result: VerificationResult,
    trusted_keys: list[TrustedKey],
) -> VerificationResult:
    if SIGNATURE_MEMBER not in names:
        return VerificationResult(
            status="VALID_UNSIGNED" if result.status == "VALID" else result.status,
            bundle_spec_version=result.bundle_spec_version,
            bundle_id=result.bundle_id,
            signing_state="UNSIGNED",
            mismatches=result.mismatches,
            missing=result.missing,
            unexpected=result.unexpected,
            notes=[*result.notes, "no signature member present"],
        )
    try:
        signature = reader.read(SIGNATURE_MEMBER)
    except KeyError:
        return VerificationResult(
            status="SIGNATURE_INVALID",
            bundle_spec_version=result.bundle_spec_version,
            bundle_id=result.bundle_id,
            signing_state="SIGNED",
            notes=["signature member unreadable"],
        )
    if not trusted_keys:
        return VerificationResult(
            status="SIGNATURE_KEY_UNKNOWN",
            bundle_spec_version=result.bundle_spec_version,
            bundle_id=result.bundle_id,
            signing_state="SIGNED",
            notes=[
                "bundle is signed but no trusted keys were supplied; "
                "embedded key metadata, if any, is never trusted"
            ],
        )
    # The signature covers the CANONICAL manifest bytes (exactly what the
    # signer signed), never the raw file bytes.
    try:
        canonical = canonicalize_json(manifest)
    except CanonicalizationError as exc:
        return VerificationResult(
            status="MALFORMED_BUNDLE",
            bundle_spec_version=result.bundle_spec_version,
            bundle_id=result.bundle_id,
            signing_state="SIGNED",
            notes=[f"manifest is not canonicalizable: {exc}"],
        )
    key_id = verify_manifest_signature(canonical, signature, trusted_keys)
    if key_id is None:
        return VerificationResult(
            status="SIGNATURE_INVALID",
            bundle_spec_version=result.bundle_spec_version,
            bundle_id=result.bundle_id,
            signing_state="SIGNED",
            notes=["signature does not verify against any supplied trusted key"],
        )
    return VerificationResult(
        status="VALID_SIGNED",
        bundle_spec_version=result.bundle_spec_version,
        bundle_id=result.bundle_id,
        signing_state="SIGNED",
        signature_checked=True,
        trusted_key_id=key_id,
        notes=[f"signature verified against trusted key: {key_id}"],
    )


class _DirReader:
    """Filesystem-directory reader with the same interface as the ZIP path."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def read(self, name: str) -> bytes:
        target = self.root / name
        return target.read_bytes()


def verify_bundle_bytes(
    data: bytes,
    trusted_keys: list[TrustedKey] | None = None,
    options: VerifierOptions | None = None,
) -> VerificationResult:
    """Verify a bundle from in-memory ZIP bytes (no disk I/O at all)."""
    opts = options or VerifierOptions()
    keys = trusted_keys or []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        return _fail("MALFORMED_BUNDLE", [f"not a readable ZIP archive: {exc}"])
    with archive as zf:
        problem = _inspect_archive(zf, opts)
        if problem is not None:
            return _fail("UNSAFE_ARCHIVE", [problem])
        names = set(zf.namelist())
        if "manifest.json" not in names:
            return _fail("MALFORMED_BUNDLE", ["manifest.json not present"])
        try:
            manifest = json.loads(_read_member(zf, "manifest.json").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return _fail("MALFORMED_BUNDLE", [f"manifest.json is not readable JSON: {exc}"])
        schema_errors = _manifest_schema_errors(manifest)
        if schema_errors:
            return _fail("MALFORMED_BUNDLE", schema_errors)
        spec = manifest.get("bundle_spec_version")
        if spec not in SUPPORTED_SPEC_VERSIONS:
            return _fail(
                "UNSUPPORTED_SPEC_VERSION",
                [f"bundle spec version {spec!r} is not supported"],
                bundle_spec_version=str(spec),
                bundle_id=str(manifest.get("bundle_id")),
            )
        member_result = _verify_members(names, zf, manifest, opts)
        if member_result.status != "VALID":
            return member_result
        return _verify_signature(names, zf, manifest, member_result, keys)


def verify_bundle(
    path: str | Path,
    trusted_keys: list[TrustedKey] | None = None,
    options: VerifierOptions | None = None,
) -> VerificationResult:
    """Verify a bundle ZIP file on disk. Fully offline; no network use."""
    target = Path(path)
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise OeptError(f"cannot read bundle file: {exc}") from exc
    return verify_bundle_bytes(data, trusted_keys, options)


def verify_bundle_dir(
    path: str | Path,
    trusted_keys: list[TrustedKey] | None = None,
    options: VerifierOptions | None = None,
) -> VerificationResult:
    """Verify an unpacked bundle directory (same rules, files read directly)."""
    opts = options or VerifierOptions()
    keys = trusted_keys or []
    root = Path(path)
    if not root.is_dir():
        raise OeptError(f"not a directory: {path}")
    entries = [p for p in root.rglob("*") if p.is_file() or p.is_symlink()]
    if len(entries) > opts.max_entries:
        return _fail("UNSAFE_ARCHIVE", [f"directory exceeds {opts.max_entries} entries"])
    names: set[str] = set()
    total = 0
    for entry in entries:
        try:
            name = entry.relative_to(root).as_posix()
        except ValueError:
            return _fail("UNSAFE_ARCHIVE", ["unresolvable member path"])
        if name in names:
            return _fail("UNSAFE_ARCHIVE", [f"duplicate member: {name!r}"])
        names.add(name)
        reason = _member_is_safe(name)
        if reason is not None:
            return _fail("UNSAFE_ARCHIVE", [reason])
        if entry.is_symlink():
            return _fail("UNSAFE_ARCHIVE", [f"symlink member not allowed: {name!r}"])
        size = entry.stat().st_size
        if size > opts.max_single_member_bytes:
            return _fail("UNSAFE_ARCHIVE", [f"member exceeds single-member limit: {name!r}"])
        total += size
        if total > opts.max_total_uncompressed_bytes:
            return _fail("UNSAFE_ARCHIVE", ["directory size exceeds safety limit"])
    if "manifest.json" not in names:
        return _fail("MALFORMED_BUNDLE", ["manifest.json not present"])
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _fail("MALFORMED_BUNDLE", [f"manifest.json is not readable JSON: {exc}"])
    schema_errors = _manifest_schema_errors(manifest)
    if schema_errors:
        return _fail("MALFORMED_BUNDLE", schema_errors)
    spec = manifest.get("bundle_spec_version")
    if spec not in SUPPORTED_SPEC_VERSIONS:
        return _fail(
            "UNSUPPORTED_SPEC_VERSION",
            [f"bundle spec version {spec!r} is not supported"],
            bundle_spec_version=str(spec),
            bundle_id=str(manifest.get("bundle_id")),
        )
    reader = _DirReader(root)
    member_result = _verify_members(names, reader, manifest, opts)
    if member_result.status != "VALID":
        return member_result
    return _verify_signature(names, reader, manifest, member_result, keys)
