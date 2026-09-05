# oept-bundle/0.1 — Portable Evidence Bundle Specification

Status: pre-1.0 draft (spec version `oept-bundle/0.1`). This document is
normative for builders and verifiers claiming `oept-bundle/0.1` support.

## 1. Purpose

An evidence bundle is a deterministic, self-describing ZIP archive that
binds a set of evidence files to SHA-256 digests through a canonical
manifest, with an optional detached-style Ed25519 application signature.
Any party holding only the bundle bytes can verify structural integrity,
digest integrity, and (with a caller-supplied trust root) signature
authenticity — fully offline, without contacting the producer.

## 2. Archive format

- Standard ZIP, DEFLATE compression.
- Member paths: sorted lexicographically at build time.
- Fixed ZIP timestamps (`2024-01-01T00:00:00`), fixed permission bits
  (`0o644`), stable compression level. See §8 on reproducibility limits.
- No encryption, no multi-disk, no proprietary extensions.

## 3. Required members

- `manifest.json` — canonical JSON (RFC 8785, UTF-8), see §5.
- `facts.json` — array/object of fact records (schema: `fact`).
- `provenance.json` — array/object of provenance pointers
  (schema: `provenance-pointer`).
- `evidence/` — one or more raw evidence files (opaque bytes).

A bundle missing any required member fails verification
(`MISSING_FILE` for declared-but-absent members, `MALFORMED_BUNDLE`
when `manifest.json` itself is absent or unreadable).

## 4. Optional members

- `metadata/` — version/transform metadata files (opaque to the verifier
  except for digest coverage).
- `rule_traces.json` — deterministic evaluation records
  (schema: `rule-trace`).
- `signatures/manifest.sig` — raw Ed25519 signature bytes over the
  canonical manifest bytes (see §6).
- `signatures/key-info.json` — advisory signer metadata
  (`{key_id, public_key_pem?, note?}`). Identification only: never trust.
- `SUMMARY.txt` — human-readable summary. Informational; digest-covered
  like any other listed member when present.

## 5. Manifest

```json
{
  "bundle_spec_version": "oept-bundle/0.1",
  "bundle_id": "report-2026-001",
  "created_at": "2026-01-01T00:00:00Z",
  "key_id": "ops-key-2026",
  "files": [
    {"path": "evidence/a.txt", "sha256": "<64 hex>", "size_bytes": 123}
  ]
}
```

Rules:

1. `bundle_spec_version` MUST be exactly `oept-bundle/0.1` for this
   version of the spec. Unknown versions → `UNSUPPORTED_SPEC_VERSION`.
2. `files` MUST be sorted by `path` (byte order). Builders MUST sort;
   verifiers MUST NOT require sorting (they compare as sets).
3. `sha256` is lowercase hex SHA-256 over the exact member bytes.
4. `size_bytes` is informative; digest equality is authoritative.
5. The manifest MUST NOT list itself (`manifest.json`).
6. The manifest MUST NOT list `signatures/manifest.sig` (envelope rule,
   §6). It SHOULD list `signatures/key-info.json` when present, binding
   the claimed key label to the signed payload.
7. No duplicate `path` values. Duplicate → `MALFORMED_BUNDLE`.
8. Every listed path MUST satisfy the path rules in §7.
9. `key_id`, when present, is an identification label only.
10. Unknown top-level fields are ignored by verifiers (forward
    compatibility for minor versions). Unknown fields are never
    interpreted. File entries stay strict.

## 6. Signatures (application-level, optional)

- Algorithm: Ed25519. Signed payload: the canonical (RFC 8785) bytes of
  `manifest.json` exactly as listed (excluding the signature member).
- The signature file carries raw signature bytes (64 bytes).
- Trust roots are ALWAYS caller-supplied (`--trust-keys`). A public key
  embedded in the bundle (e.g. inside `key-info.json`) is NEVER trusted
  automatically, even when its bytes match the signing key.
- Outcomes: `VALID_SIGNED` (verified against a named trusted key),
  `SIGNATURE_INVALID` (present but matches nothing supplied),
  `SIGNATURE_KEY_UNKNOWN` (signed bundle, no trust roots supplied),
  unsigned bundles report `VALID_UNSIGNED` with an explicit no-signature
  note when digests are intact.
- These signatures assert bundle authorship/integrity at the application
  layer. They are NOT qualified electronic signatures, NOT eIDAS
  instruments, NOT timestamps, NOT certificate chains.

## 7. Path rules (builders and verifiers)

A member path is safe iff ALL hold:

- non-empty, length ≤ 512
- no NUL byte
- relative (no leading `/`, no Windows drive `X:` prefix)
- no backslash `\` anywhere
- no empty, `.`, or `..` segments

Violations in archive structure → `UNSAFE_ARCHIVE`. Violations inside a
listed manifest path → `MALFORMED_BUNDLE`. Symlink entries are always
rejected (`UNSAFE_ARCHIVE`).

## 8. Reproducibility

Identical logical inputs (same member paths + bytes + bundle_id +
created_at) produce identical manifest bytes on any platform — asserted
by test. Complete-ZIP-byte identity additionally depends on the
Python/zlib ZIP implementation and is asserted only for same-interpreter
round-trips. OEPT claims manifest-level determinism portably, and
whole-archive determinism on a fixed toolchain. No stronger claim.

## 9. Resource limits (defaults, all configurable)

- `MAX_ENTRIES = 10_000`
- `MAX_TOTAL_UNCOMPRESSED_BYTES = 512 MiB`
- `MAX_SINGLE_MEMBER_BYTES = 64 MiB`

Exceeding any limit fails verification as `UNSAFE_ARCHIVE` (expansion
abuse is a safety failure, not a content failure).

## 10. Verification algorithm (normative order)

1. Open the archive (unreadable → `MALFORMED_BUNDLE`).
2. Inspect member names before reading content.
3. Duplicates → `UNSAFE_ARCHIVE`.
4. Unsafe paths/symlinks → `UNSAFE_ARCHIVE`.
5. Entry/size limits → `UNSAFE_ARCHIVE`.
6. Require `manifest.json` → else `MALFORMED_BUNDLE`.
7. Parse JSON → else `MALFORMED_BUNDLE`.
8. Validate manifest schema → else `MALFORMED_BUNDLE`.
9. Check spec version → else `UNSUPPORTED_SPEC_VERSION`.
10. Declared-vs-actual set comparison (signature envelope recognized) →
    `MISSING_FILE` / `UNEXPECTED_FILE`.
11. Recompute every digest → `HASH_MISMATCH` on any difference.
12. Signature step → `VALID_SIGNED` / `SIGNATURE_INVALID` /
    `SIGNATURE_KEY_UNKNOWN` / `VALID_UNSIGNED`.
13. Members are read from ZIP streams; verifiers MUST NOT extract to
    arbitrary filesystem paths.
14. Verifiers MUST reject files with bytes outside the central-directory
    envelope (leading garbage, trailing data, gaps): such bytes are
    invisible to ZIP readers, so a file carrying them must never verify
    cleanly. Legitimate ZIP comments remain valid.

## 11. Versioning

Spec versions are `oept-bundle/<major>.<minor>`. Verifiers accept the
exact versions they implement and reject everything else as
`UNSUPPORTED_SPEC_VERSION`. Minor versions may only ADD optional
members; required-member or digest-model changes require a major bump.
