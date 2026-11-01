# OEPT-1.0 (draft) — Open Evidence Provenance Toolkit Bundle Format and Verifier

Status: **draft** — normative restatement of shipped `oept-bundle/0.1`
behavior, extracted from code as Faz B of the NLnet plan v2. On release this
file becomes `OEPT-1.0`; until then the bundled schemas and the Python
reference verifier remain the source of truth for the reference behavior.
The key words MUST, MUST NOT, SHOULD, MAY are to be interpreted as described
in RFC 2119. Code license: Apache-2.0; this document: CC-BY-4.0 (see
GOVERNANCE.md in the sibling repository).

## 1. Scope

This specification defines: the `oept-bundle/0.1` evidence-bundle archive
format, its canonical JSON rules, the offline verification pipeline, the
terminal statuses, and the trust model. It does NOT define receipts,
profiles, or re-verification (see OEVP-1.0).

## 2. Bundle format

1. A bundle MUST be a ZIP archive whose first local file header starts with
   the bytes `PK\x03\x04`. [test: `test_not_a_zip`]
2. A bundle MUST contain a member `manifest.json` conforming to the bundled
   schema `bundle-manifest.schema.json` (normative artifact shipped with the
   verifier). [test: `test_malformed_manifest`, `test_unsupported_version`]
3. `manifest.json.bundle_spec_version` MUST equal `oept-bundle/0.1`. A
   verifier MUST reject unknown `spec_version` values with
   `UNSUPPORTED_SPEC_VERSION`. [test: `test_unsupported_version`]
4. Every declared member MUST be present (`MISSING_FILE` otherwise); no
   undeclared member MAY be present (`UNEXPECTED_FILE` otherwise).
   [tests: `test_missing_file`, `test_unexpected_file`]
5. The archive MUST NOT contain duplicate member names. [test:
   `test_duplicate_entry`]
6. Member names MUST NOT be empty, absolute, contain `\` or NUL, contain a
   `:`-drive segment, contain empty or `..` path segments, exceed 512
   characters, or be symlink entries. Violations MUST yield
   `UNSAFE_ARCHIVE`. [tests: `test_unsafe_path_traversal`,
   `test_unsafe_absolute_path`, `test_windows_traversal`,
   `test_symlink_entry`, `test_hostile_member_names`,
   `test_bare_directory_entry_rejected`]

## 3. Canonicalization

1. Canonical JSON MUST be RFC 8785 (JCS). [test:
   `test_canonical_json_deterministic_and_idempotent`]
2. The canonical domain is: `null`, booleans, strings, integers with
   `|n| <= 2**53 - 1`, arrays, and objects with string keys. Floats, larger
   integers, and all other types MUST be rejected, not coerced. [tests:
   `test_canonical_json_deterministic_and_idempotent` (boundary values),
   `test_duplicate_json_keys_in_manifest`]

## 3.1 Canonical JSON properties (normative)

- **Determinism**: two values that are equal as JSON data MUST produce
  identical canonical bytes, regardless of object key insertion order.
- **Idempotency**: canonicalizing the parsed canonical output MUST be a
  fixed point.
- **Fail-closed domain**: a value outside the domain MUST raise a
  canonicalization error; silent rounding or reformatting MUST NOT occur.

## 4. Resource limits

A verifier MUST enforce, at minimum: maximum entry count (default 10,000),
maximum total uncompressed size (default 512 MiB), maximum single member
size (default 64 MiB), and maximum archive file size before reading the
archive into memory (default 512 MiB). Exceeding any limit MUST yield
`UNSAFE_ARCHIVE`. [tests: `test_entry_count_limit`, `test_member_size_limit`,
`test_archive_file_size_limit`, `test_configurable_limits_enforced`]

## 5. Verification pipeline

A conforming verifier MUST evaluate, in order, and MUST stop at the first
failing step: (1) readable archive; (2) member-name safety; (3) duplicates;
(4) symlinks; (5) resource limits; (6) manifest presence and schema
validation; (7) spec version support; (8) declared-vs-actual member set;
(9) per-member SHA-256 recomputation (`HASH_MISMATCH` on any difference);
(10) Ed25519 signature over the canonical manifest bytes when a signature
member is present. Members MUST be read from ZIP streams; extraction to
arbitrary filesystem paths MUST NOT happen. [tests:
`test_valid_unsigned`, `test_valid_signed`, `test_tampered_evidence`,
`test_trailing_data_after_central_directory`,
`test_leading_data_before_first_record`]

## 6. Terminal statuses

`UNSAFE_ARCHIVE`, `MALFORMED_BUNDLE`, `UNSUPPORTED_SPEC_VERSION`,
`MISSING_FILE`, `UNEXPECTED_FILE`, `HASH_MISMATCH`, `SIGNATURE_INVALID`,
`SIGNATURE_KEY_UNKNOWN`, `VALID_SIGNED`, `VALID_UNSIGNED`. A verifier MUST
report exactly one terminal status per bundle.

## 7. Trust model

1. Signature verification keys MUST come exclusively from caller-supplied
   trust roots (`--trust-keys`). [tests: `test_valid_signed`,
   `test_wrong_trusted_key`]
2. Keys embedded in the bundle or manifest MUST be treated as untrusted
   labels and MUST NOT satisfy trust. [test: `test_embedded_key_not_trusted`,
   `test_unknown_signing_key`]
3. `SIGNATURE_KEY_UNKNOWN` MUST be reported when a bundle is signed but no
   caller trust root matches; this is distinct from `SIGNATURE_INVALID`.

## 8. Versioning policy

| Bundle `bundle_spec_version` | Verifier of a later spec | Behavior |
| :--- | :--- | :--- |
| `oept-bundle/0.1` | 0.1 / 1.0 | accept |
| unknown future version | any | reject with `UNSUPPORTED_SPEC_VERSION` |

Removing support for an old `spec_version` is a breaking change and MUST be
announced in the CHANGELOG and GOVERNANCE process.

## 9. What this specification does NOT guarantee

- That the evidence content is true, complete, or lawful.
- That the bundle author is who they claim to be; signatures bind content to
  a key, and trust in keys is the caller's responsibility.
- That timestamps in the manifest are wall-clock-correct (they are fixed,
  deterministic values by design).
- Any property of a bundle after a verifier declares a non-valid terminal
  status.

## 10. Conformance

Conformance to OEPT-1.0 is defined by passing the published OEPT vector set
(`oept conformance`, corpus shipped with the verifier) and, for cross-
implementer claims, the OEVP conformance runner vectors. Conformance claims
are governed by GOVERNANCE.md.
