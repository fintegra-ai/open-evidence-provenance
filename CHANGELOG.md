# Changelog

All notable changes to this project are documented here. Format follows
"Keep a Changelog"; versioning is pre-1.0 (`0.x.y`, breaking changes may
land in minor releases until 1.0).

## [Unreleased]

### Fixed

- The builder requires evidence members, matching the existing verifier/spec.
- Directory verification rejects symlink roots; directory bundling checks
  symlinks before treating them as directories.
- CLI digest reporting says NOT EVALUATED when structural checks terminate
  verification, rather than presenting unexecuted digest checks as VALID.

## [0.1.2] — 2026-11-02


### Fixed

- Validate manifest field types and strict file entries before consuming them;
  reject bundles lacking facts, provenance, or evidence even when undeclared.
- Fail closed on encrypted members, corrupt CRC/compression, malformed JSON,
  and byte-API archive size violations. Builder rejects Windows drive paths.
- Five permanent negative conformance vectors extend the OEPT corpus to 15.


### Added

- Normative bundle-format draft `spec/OEPT-1.0-draft.md` (RFC 2119,
  MUST→test traceability, versioning policy, non-guarantees) and
  SECURITY.md notes: explicit non-vulnerability of the test-only conformance
  keypair and the fuzz→vector closure rule.
- Issue template `fuzz-finding.yml`: fuzz findings cannot be closed without
  a permanent negative conformance vector (Faz C rule).

## [0.1.1] — 2026-11-01

### Changed

- Package metadata: `project.urls` now points at the real repository
  (github.com/fintegra-ai/open-evidence-provenance) instead of the provisional
  `example.invalid` placeholders. (Schema `$id` namespaces remain provisional
  by design; see CONTRIBUTING.md.)

### Added

- `VerifierOptions.max_archive_bytes` (default 512 MiB): `verify_bundle`
  rejects an archive file exceeding the limit *before* reading it into memory
  (`UNSAFE_ARCHIVE`), bounding memory consumption on hostile oversized inputs;
  the decompressed-size limits alone could not bound this path.

## [0.1.0] — 2026-09-05

Initial public release:

- Versioned JSON Schemas (7): evidence-object, evidence-version,
  provenance-pointer, fact, rule-trace, bundle-manifest,
  verification-result.
- Deterministic bundle builder (`oept-bundle/0.1`) with canonical
  manifest, sorted members, fixed timestamps.
- Offline verifier with ten terminal statuses, ZIP-safety guards
  (traversal/symlink/duplicate/count/size), and Ed25519 trust model
  (caller-supplied trust roots only; embedded keys never trusted).
- CLI: `bundle`, `verify` (human + JSON), `conformance`, `schema`.
- Conformance corpus: 10 fixtures with expected results.
- Specifications: bundle-spec.md, threat-model.md.
