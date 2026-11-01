# Changelog

All notable changes to this project are documented here. Format follows
"Keep a Changelog"; versioning is pre-1.0 (`0.x.y`, breaking changes may
land in minor releases until 1.0).

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
