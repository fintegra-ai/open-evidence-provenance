# Changelog

All notable changes to this project are documented here. Format follows
"Keep a Changelog"; versioning is pre-1.0 (`0.x.y`, breaking changes may
land in minor releases until 1.0).

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
