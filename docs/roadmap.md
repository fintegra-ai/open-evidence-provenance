# OEPT Documentation

- Quickstart: `../README.md`
- Bundle format: `../spec/bundle-spec.md`
- Threat model: `../spec/threat-model.md`
- Schemas: `../schemas/`
- Conformance corpus: `../conformance/fixtures/` (each fixture directory
  documents its scenario through `expected-result.json`)

## Roadmap (grant work, not v0.1)

1. EvidenceStore: SQLite-backed object/version/fact history with the
   public API sketched in the architecture report.
2. Source-mapping profiles: whitelisted transforms with content hashes.
3. Rule-trace emitter: record deterministic evaluations in
   `rule_traces.json` format.
4. Snapshot pinning: ID+hash reference sets with replay against an
   injected evaluator.
5. Interoperability: in-toto Statement emission, W3C PROV-O export
   (planned; no compatibility claimed yet).
6. Transparency anchoring study: SCITT/Sigstore options analysis.
