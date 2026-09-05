# Open Evidence Provenance Toolkit (OEPT)

Small, dependency-light infrastructure for **evidence provenance**:
prove *which exact source version produced which claim*, and let any
third party verify the package **offline** — without trusting your servers.

```
source bytes → content digest → provenance metadata → portable bundle → offline verification
```

## The problem

Software and data pipelines transform source files through parsing,
normalization, mappings, validation, and deterministic controls. Downstream
users — auditors, integrators, regulators, customers — frequently cannot
independently determine which source object produced a claim, which exact
version was used, which transformation ran, when it was observed, whether
the source changed later, or whether an exported package was modified.

OEPT provides reusable primitives for that chain:
content-addressed evidence objects, append-only observation history,
deterministic canonicalization, portable signed bundles, and an offline
verifier. The project emerged from work on evidence-intensive systems
including financial and regulatory workflows, but OEPT itself is
domain-neutral: it works with arbitrary data files.

## Trust boundary (read first)

OEPT proves: bundle structure, member presence, SHA-256 integrity,
manifest integrity, safe archive structure, Ed25519 signature validity,
supplied trusted-key identity.

OEPT never claims: factual truth, commercial truth, legal validity,
compliance approval, fraud detection, eIDAS qualification, timestamps,
certificate chains, or malware-free status.

## Quickstart

```bash
pip install -e .
oept verify examples/valid-unsigned.zip
```

Expected output:

```
Bundle: examples/valid-unsigned.zip
Specification: oept-bundle/0.1
Structure: VALID
Member digests: VALID
Signature: NOT PRESENT
Result: VALID_UNSIGNED

Technical verification only — not a legal, compliance, or factual conclusion.
```

Build a bundle from a prepared directory (containing `facts.json`,
`provenance.json`, and `evidence/`):

```bash
oept bundle examples/evidence-project --output my-evidence.zip
oept verify my-evidence.zip --json
```

Signed bundles:

```bash
oept bundle DIR --output signed.zip --sign my-key.pem --key-id ops-2026
oept verify signed.zip --trust-keys trust-keys.json
```

Trust roots always come from `--trust-keys`. Keys embedded in a bundle
are identification labels only and are never trusted automatically.

## Bundle anatomy (oept-bundle/0.1)

Required: `manifest.json`, `facts.json`, `provenance.json`, `evidence/`.
Optional: `metadata/`, `rule_traces.json`, `signatures/manifest.sig`,
`signatures/key-info.json`, `SUMMARY.txt`.
Full rules: `spec/bundle-spec.md`.

Verification statuses: `VALID_SIGNED`, `VALID_UNSIGNED`, `HASH_MISMATCH`,
`MISSING_FILE`, `UNEXPECTED_FILE`, `SIGNATURE_INVALID`,
`SIGNATURE_KEY_UNKNOWN`, `UNSUPPORTED_SPEC_VERSION`, `UNSAFE_ARCHIVE`,
`MALFORMED_BUNDLE`.

## Relationship to existing standards

OEPT complements rather than replaces: in-toto, SLSA, Sigstore, W3C PROV,
RO-Crate, SCITT, SPDX, CycloneDX. None of these today gives field-level
source-bytes→claim lineage in one stdlib-friendly offline bundle without
a daemon, OIDC, RDF store, or log operator — that narrow gap is OEPT's
reason to exist. Interoperability adapters (in-toto statement emission,
PROV export) are planned grant work; v0.1 claims no compatibility beyond
its own spec. See `docs/roadmap.md`.

## Roadmap

- v0.1 (this release): schemas, SDK core (canonical/hash/bundle/verify),
  CLI, conformance corpus, specs.
- Grant work (planned): EvidenceStore (SQLite), source-mapping profiles,
  rule-trace emitter, snapshot pinning, W3C PROV + in-toto exporters,
  transparency-log anchoring study.

## Security reporting

See SECURITY.md. Until a dedicated project security address is published,
report privately through the repository hosting platform's security
advisory mechanism.

## License

Apache-2.0. See LICENSE.
