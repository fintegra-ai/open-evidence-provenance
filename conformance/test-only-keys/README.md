# TEST-ONLY signing key — PUBLICLY COMPROMISED BY DEFINITION

The keypair in this directory (`conformance-test-only-signing.key` /
`.pub`) exists solely so the conformance corpus can contain a deterministic
valid-signed fixture.

- NEVER use this key for real signatures.
- NEVER name it production/real/institution anywhere.
- It is committed to the repository ON PURPOSE so fixtures verify
  deterministically; that is exactly what makes it unsuitable for any
  trust purpose.
- Real deployments generate their own keys and distribute trust roots
  out of band (see `oept verify --trust-keys`).
