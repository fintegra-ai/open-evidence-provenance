# OEPT Threat Model (v0.1)

Scope: the `oept-bundle/0.1` format, the builder, and the offline
verifier. Out of scope: producer infrastructure, key management
operations, transport security, host security.

## Attacker capabilities assumed

The attacker can produce arbitrary bundles, modify bundles in transit
or at rest, and submit malicious archives to a verifier.

## Threats addressed (each maps to a verifier status)

1. Evidence bytes modified after bundling → detected by per-file
   SHA-256 recomputation (`HASH_MISMATCH`).
2. Manifest modified (digests weakened, members dropped) → manifest is
   outside its own file table, so any change alters the signed payload;
   unsigned bundles still expose the change through digest mismatch
   against independently retained digests; dropped declarations change
   the declared set (`MISSING_FILE` only fires for declared-but-absent;
   manifest edits that remove declarations are detectable only by
   holders of the original manifest hash or a signature —
   see Residual risks).
3. Extra file inserted → `UNEXPECTED_FILE` (or digest failure if the
   attacker also edits the manifest without re-signing).
4. Required file removed → `MISSING_FILE`.
5. Signature substituted or stripped → `SIGNATURE_INVALID`, or the
   bundle degrades to `VALID_UNSIGNED` with an explicit no-signature
   note (callers that require signatures MUST treat unsigned as failure;
   the CLI exit code distinguishes only integrity, policy is the
   caller's).
6. Attacker supplies their own embedded key → never trusted
   (`SIGNATURE_KEY_UNKNOWN` without caller trust roots; verification
   succeeds only against caller-supplied keys, reported by key_id).
7. Malicious ZIP paths (`../`, absolute, drive-letter, backslash, NUL,
   symlink, duplicates) → `UNSAFE_ARCHIVE` before any content read.
8. Archive expansion / resource exhaustion → entry-count, total-size,
   and single-member limits → `UNSAFE_ARCHIVE`.

## Explicit non-goals (the verifier MUST NOT claim these)

- Truth of source content. A valid bundle proves bytes are unchanged,
  not that they are true.
- Identity proof beyond the configured key. A signature proves control
  of a key, not who controls it in the real world.
- Non-equivocation. Without a transparency log, a signer can sign two
  contradictory bundles; both verify. (Future: SCITT anchoring.)
- Timestamp authority. `created_at` is a producer assertion.
- Legal validity, compliance approval, eIDAS/QSeal status.
- Malware detection. Evidence bytes are opaque.

## Residual risks

- Unsigned bundles rely on out-of-band manifest-hash retention for
  manifest-edit detection. Mitigation: sign bundles whenever authorship
  matters.
- Key distribution is out of band. Compromised trust-root files
  compromise verification. Mitigation: minimal trust lists, documented
  rotation (operator responsibility).
- Deterministic builds aid reproducibility but also let an attacker
  precompute expected bytes; this is not a weakness of the integrity
  model (digests still bind content).
- Side-channel or host compromise of the verifying machine is out of
  scope.

## Security-sensitive change process

Changes to canonicalization, digest model, signature coverage, path
validation, or resource limits REQUIRE: spec version consideration (§11
of bundle-spec.md), new conformance fixtures, and explicit review.
See CONTRIBUTING.md.
