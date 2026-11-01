# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Pre-1.0 software: the API and bundle spec may change. Security fixes are
backported only to the latest 0.1.x release.

## Reporting a vulnerability

Until a dedicated project security address is published, report privately
through the repository hosting platform's security advisory mechanism.
Do not open public issues for suspected vulnerabilities.

What to include: affected version, bundle/spec area, reproduction steps
(preferably a minimal bundle or script), and impact assessment.

## Responsible disclosure expectations

- We acknowledge receipt within 5 business days.
- We aim to ship a fix and credit the reporter within 30 days for
  confirmed issues, sooner for critical archive-safety or signature
  verification flaws.
- Please do not disclose details publicly before a fix is released.

## Scope notes

The verifier is a technical integrity check (structure, digests,
signatures). It does not detect malicious *content*, does not validate
legal meaning, and does not establish real-world identity beyond
caller-configured trust roots. See `spec/threat-model.md` for the full
threat model and explicit non-goals.

## Explicit non-vulnerabilities

- The committed keypair in `conformance/test-only-keys/` is PUBLICLY
  COMPROMISED BY DEFINITION (see its README) and exists solely to keep the
  signed conformance fixture deterministic. Reports about that keypair are
  not security findings.
- Fuzz crashes are converted into permanent negative conformance vectors
  (Faz C rule) before the fixing issue is closed; a fixed crash without a
  vector is treated as an incomplete fix in review.

