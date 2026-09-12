# Changelog

Package versions and format versions are separate. This file tracks **package**
releases; the version in a document's `v` field tracks the **wire format**, and
a release that fixes a bug without touching the format will not change it.

## 0.1.0 — unreleased

First release. Implements **format 0.1**.

### Documents

- **Mandate**, signed by the principal granting it and naming the single agent
  it is granted to. An agent may pass authority on, but a delegated grant can
  never widen what it received: not in scope, not in ceiling, not in expiry.
- **Action receipt**, signed by the agent, bound to its mandate by digest so a
  grant cannot be widened after the fact and still satisfy it.
- **Outcome attestation**, signed later and bound to its receipt by digest,
  recording what happened and any loss.

### Signing

- Ed25519 over RFC 8785 canonical bytes, with a payload-only signing boundary:
  the envelope is never signed, so rewrapping a payload cannot change what was
  signed or who signed it.
- Verification reports which keys signed rather than a bare boolean, because
  "valid according to whom" is the question evidence exists to answer.
- Every value reduces to one canonical form on construction, so a document
  cannot exist in a non-canonical state. Amounts are strings, never JSON
  numbers, which keeps IEEE 754 rounding out of the format entirely.

### Tooling

- `mandates verify` checks signatures, outcome binding, delegation chains and
  whether an action stayed inside its mandate, using only a published JWKS.
- Golden vectors with fixed key seeds, so another implementation can reproduce
  the same signature bytes.

### Verified on

Linux, macOS and Windows across Python 3.11, 3.12 and 3.13, which ship
different Unicode tables and must still agree on canonical bytes.

### Design notes

The format was revised twice before release: mandates moved out of the receipt
to become documents signed by the principal granting them, and an unused `prev`
field was removed. Neither revision was ever published, so the released format
is 0.1.
