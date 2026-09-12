# Changelog

The **format version** in a document's `v` field and the **package version** are
different things. They move together before 1.0, but a release that fixes a bug
without touching the wire format will not change `v`.

## 0.3.0 — unreleased

First public release.

### Format 0.3

- Removed `prev` from action receipts. It was signed, settable and unused: a
  bare reference with no digest, which proves nothing about what it points at.
  Walking hops back to an accountable principal is done by mandate chains.

### Format 0.2

- Mandates became documents in their own right, signed by the **principal** who
  grants them rather than travelling inside the receipt that relies on them. An
  agent signing its own account of what it was permitted to do proved nothing.
- Receipts reference a mandate by id and digest, so a grant cannot be widened
  after the fact and still satisfy a receipt taken under the narrower one.
- Added delegation. An agent may pass authority on, but a delegated grant can
  never widen what it received: not in scope, ceiling, or expiry.
- Added outcome attestations bound to a receipt by digest, recording what
  happened and any loss.

### Added

- Ed25519 signing over RFC 8785 canonical bytes, with a payload-only signing
  boundary: the envelope is never signed, so rewrapping a payload cannot change
  what was signed or who signed it.
- `mandates verify` — checks signatures, outcome binding, delegation chains and
  whether an action stayed inside its mandate, using only a published JWKS.
- Golden vectors with fixed key seeds, so another implementation can reproduce
  the same signature bytes.

### Notes

- Verified on Linux, macOS and Windows across Python 3.11, 3.12 and 3.13, which
  ship different Unicode tables and must still agree on canonical bytes.
- Published previously under no name; `agent-receipts` on PyPI is an unrelated
  project.
