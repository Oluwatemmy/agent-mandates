# Changelog

Package versions and format versions are separate. This file tracks **package**
releases; the version in a document's `v` field tracks the **wire format**, and
a release that fixes a bug without touching the format will not change it.

## 0.2.0 — unreleased

Implements **format 0.2**.

### Added

- **Linked receipts.** A receipt may carry `prev` and `prev_hash`, committing to
  the agent's previous action, so a run is a sequence rather than a pile.
  Without it a receipt proves what it records and says nothing about what is
  missing — an agent that made five hundred calls and kept receipts for
  fifty-nine would pass every other check. `sequence_problems` reports gaps,
  reordering and splices, per position. It cannot catch an agent that simply
  stopped recording; that needs an anchor outside the agent's control.
- `mandates sequence` — check a run of receipts for gaps from the command line.
- **Cited evidence.** An outcome attestation may carry `evidence`: artifacts
  from outside this format — a provider's report, a settlement record — each a
  kind, a source and a digest over the artifact's own bytes. It pins the
  attester to one specific artifact rather than proving what that artifact says,
  and moves an outcome from the observer's say-so to a commitment somebody
  holding the original can check. A counterparty willing to sign should
  countersign the envelope instead, which is stronger and already supported.
- `permits` — the scope check, asked before acting rather than after. Same
  rules, and not enforcement: nothing sits between an agent and what it calls.

### Changed

- **An action under a ceiling must state what it cost**, and a free one states
  zero. Previously an action with no value was treated as not engaging the
  limit, which left a one-line way around the only number in the grant: omit
  the value and spend anything. Reported as `value_not_stated`.
- **An empty chain or run is refused rather than reported as sound.**
  `chain_problems([])` and `sequence_problems([])` returned no positions, and
  `any(())` is false, so the idiomatic check read "there is nothing here" as
  "nothing is wrong". `accountable_principal` already refused the same input.
- Format version 0.2. Receipts gained two optional fields, so documents signed
  under 0.1 do not validate against 0.2 and vice versa.

## 0.1.0 — 2026-09-23

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
