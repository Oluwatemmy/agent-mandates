# agent-receipts

Signed, independently verifiable records of what an AI agent did and what
happened as a result.

Three linked documents:

- **Mandate** — signed by a principal, granting one named agent a scope, a
  ceiling and an expiry.
- **Action receipt** — signed by the agent when it acts, bound by hash to the
  mandate it acted under.
- **Outcome attestation** — signed later and bound by hash to that receipt.
  What actually happened: completed, disputed, refunded, reversed, and any loss.

Each is signed by the party making the claim, so a verifier checks a grant
against whoever granted it rather than whoever used it.

Verification requires only the issuer's public key. It never requires access to
the issuer's systems.

## Status

Documents can be signed and independently verified today. What remains is the
work that makes a receipt mean something beyond "this was signed": binding an
outcome to its receipt, checking an action against its mandate, and walking
delegation chains.

The wire format is specified in [FORMAT.md](FORMAT.md) and pinned by golden
vectors in `tests/vectors/`, which carry fixed key seeds so another
implementation can reproduce the same signature bytes.

- [x] Document format
- [x] Canonical values and canonical JSON
- [x] Canonical bytes (RFC 8785)
- [x] Ed25519 signing and verification
- [x] Verifier CLI
- [x] Outcome binding
- [x] Mandate scope checking
- [x] Principal-signed mandates
- [x] Delegation chains
- [ ] Hardening: CI matrix, property-based tests, parser fuzzing
- [ ] Publish to PyPI

## Verifying

    receipts verify envelope.json --keys jwks.json

Prints what the document claims and which keys signed it, then VERIFIED or
NOT VERIFIED. Exit codes are 0 verified, 1 not verified, 2 bad input, so the
three cases can be told apart in a script.

Use `--require KEY_ID` (repeatable) to fail unless a particular key signed.

To check a whole chain, pass the documents it rests on:

    receipts verify outcome.json --keys jwks.json         --receipt receipt.json --mandate mandate.json

Repeat `--mandate`, root first, to check a delegation chain. Each grant must
narrow what it received, and the chain must lead back to one principal:

    receipts verify receipt.json --keys jwks.json         --mandate root-grant.json --mandate sub-grant.json

Verification needs only the public key directory, never access to the issuer.

## Development

    python -m pip install -e ".[dev]"
    python -m pytest

## License

Copyright 2026 Ajayi Oluwaseyi Temitope.

Licensed under the Apache License, Version 2.0. Apache-2.0 rather than MIT for
its explicit patent grant: this format is meant to be implemented by other
parties, who need assurance that no patent claim will be asserted over it later.
