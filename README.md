# agent-receipts

Signed, independently verifiable records of what an AI agent did and what
happened as a result.

Two linked documents:

- **Action receipt** — signed when an agent acts. Who acted, on whose
  authority, under what mandate, what they did, and whether it was allowed.
- **Outcome attestation** — signed later and bound to that receipt. What
  actually happened: completed, disputed, refunded, reversed, and any loss.

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
- [ ] Outcome binding
- [ ] Mandate scope checking
- [ ] Delegation chains

## Verifying

    receipts verify envelope.json --keys jwks.json

Prints what the document claims and which keys signed it, then VERIFIED or
NOT VERIFIED. Exit codes are 0 verified, 1 not verified, 2 bad input, so the
three cases can be told apart in a script.

Use `--require KEY_ID` (repeatable) to fail unless a particular key signed.
Verification needs only the public key directory, never access to the issuer.

## Development

    python -m pip install -e ".[dev]"
    python -m pytest

## License

Copyright 2026 Ajayi Oluwaseyi Temitope.

Licensed under the Apache License, Version 2.0. Apache-2.0 rather than MIT for
its explicit patent grant: this format is meant to be implemented by other
parties, who need assurance that no patent claim will be asserted over it later.
