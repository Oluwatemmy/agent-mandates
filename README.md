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
- [x] Hardening: CI matrix, property-based tests, parser fuzzing
- [ ] Publish to PyPI

## A whole transaction

[`examples/walkthrough.py`](examples/walkthrough.py) issues a grant, records an
action under it, attests the outcome and publishes the public keys. The test
suite runs that file, so it cannot drift from the library.

```python
# Alice grants her shopping agent authority to charge up to 200 USD.
mandate = Mandate(
    id=new_mandate_id(), issued_at=now, principal=alice, agent=shopper,
    scope=("payment.charge",), expires_at=now + timedelta(days=30),
    max_value=Money(amount=Decimal("200.00"), currency="USD"),
)

# The agent charges 79.99. receipt_under commits to the grant, so the
# binding cannot be mistyped.
receipt = receipt_under(
    mandate,
    action=Action(type="payment.charge", target="https://shop.example.com/v1/orders",
                  params_hash=..., value=Money(amount=Decimal("79.99"), currency="USD")),
    decision=Decision(outcome=DecisionOutcome.ALLOW),
    issued_at=now + timedelta(minutes=2),
)

# Two days later the merchant attests what happened.
outcome = outcome_for(receipt, status=OutcomeStatus.COMPLETED,
                      issued_at=now + timedelta(days=2))

envelope = sign(mandate, "alice", alice_key)
```

Then anyone holding the published keys can check the whole chain:

```
$ receipts verify outcome.json --keys jwks.json       --receipt receipt.json --mandate mandate.json

document   outc_70744f1f3219436cb220f281817fee60 (outcome attestation)
status     completed
signed by  merchant
receipt    rcpt_1614b59b188b4e8b8cffe7d14be710db signed by shopper
binding    OK
mandate    mndt_5533e1521b474eb5a62f310837f472a5 granted by alice
chain      OK, answering to user:alice (human)
scope      OK
result     VERIFIED
```

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
