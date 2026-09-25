<div align="center">

# agent-mandates

### Provable authority for AI agents

[![PyPI](https://img.shields.io/pypi/v/agent-mandates?color=blue)](https://pypi.org/project/agent-mandates/)
[![License](https://img.shields.io/pypi/l/agent-mandates?color=success)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/agent-mandates?logo=python&logoColor=white)](https://pypi.org/project/agent-mandates/)
[![CI](https://img.shields.io/github/actions/workflow/status/Oluwatemmy/agent-mandates/ci.yml?branch=main&label=CI&logo=github)](https://github.com/Oluwatemmy/agent-mandates/actions/workflows/ci.yml)

---

Who authorized an AI agent to do something, whether it stayed inside those
bounds, and what it cost when it did not.

[Specification](FORMAT.md) &bull; [Changelog](CHANGELOG.md) &bull; [Security](SECURITY.md) &bull; [Contributing](CONTRIBUTING.md)

</div>

---

Three linked documents, each signed by the party actually making the claim:

- **Mandate** — signed by a principal, granting one named agent a scope, a
  ceiling and an expiry. An agent may pass authority on, but only narrowed: a
  delegated grant can never widen what it received.
- **Action receipt** — signed by the agent when it acts, bound by hash to the
  mandate it acted under.
- **Outcome attestation** — signed later and bound by hash to that receipt.
  What actually happened: completed, disputed, refunded, reversed, and any loss.

Because a grant is signed by whoever granted it rather than whoever used it, a
verifier checks an agent's authority against its principal instead of taking the
agent's word for it. Verification needs only the published public keys, never
access to the issuer.

## Install

```sh
pip install agent-mandates
```

Python 3.11+. Depends on `pydantic` and `cryptography`, nothing else.

## Issue a grant, act under it, attest the outcome

```python
# Alice grants her shopping agent authority to charge up to 200 USD.
mandate = Mandate(
    id=new_mandate_id(),
    issued_at=now,
    principal=alice,
    agent=shopper,
    scope=("payment.charge",),
    expires_at=now + timedelta(days=30),
    max_value=Money(amount=Decimal("200.00"), currency="USD"),
)

# The agent charges 79.99. receipt_under commits to the grant by hash, so the
# binding cannot be mistyped.
receipt = receipt_under(
    mandate,
    action=Action(
        type="payment.charge",
        target="https://shop.example.com/v1/orders",
        params_hash=...,
        value=Money(amount=Decimal("79.99"), currency="USD"),
    ),
    decision=Decision(outcome=DecisionOutcome.ALLOW),
    issued_at=now + timedelta(minutes=2),
)

# Two days later the merchant attests what happened.
outcome = outcome_for(receipt, status=OutcomeStatus.COMPLETED, issued_at=now + timedelta(days=2))

envelope = sign(mandate, "alice", alice_key)
```

[`examples/walkthrough.py`](examples/walkthrough.py) is the whole flow, runnable.
The test suite executes it, so it cannot drift from the library.

## Ask before acting

The same check reads just as well *before* an action as after it. An agent that
consults its own grant stops a runaway loop at the second call instead of the
five-hundredth:

```python
from agent_mandates.scope import permits

refusals = permits(grant, proposed_action, at=datetime.now(UTC))
if refusals:
    ...  # stop, and ask a human
```

```console
$ python examples/preflight.py
grant: video.generate, up to 200 USD, expires in 2 hours

the batch that was asked for   go ahead
the loop that ran away         STOP
                               - the action's value is above the mandate's limit
reaching into local files      STOP
                               - the action type is not in the mandate's scope
```

This is **not enforcement**. Nothing here sits between an agent and the thing it
is calling, and an agent that lies about what it did will not honestly ask
permission first. It catches the honest failures — a loop that misread its
instructions, a job retried until it drained a budget — which are most of them.

For the rest, the point of a signed grant is that somebody else can enforce it:
a framework, a proxy, or the provider taking the requests. The grant is portable
evidence of what was permitted, whoever ends up refusing.

## Did it show you everything?

A receipt proves what it records and says nothing about what is missing. Link
each one to the agent's previous action and a run becomes a sequence, so a
selective subset cannot be presented as the whole story:

```console
$ mandates sequence run/*.json --keys jwks.json
#0         rcpt_0123... signed by shopper
#1         rcpt_aaaa... signed by shopper
sequence   intact, 2 receipt(s)
result     VERIFIED
```

Pass `prev=` to `receipt_under` and the link is built for you. It catches
deletion and reordering within what you were handed. It cannot catch an agent
that simply stopped recording — nothing here is outside the agent's control.

## Verify

Anyone holding the published keys can check the chain:

```console
$ mandates verify outcome.json --keys jwks.json \
      --receipt receipt.json --mandate mandate.json

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

Exit codes are `0` verified, `1` not verified, `2` bad input, so the three cases
can be told apart in a script. `--require KEY_ID` fails unless a particular key
signed. Repeat `--mandate`, root first, to check a delegation chain.

### Keys that carry themselves

An agent's keypair is usually generated per deployment, and registering it
somewhere before the agent can act is friction with no payoff. Name it with a
[`did:key`](https://w3c-ccg.github.io/did-key-spec/) identifier instead and the
public key travels inside the id, so `--keys` becomes optional:

```console
$ mandates verify receipt.json
agent      agent:shopper using did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd
...
signed by  did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd [self-described]
result     VERIFIED
```

```python
from agent_mandates.keys import KeyDirectory, public_key_to_did
from agent_mandates.signing import author_signed

key_id = public_key_to_did(private_key.public_key())
author_signed(envelope, KeyDirectory())  # nothing to look the key up in
```

`[self-described]` is the important part of that output. It means the signature
came from the key named in the id — not that the key belongs to anyone you know.
Anyone can mint a `did:key` in a microsecond, so a *principal* still has to be
someone you recognise; a directory is what says whose key it is. It is the
*agent* side where this pays off.

## What it does not do

**It verifies documents, not the world they describe.** An agent signs its own
account of what it did, and nothing here compares that account to reality. A
receipt saying an agent charged 79.99 is evidence that the agent *claimed* that,
under authority its principal *did* grant. It is not evidence the charge
happened.

Key management is deliberately out of scope: generating, storing, rotating and
revoking private keys is left to you.

## The format

The wire format is specified in [FORMAT.md](FORMAT.md) — canonicalization,
signing boundary, binding, attenuation — and pinned by golden vectors in
[`tests/vectors/`](tests/vectors), which carry fixed key seeds so an
implementation in another language can reproduce the same signature bytes.

Verified on Linux, macOS and Windows across Python 3.11, 3.12 and 3.13, which
ship different Unicode tables and must still agree on canonical bytes.

## Development

```sh
python -m pip install -e ".[dev]"
python -m pytest
```

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Security
reports: [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Ajayi Oluwaseyi Temitope.

Apache-2.0 rather than MIT for its explicit patent grant: this format is meant
to be implemented by other parties, who need assurance that no patent claim will
be asserted over it later.
