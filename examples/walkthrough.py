"""A whole transaction, from grant to outcome, written out and verified.

Run it with an output directory:

    python examples/walkthrough.py ./out
    receipts verify ./out/outcome.json --keys ./out/jwks.json \\
        --receipt ./out/receipt.json --mandate ./out/mandate.json

The test suite runs this file, so it cannot drift from the library.
"""

import json
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_receipts.binding import outcome_for, receipt_under
from agent_receipts.keys import jwks_from_public_keys
from agent_receipts.models import (
    Action,
    Agent,
    Decision,
    DecisionOutcome,
    Mandate,
    Money,
    OutcomeStatus,
    Principal,
    PrincipalType,
    new_mandate_id,
)
from agent_receipts.signing import sign


def main(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)

    # Each party holds its own key. Nothing here manages keys for you; that is
    # deliberately somebody else's job.
    keys = {name: ed25519.Ed25519PrivateKey.generate() for name in ("alice", "shopper", "merchant")}

    alice = Principal(id="user:alice", type=PrincipalType.HUMAN, key_id="alice")
    shopper = Agent(id="agent:shopper", key_id="shopper")

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

    # The agent charges 79.99. receipt_under commits to the grant for you, so
    # the binding cannot be mistyped.
    receipt = receipt_under(
        mandate,
        action=Action(
            type="payment.charge",
            target="https://shop.example.com/v1/orders",
            params_hash="sha256:" + "0" * 64,
            value=Money(amount=Decimal("79.99"), currency="USD"),
        ),
        decision=Decision(outcome=DecisionOutcome.ALLOW, reasons=("within mandate",)),
        issued_at=now + timedelta(minutes=2),
    )

    # Two days later the merchant attests what happened.
    outcome = outcome_for(
        receipt, status=OutcomeStatus.COMPLETED, issued_at=now + timedelta(days=2)
    )

    for name, document, signer in [
        ("mandate", mandate, "alice"),
        ("receipt", receipt, "shopper"),
        ("outcome", outcome, "merchant"),
    ]:
        envelope = sign(document, signer, keys[signer])
        (destination / f"{name}.json").write_text(envelope.to_json(indent=2), encoding="utf-8")

    # Only the public half is published. That is all a verifier ever needs.
    directory = jwks_from_public_keys({name: key.public_key() for name, key in keys.items()})
    (destination / "jwks.json").write_text(json.dumps(directory, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "out"))
