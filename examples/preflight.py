"""Ask the grant before acting, not after.

A mandate is usually read when something has already gone wrong. It reads just
as well beforehand: an agent that checks its own grant before each call stops a
runaway loop at the second call instead of the five-hundredth.

    python examples/preflight.py

This is not enforcement. Nothing here sits between the agent and the thing it
is calling, and an agent that lies about what it did will not honestly ask
permission first. It catches the honest failures -- a loop that misread its
instructions, a job retried until it drained a budget -- which are most of them.
"""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from agent_mandates.models import (
    Action,
    Agent,
    Mandate,
    Money,
    Principal,
    PrincipalType,
    new_mandate_id,
)
from agent_mandates.scope import VIOLATION_DESCRIPTIONS, permits

PARAMS = "sha256:" + "0" * 64


def main() -> None:
    now = datetime.now(UTC)

    # Signed once by the person whose money it is, before the run starts.
    grant = Mandate(
        id=new_mandate_id(),
        issued_at=now,
        principal=Principal(id="user:creator", type=PrincipalType.HUMAN, key_id="creator-key"),
        agent=Agent(id="agent:video-bot", key_id="bot-key"),
        scope=("video.generate",),
        expires_at=now + timedelta(hours=2),
        max_value=Money(amount=Decimal("200.00"), currency="USD"),
    )

    print(
        f"grant: {', '.join(grant.scope)}, up to {grant.max_value.amount} "
        f"{grant.max_value.currency}, expires in 2 hours\n"
    )

    proposals = [
        ("the batch that was asked for", "video.generate", "200.00"),
        ("the loop that ran away", "video.generate", "5000.00"),
        ("reaching into local files", "file.read", None),
    ]

    for label, action_type, amount in proposals:
        proposed = Action(
            type=action_type,
            target="https://api.provider.example/v1/generate",
            params_hash=PARAMS,
            value=Money(amount=Decimal(amount), currency="USD") if amount else None,
        )

        refusals = permits(grant, proposed, at=datetime.now(UTC))
        print(f"{label:<30} {'go ahead' if not refusals else 'STOP'}")
        for refusal in sorted(refusals):
            print(f"{'':<30} - {VIOLATION_DESCRIPTIONS[refusal]}")

    print(
        "\nA refusal is the moment to stop and ask a human. Whatever happens next,"
        "\nrecord it with receipt_under so the decision is evidence rather than memory."
    )


if __name__ == "__main__":
    main()
