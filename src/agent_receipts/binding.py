"""Binding documents to the documents they refer to.

Two documents that each verify on their own still say nothing as a pair. A
reference by id proves only that somebody typed that string, because ids are
chosen by whoever issues them. Binding closes that: the referring document
commits to the referenced document's canonical bytes.

There are two pairings:

- a **receipt** to the **mandate** it was taken under, which is what makes the
  agent's claimed authority checkable against the principal who granted it
- an **outcome** to the **receipt** it reports on, which is what turns two
  signed documents into a record of a transaction's full lifecycle

In both, two kinds of check are reported together, and the distinction matters
when reading a failure. **Cryptographic** checks involve no judgement: the
commitment either holds or it does not, and a mismatch means you are holding the
wrong document. **Coherence** checks ask whether the pair describes something
that could have happened; a failure there means the documents are wrong about
each other.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum

from agent_receipts.canonical import canonical_bytes
from agent_receipts.models import (
    Action,
    ActionReceipt,
    Decision,
    DecisionOutcome,
    DisputeResolution,
    Mandate,
    Money,
    OutcomeAttestation,
    OutcomeStatus,
    new_outcome_id,
    new_receipt_id,
)


class MandateProblem(StrEnum):
    MANDATE_ID_MISMATCH = "mandate_id_mismatch"
    MANDATE_HASH_MISMATCH = "mandate_hash_mismatch"
    GRANTED_TO_ANOTHER_AGENT = "granted_to_another_agent"
    GRANTED_BY_ANOTHER_PRINCIPAL = "granted_by_another_principal"
    ACTION_PRECEDES_MANDATE = "action_precedes_mandate"


class BindingProblem(StrEnum):
    RECEIPT_ID_MISMATCH = "receipt_id_mismatch"
    RECEIPT_HASH_MISMATCH = "receipt_hash_mismatch"
    OUTCOME_PRECEDES_ACTION = "outcome_precedes_action"
    ACTION_WAS_REFUSED = "action_was_refused"


MANDATE_PROBLEM_DESCRIPTIONS = {
    MandateProblem.MANDATE_ID_MISMATCH: "the receipt names a different mandate",
    MandateProblem.MANDATE_HASH_MISMATCH: "the receipt commits to different mandate content",
    MandateProblem.GRANTED_TO_ANOTHER_AGENT: "the mandate was granted to a different agent",
    MandateProblem.GRANTED_BY_ANOTHER_PRINCIPAL: "the mandate was granted by a different principal",
    MandateProblem.ACTION_PRECEDES_MANDATE: "the action was taken before the mandate was granted",
}

PROBLEM_DESCRIPTIONS = {
    BindingProblem.RECEIPT_ID_MISMATCH: "the outcome names a different receipt",
    BindingProblem.RECEIPT_HASH_MISMATCH: "the outcome commits to different receipt content",
    BindingProblem.OUTCOME_PRECEDES_ACTION: "the outcome is dated before the action it reports on",
    BindingProblem.ACTION_WAS_REFUSED: "the receipt records a refused action, which has no outcome",
}


def mandate_digest(mandate: Mandate) -> str:
    """The value a receipt commits to when it binds to this mandate."""
    return "sha256:" + hashlib.sha256(canonical_bytes(mandate)).hexdigest()


def receipt_digest(receipt: ActionReceipt) -> str:
    """The value an outcome commits to when it binds to this receipt."""
    return "sha256:" + hashlib.sha256(canonical_bytes(receipt)).hexdigest()


def mandate_problems(mandate: Mandate, receipt: ActionReceipt) -> frozenset[MandateProblem]:
    """Everything wrong with this grant and the action claiming it."""
    problems = set()

    if receipt.mandate_id != mandate.id:
        problems.add(MandateProblem.MANDATE_ID_MISMATCH)
    if receipt.mandate_hash != mandate_digest(mandate):
        problems.add(MandateProblem.MANDATE_HASH_MISMATCH)
    # Compared whole rather than by id, so that a grant cannot be claimed by an
    # agent sharing an id but presenting a different signing key.
    if receipt.agent != mandate.agent:
        problems.add(MandateProblem.GRANTED_TO_ANOTHER_AGENT)
    if receipt.principal != mandate.principal:
        problems.add(MandateProblem.GRANTED_BY_ANOTHER_PRINCIPAL)
    if receipt.issued_at < mandate.issued_at:
        problems.add(MandateProblem.ACTION_PRECEDES_MANDATE)

    return frozenset(problems)


def binding_problems(
    receipt: ActionReceipt, outcome: OutcomeAttestation
) -> frozenset[BindingProblem]:
    """Everything wrong with this pair, or an empty set if they belong together.

    Deliberately not a boolean, and deliberately not first-failure: a caller
    reporting a broken pair needs to say what is broken, and stopping at the
    first problem would hide the others.
    """
    problems = set()

    if outcome.receipt_id != receipt.id:
        problems.add(BindingProblem.RECEIPT_ID_MISMATCH)
    if outcome.receipt_hash != receipt_digest(receipt):
        problems.add(BindingProblem.RECEIPT_HASH_MISMATCH)
    if outcome.issued_at < receipt.issued_at:
        problems.add(BindingProblem.OUTCOME_PRECEDES_ACTION)
    if receipt.decision.outcome is DecisionOutcome.DENY:
        problems.add(BindingProblem.ACTION_WAS_REFUSED)

    return frozenset(problems)


def receipt_under(
    mandate: Mandate,
    *,
    action: Action,
    decision: Decision,
    issued_at: datetime,
    receipt_id: str | None = None,
) -> ActionReceipt:
    """Record an action taken under a grant.

    Computes the mandate hash for the same reason outcome_for computes the
    receipt hash: a document built by hand is one transcription error away from
    being unbindable, and the error surfaces only when somebody needs it as
    evidence.
    """
    return ActionReceipt(
        id=receipt_id or new_receipt_id(),
        issued_at=issued_at,
        agent=mandate.agent,
        principal=mandate.principal,
        mandate_id=mandate.id,
        mandate_hash=mandate_digest(mandate),
        action=action,
        decision=decision,
    )


def outcome_for(
    receipt: ActionReceipt,
    *,
    status: OutcomeStatus,
    issued_at: datetime,
    resolution: DisputeResolution | None = None,
    loss: Money | None = None,
    outcome_id: str | None = None,
) -> OutcomeAttestation:
    """Attest what happened as a result of a receipted action.

    Computing the receipt hash here rather than leaving it to the caller is the
    point of this function: an outcome built by hand is one transcription error
    away from being unbindable, and the error would not surface until somebody
    tried to use the pair as evidence.
    """
    if receipt.decision.outcome is DecisionOutcome.DENY:
        raise ValueError("a refused action has no outcome to attest")

    return OutcomeAttestation(
        id=outcome_id or new_outcome_id(),
        receipt_id=receipt.id,
        receipt_hash=receipt_digest(receipt),
        issued_at=issued_at,
        status=status,
        resolution=resolution,
        loss=loss,
    )
