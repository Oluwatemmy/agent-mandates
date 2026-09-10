"""Binding an outcome attestation to the receipt it reports on.

Two documents that each verify on their own still say nothing as a pair. An
outcome names a receipt id, but ids are chosen by whoever issues them, so the
reference alone proves nothing about which receipt is meant. Binding closes
that gap.

There are two distinct kinds of check here, and conflating them would be a
mistake:

- **Cryptographic binding** is the receipt hash. Either the outcome commits to
  exactly these receipt bytes or it does not, and no judgement is involved.
- **Coherence** is whether the pair describes something that could have
  happened. An outcome dated before its own action, or reporting a transaction
  for an action that was refused, is incoherent however well it verifies.

Both are reported together because a caller needs to act on either, but the
distinction matters when reading a failure: a hash mismatch means you are
holding the wrong receipt, while an incoherent pair means the documents are
wrong about each other.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum

from agent_receipts.canonical import canonical_bytes
from agent_receipts.models import (
    ActionReceipt,
    DecisionOutcome,
    DisputeResolution,
    Money,
    OutcomeAttestation,
    OutcomeStatus,
    new_outcome_id,
)


class BindingProblem(StrEnum):
    RECEIPT_ID_MISMATCH = "receipt_id_mismatch"
    RECEIPT_HASH_MISMATCH = "receipt_hash_mismatch"
    OUTCOME_PRECEDES_ACTION = "outcome_precedes_action"
    ACTION_WAS_REFUSED = "action_was_refused"


PROBLEM_DESCRIPTIONS = {
    BindingProblem.RECEIPT_ID_MISMATCH: "the outcome names a different receipt",
    BindingProblem.RECEIPT_HASH_MISMATCH: "the outcome commits to different receipt content",
    BindingProblem.OUTCOME_PRECEDES_ACTION: "the outcome is dated before the action it reports on",
    BindingProblem.ACTION_WAS_REFUSED: "the receipt records a refused action, which has no outcome",
}


def receipt_digest(receipt: ActionReceipt) -> str:
    """The value an outcome commits to when it binds to this receipt."""
    return "sha256:" + hashlib.sha256(canonical_bytes(receipt)).hexdigest()


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
