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
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from itertools import pairwise

from agent_mandates.canonical import canonical_bytes
from agent_mandates.models import (
    Action,
    ActionReceipt,
    Decision,
    DecisionOutcome,
    DisputeResolution,
    Evidence,
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


class SequenceProblem(StrEnum):
    PREVIOUS_ID_MISMATCH = "previous_id_mismatch"
    PREVIOUS_HASH_MISMATCH = "previous_hash_mismatch"
    NOT_LINKED = "not_linked"
    FIRST_IS_LINKED = "first_is_linked"
    OUT_OF_ORDER = "out_of_order"
    DIFFERENT_AGENT = "different_agent"


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


SEQUENCE_PROBLEM_DESCRIPTIONS = {
    SequenceProblem.PREVIOUS_ID_MISMATCH: "the receipt names a different predecessor",
    SequenceProblem.PREVIOUS_HASH_MISMATCH: "the receipt commits to different predecessor content",
    SequenceProblem.NOT_LINKED: "the receipt does not link to the one before it",
    SequenceProblem.FIRST_IS_LINKED: "the run begins part-way through a longer sequence",
    SequenceProblem.OUT_OF_ORDER: "the receipt is dated before the one it follows",
    SequenceProblem.DIFFERENT_AGENT: "the run changes which agent is acting",
}


def sequence_problems(receipts: Sequence[ActionReceipt]) -> tuple[frozenset[SequenceProblem], ...]:
    """Problems at each position in a run of receipts, earliest first.

    A receipt proves what it records and says nothing about what is missing.
    Linking each one to its predecessor makes a run a sequence rather than a
    pile: an agent that made five hundred calls and kept receipts for fifty-nine
    cannot present them as the whole story, because the links do not close.

    What this catches is deletion or reordering **within** what was handed over.
    It cannot catch an agent that simply stopped recording, or that kept a
    second sequence it never showed anybody. Detecting that needs an anchor
    outside the agent's control, which this format does not provide.

    Reported per position rather than flattened, because knowing a run is broken
    matters much less than knowing where.

    An empty run raises rather than reporting nothing. A caller writing the
    idiomatic `if any(sequence_problems(run))` would otherwise read "no receipts
    were handed over" as "nothing is wrong", which is the opposite of what an
    empty run means when somebody was asked to produce one.
    """
    if not receipts:
        raise ValueError("an empty run is not an intact run; there is nothing to check")

    first = {SequenceProblem.FIRST_IS_LINKED} if receipts[0].prev is not None else set()
    links = (_link_problems(earlier, later) for earlier, later in pairwise(receipts))
    return (frozenset(first), *links)


def _link_problems(earlier: ActionReceipt, later: ActionReceipt) -> frozenset[SequenceProblem]:
    if later.prev is None:
        return frozenset({SequenceProblem.NOT_LINKED})

    problems = set()
    if later.prev != earlier.id:
        problems.add(SequenceProblem.PREVIOUS_ID_MISMATCH)
    if later.prev_hash != receipt_digest(earlier):
        problems.add(SequenceProblem.PREVIOUS_HASH_MISMATCH)
    if later.issued_at < earlier.issued_at:
        problems.add(SequenceProblem.OUT_OF_ORDER)
    # Compared whole, as agents are everywhere else: a different signing key is
    # a different agent, and its actions belong to its own run.
    if later.agent != earlier.agent:
        problems.add(SequenceProblem.DIFFERENT_AGENT)

    return frozenset(problems)


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
    prev: ActionReceipt | None = None,
) -> ActionReceipt:
    """Record an action taken under a grant.

    Computes the mandate hash for the same reason outcome_for computes the
    receipt hash: a document built by hand is one transcription error away from
    being unbindable, and the error surfaces only when somebody needs it as
    evidence.

    Pass the agent's previous receipt as prev to link them into a run, so a
    later reader can tell whether anything between them is missing.
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
        prev=prev.id if prev else None,
        prev_hash=receipt_digest(prev) if prev else None,
    )


def outcome_for(
    receipt: ActionReceipt,
    *,
    status: OutcomeStatus,
    issued_at: datetime,
    resolution: DisputeResolution | None = None,
    loss: Money | None = None,
    evidence: tuple[Evidence, ...] = (),
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
        evidence=evidence,
    )
