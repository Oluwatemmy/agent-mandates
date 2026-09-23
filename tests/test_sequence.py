"""Linking receipts into a run.

A receipt proves what it records and says nothing about what is missing. These
tests are about the gap that closes: an agent handing over a selective subset of
what it actually did.
"""

from datetime import timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from agent_mandates.binding import (
    SEQUENCE_PROBLEM_DESCRIPTIONS,
    SequenceProblem,
    receipt_digest,
    receipt_under,
    sequence_problems,
)
from agent_mandates.models import Action, ActionReceipt, Agent, Decision, DecisionOutcome, Money
from support import FOLLOWING_RECEIPT_VECTOR, MANDATE_VECTOR, RECEIPT_VECTOR, document

PARAMS = "sha256:" + "0" * 64


@pytest.fixture
def grant():
    return document(MANDATE_VECTOR)


def call(grant, minute: int, prev: ActionReceipt | None = None) -> ActionReceipt:
    return receipt_under(
        grant,
        action=Action(
            type="payment.charge",
            target="https://api.example.com/v1/charge",
            params_hash=PARAMS,
            value=Money(amount=Decimal("10"), currency="USD"),
        ),
        decision=Decision(outcome=DecisionOutcome.ALLOW),
        issued_at=grant.issued_at + timedelta(minutes=minute),
        prev=prev,
    )


@pytest.fixture
def run(grant) -> list[ActionReceipt]:
    receipts: list[ActionReceipt] = []
    for minute in range(5):
        receipts.append(call(grant, minute, receipts[-1] if receipts else None))
    return receipts


def test_an_unbroken_run_has_no_problems(run):
    assert sequence_problems(run) == tuple(frozenset() for _ in run)


def test_receipt_under_links_to_the_one_before(run):
    assert run[1].prev == run[0].id
    assert run[1].prev_hash == receipt_digest(run[0])


def test_the_first_receipt_in_a_run_links_to_nothing(run):
    assert run[0].prev is None and run[0].prev_hash is None


def test_a_receipt_removed_from_the_middle_is_detected(run):
    # The gap this whole field exists for: an agent handing over a selective
    # subset of what it actually did.
    handed_over = run[:2] + run[3:]

    problems = sequence_problems(handed_over)

    assert SequenceProblem.PREVIOUS_ID_MISMATCH in problems[2]
    assert SequenceProblem.PREVIOUS_HASH_MISMATCH in problems[2]


def test_reordering_is_detected(run):
    shuffled = [run[0], run[2], run[1], run[3], run[4]]

    problems = sequence_problems(shuffled)

    assert SequenceProblem.PREVIOUS_ID_MISMATCH in problems[1]
    assert SequenceProblem.OUT_OF_ORDER in problems[2]


def test_a_run_handed_over_from_the_middle_is_detected(run):
    # Everything links correctly, but it does not begin at a beginning.
    assert sequence_problems(run[2:])[0] == {SequenceProblem.FIRST_IS_LINKED}


def test_an_unlinked_receipt_after_the_first_is_detected(grant, run):
    orphan = call(grant, 9)

    assert sequence_problems([run[0], orphan])[1] == {SequenceProblem.NOT_LINKED}


def test_a_receipt_whose_predecessor_was_altered_does_not_link(grant, run):
    # The id still matches; only the content changed. Without the hash this
    # would pass, which is why the id alone was never enough.
    altered = run[0].model_copy(update={"decision": Decision(outcome=DecisionOutcome.STEP_UP)})

    problems = sequence_problems([altered, run[1]])

    assert problems[1] == {SequenceProblem.PREVIOUS_HASH_MISMATCH}


def test_a_run_cannot_change_agent_midway(grant, run):
    someone_else = run[1].model_copy(update={"agent": Agent(id="agent:other", key_id="key-9")})

    assert SequenceProblem.DIFFERENT_AGENT in sequence_problems([run[0], someone_else])[1]


def test_a_single_receipt_is_a_valid_run(run):
    assert sequence_problems([run[0]]) == (frozenset(),)


def test_an_empty_run_has_no_positions():
    assert sequence_problems([]) == ()


def test_the_golden_vector_links_to_its_predecessor():
    first = document(RECEIPT_VECTOR)
    second = document(FOLLOWING_RECEIPT_VECTOR)

    assert sequence_problems([first, second]) == (frozenset(), frozenset())


def test_every_problem_has_a_description():
    assert set(SEQUENCE_PROBLEM_DESCRIPTIONS) == set(SequenceProblem)


@pytest.mark.parametrize(
    ("prev", "prev_hash"),
    [("rcpt_" + "0" * 32, None), (None, "sha256:" + "0" * 64)],
)
def test_a_half_written_link_is_refused(run, prev, prev_hash):
    # An id without a digest names a receipt without committing to it, which is
    # the mistake this field was removed for the first time round.
    half_written = {**run[1].model_dump(mode="json"), "prev": prev, "prev_hash": prev_hash}

    with pytest.raises(ValidationError, match="together or not at all"):
        ActionReceipt.model_validate(half_written)
