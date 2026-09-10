"""Binding an outcome to the receipt it reports on.

The property under test: two documents that each verify on their own must not
be presentable as a pair unless the outcome actually commits to that receipt.
"""

import copy
import json
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from agent_receipts.binding import (
    BindingProblem,
    PROBLEM_DESCRIPTIONS,
    binding_problems,
    outcome_for,
    receipt_digest,
)
from agent_receipts.models import (
    ActionReceipt,
    Decision,
    DecisionOutcome,
    DisputeResolution,
    Money,
    OutcomeAttestation,
    OutcomeStatus,
    new_receipt_id,
)

VECTOR_DIR = Path(__file__).parent / "vectors"
RECEIPT_VECTOR = json.loads(
    (VECTOR_DIR / "001-receipt-written-non-canonically.json").read_text(encoding="utf-8")
)
OUTCOME_VECTOR = json.loads(
    (VECTOR_DIR / "003-outcome-disputed-with-loss.json").read_text(encoding="utf-8")
)


@pytest.fixture
def receipt() -> ActionReceipt:
    return ActionReceipt.model_validate(RECEIPT_VECTOR["input"])


@pytest.fixture
def outcome() -> OutcomeAttestation:
    return OutcomeAttestation.model_validate(OUTCOME_VECTOR["input"])


def test_a_matching_pair_has_no_problems(receipt, outcome):
    assert binding_problems(receipt, outcome) == frozenset()


def test_outcome_for_produces_a_bound_pair(receipt):
    attested = outcome_for(
        receipt,
        status=OutcomeStatus.REFUNDED,
        issued_at=receipt.issued_at + timedelta(days=3),
        loss=Money(amount=Decimal("42.50"), currency="USD"),
    )

    assert binding_problems(receipt, attested) == frozenset()


def test_a_receipt_with_the_same_id_but_different_content_does_not_bind(receipt, outcome):
    # The whole point of committing to the hash. An id alone is chosen by
    # whoever issues it, so it cannot distinguish these two receipts.
    restated = receipt.model_copy(update={"decision": Decision(outcome=DecisionOutcome.STEP_UP)})

    problems = binding_problems(restated, outcome)

    assert problems == {BindingProblem.RECEIPT_HASH_MISMATCH}
    assert restated.id == outcome.receipt_id


def test_an_outcome_for_an_entirely_different_receipt_fails_on_both_counts(receipt, outcome):
    unrelated = receipt.model_copy(update={"id": new_receipt_id()})

    assert binding_problems(unrelated, outcome) == {
        BindingProblem.RECEIPT_ID_MISMATCH,
        BindingProblem.RECEIPT_HASH_MISMATCH,
    }


def test_an_outcome_dated_before_its_action_is_incoherent(receipt):
    backdated = outcome_for(
        receipt, status=OutcomeStatus.COMPLETED, issued_at=receipt.issued_at - timedelta(seconds=1)
    )

    assert binding_problems(receipt, backdated) == {BindingProblem.OUTCOME_PRECEDES_ACTION}


def test_an_outcome_at_the_same_instant_as_its_action_is_allowed(receipt):
    simultaneous = outcome_for(receipt, status=OutcomeStatus.COMPLETED, issued_at=receipt.issued_at)

    assert binding_problems(receipt, simultaneous) == frozenset()


def test_a_refused_action_has_no_outcome(receipt):
    refused = receipt.model_copy(update={"decision": Decision(outcome=DecisionOutcome.DENY)})

    with pytest.raises(ValueError, match="refused action has no outcome"):
        outcome_for(refused, status=OutcomeStatus.COMPLETED, issued_at=refused.issued_at)


def test_an_outcome_attached_to_a_refused_action_is_reported(receipt, outcome):
    # outcome_for refuses to build one, but documents arrive from outside, so
    # the verifying side has to catch it too.
    refused = receipt.model_copy(update={"decision": Decision(outcome=DecisionOutcome.DENY)})

    assert BindingProblem.ACTION_WAS_REFUSED in binding_problems(refused, outcome)


def test_all_problems_are_reported_not_just_the_first(receipt, outcome):
    # Stopping at the first failure would hide the rest from whoever has to act
    # on the report.
    refused_and_unrelated = receipt.model_copy(
        update={"id": new_receipt_id(), "decision": Decision(outcome=DecisionOutcome.DENY)}
    )

    assert len(binding_problems(refused_and_unrelated, outcome)) == 3


def test_the_digest_covers_canonical_bytes_not_the_written_form(receipt):
    # The vector's input is written non-canonically, so if the digest were taken
    # over the received bytes these two would differ.
    as_received = ActionReceipt.model_validate(RECEIPT_VECTOR["input"])
    as_canonical = ActionReceipt.model_validate(RECEIPT_VECTOR["canonical"])

    assert receipt_digest(as_received) == receipt_digest(as_canonical)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("id",), "rcpt_ffffffffffffffffffffffffffffffff"),
        (("prev",), "rcpt_11111111111111111111111111111111"),
        (("issued_at",), "2027-01-01T00:00:00.000Z"),
        (("principal", "id"), "user:9999"),
        (("action", "value", "amount"), "4200"),
    ],
)
def test_changing_a_receipt_anywhere_changes_its_digest(receipt, path, replacement):
    altered = copy.deepcopy(RECEIPT_VECTOR["canonical"])
    target = altered
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement

    assert receipt_digest(receipt) != receipt_digest(ActionReceipt.model_validate(altered))


def test_every_problem_has_a_description():
    assert set(PROBLEM_DESCRIPTIONS) == set(BindingProblem)


def test_a_bound_outcome_still_records_the_loss(receipt):
    attested = outcome_for(
        receipt,
        status=OutcomeStatus.DISPUTED,
        issued_at=receipt.issued_at + timedelta(days=14),
        resolution=DisputeResolution.MERCHANT_LOST,
        loss=Money(amount=Decimal("42.50"), currency="USD"),
    )

    assert attested.loss == Money(amount=Decimal("42.5"), currency="USD")
    assert attested.resolution is DisputeResolution.MERCHANT_LOST
