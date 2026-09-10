"""The canonical-form contract.

Two documents describing the same thing must serialize to the same bytes, no
matter how the caller wrote the values. Everything here guards that.
"""

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from agent_receipts.canonical import canonical_json_value
from agent_receipts.models import (
    Action,
    ActionReceipt,
    Agent,
    Decision,
    DecisionOutcome,
    Mandate,
    Money,
    OutcomeAttestation,
    OutcomeStatus,
    Principal,
    PrincipalType,
    new_outcome_id,
    new_receipt_id,
)

PARAMS_HASH = "sha256:" + "a" * 64
EXPIRES_AT = datetime(2026, 9, 10, 14, 3, 11, tzinfo=timezone.utc)

PRECOMPOSED_E_ACUTE = "café"
DECOMPOSED_E_ACUTE = "café"


def test_differently_written_equivalent_documents_serialize_identically():
    receipt_id = new_receipt_id()
    berlin = timezone(timedelta(hours=2))

    as_written_by_one_caller = OutcomeAttestation(
        id=(outcome_id := new_outcome_id()),
        receipt_id=receipt_id,
        issued_at=datetime(2026, 9, 23, 11, 11, 2, 999_400, tzinfo=berlin),
        status=OutcomeStatus.DISPUTED,
        loss=Money(amount=Decimal("42.50"), currency="USD"),
    )
    as_written_by_another = OutcomeAttestation(
        id=outcome_id,
        receipt_id=receipt_id,
        issued_at=datetime(2026, 9, 23, 9, 11, 2, 999_000, tzinfo=timezone.utc),
        status=OutcomeStatus.DISPUTED,
        loss=Money(amount=Decimal("42.5"), currency="USD"),
    )

    assert as_written_by_one_caller.model_dump(mode="json") == as_written_by_another.model_dump(mode="json")


@pytest.mark.parametrize(
    ("written", "canonical"),
    [
        ("42.50", "42.5"),
        ("42.500000", "42.5"),
        ("100", "100"),
        ("100.00", "100"),
        ("1E+2", "100"),
        ("0.00", "0"),
        ("-0", "0"),
        ("0.010", "0.01"),
    ],
)
def test_amounts_reduce_to_one_written_form(written, canonical):
    money = Money(amount=Decimal(written), currency="USD")

    assert money.model_dump(mode="json")["amount"] == canonical


@pytest.mark.parametrize("amount", ["NaN", "Infinity", "-1.00"])
def test_money_rejects_amounts_that_have_no_canonical_form(amount):
    with pytest.raises(ValidationError):
        Money(amount=Decimal(amount), currency="USD")


def test_timestamps_always_carry_three_fractional_digits_and_a_zulu_suffix():
    outcome = OutcomeAttestation(
        id=new_outcome_id(),
        receipt_id=new_receipt_id(),
        issued_at=datetime(2026, 9, 23, 9, 11, 2, tzinfo=timezone.utc),
        status=OutcomeStatus.COMPLETED,
    )

    assert outcome.model_dump(mode="json")["issued_at"] == "2026-09-23T09:11:02.000Z"


def test_timestamps_truncate_below_millisecond_precision():
    mandate = Mandate(
        id="mandate:abc",
        scope=("payment.charge",),
        expires_at=datetime(2026, 9, 10, 14, 3, 11, 999_999, tzinfo=timezone.utc),
    )

    assert mandate.model_dump(mode="json")["expires_at"] == "2026-09-10T14:03:11.999Z"


def test_equivalent_unicode_spellings_produce_the_same_identifier():
    precomposed = Action(type=PRECOMPOSED_E_ACUTE, target="https://api.example.com/x", params_hash=PARAMS_HASH)
    decomposed = Action(type=DECOMPOSED_E_ACUTE, target="https://api.example.com/x", params_hash=PARAMS_HASH)

    assert precomposed.type == decomposed.type


@pytest.mark.parametrize("identifier", [" agent:bot", "agent:bot ", "agent:bot\n", "   "])
def test_identifiers_reject_surrounding_whitespace(identifier):
    with pytest.raises(ValidationError):
        Action(type=identifier, target="https://api.example.com/x", params_hash=PARAMS_HASH)


def test_identifier_case_is_preserved():
    # Folding case would merge principals that a caller's own system treats as
    # two different subjects.
    action = Action(type="Payment.Charge", target="https://api.example.com/x", params_hash=PARAMS_HASH)

    assert action.type == "Payment.Charge"


def test_mandate_scope_is_sorted_and_deduplicated():
    mandate = Mandate(
        id="mandate:abc",
        scope=("order.create", "payment.charge", "order.create"),
        expires_at=EXPIRES_AT,
    )

    assert mandate.scope == ("order.create", "payment.charge")


def test_mandate_scope_order_does_not_change_the_document():
    written_one_way = Mandate(id="m", scope=("a.read", "b.write"), expires_at=EXPIRES_AT)
    written_another = Mandate(id="m", scope=("b.write", "a.read"), expires_at=EXPIRES_AT)

    assert written_one_way.model_dump(mode="json") == written_another.model_dump(mode="json")


def test_mandate_rejects_an_empty_scope():
    with pytest.raises(ValidationError):
        Mandate(id="mandate:abc", scope=(), expires_at=EXPIRES_AT)


def test_decision_reasons_keep_the_order_the_policy_produced():
    decision = Decision(outcome=DecisionOutcome.DENY, reasons=("over mandate limit", "mandate expired"))

    assert decision.reasons == ("over mandate limit", "mandate expired")


def _scalars(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _scalars(value)
    elif isinstance(node, list):
        for value in node:
            yield from _scalars(value)
    else:
        yield node


def test_canonical_form_contains_no_json_numbers():
    # RFC 8785 serializes JSON numbers as IEEE 754 doubles, so any numeric field
    # would be silently rounded before signing and a large integer would lose
    # precision. Every scalar in this format is a string to avoid that entirely.
    receipt = ActionReceipt(
        id=new_receipt_id(),
        issued_at=EXPIRES_AT,
        agent=Agent(id="agent:bot", key_id="key-1"),
        principal=Principal(id="user:1234", type=PrincipalType.HUMAN),
        mandate=Mandate(
            id="mandate:abc",
            scope=("payment.charge",),
            expires_at=EXPIRES_AT,
            max_value=Money(amount=Decimal("100.00"), currency="USD"),
        ),
        action=Action(
            type="payment.charge",
            target="https://api.example.com/v1/orders",
            params_hash=PARAMS_HASH,
            value=Money(amount=Decimal("42.50"), currency="USD"),
        ),
        decision=Decision(outcome=DecisionOutcome.ALLOW, reasons=("within mandate",)),
    )

    numeric = [s for s in _scalars(canonical_json_value(receipt)) if isinstance(s, (int, float))]

    assert numeric == []
