from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from agent_mandates.models import (
    Action,
    ActionReceipt,
    Agent,
    Decision,
    DecisionOutcome,
    Money,
    OutcomeAttestation,
    OutcomeStatus,
    Principal,
    PrincipalType,
    new_outcome_id,
    new_receipt_id,
)

PARAMS_HASH = "sha256:" + "a" * 64
RECEIPT_HASH = "sha256:" + "b" * 64
MANDATE_HASH = "sha256:" + "c" * 64
MANDATE_ID = "mndt_" + "0" * 32
ISSUED_AT = datetime(2026, 9, 9, 14, 3, 11, tzinfo=UTC)


def build_receipt(**overrides) -> ActionReceipt:
    fields = {
        "id": new_receipt_id(),
        "issued_at": ISSUED_AT,
        "agent": Agent(id="agent:checkout-bot", key_id="key-1"),
        "principal": Principal(id="user:1234", type=PrincipalType.HUMAN, key_id="principal-key"),
        "mandate_id": MANDATE_ID,
        "mandate_hash": MANDATE_HASH,
        "action": Action(
            type="payment.charge",
            target="https://api.example.com/v1/orders",
            params_hash=PARAMS_HASH,
            value=Money(amount=Decimal("42.50"), currency="USD"),
        ),
        "decision": Decision(outcome=DecisionOutcome.ALLOW),
    }
    return ActionReceipt(**{**fields, **overrides})


def test_receipt_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        build_receipt(approved_by_vendor=True)


def test_receipt_rejects_naive_timestamp():
    with pytest.raises(ValidationError):
        build_receipt(issued_at=datetime(2026, 9, 9, 14, 3, 11))


def test_receipt_normalizes_timestamp_to_utc():
    berlin = timezone(timedelta(hours=2))
    receipt = build_receipt(issued_at=datetime(2026, 9, 9, 16, 3, 11, tzinfo=berlin))

    assert receipt.issued_at == ISSUED_AT
    assert receipt.issued_at.utcoffset() == timedelta(0)


def test_receipt_is_immutable_after_construction():
    receipt = build_receipt()

    with pytest.raises(ValidationError):
        receipt.id = new_receipt_id()


def test_receipt_rejects_id_without_receipt_prefix():
    with pytest.raises(ValidationError):
        build_receipt(id=new_outcome_id())


@pytest.mark.parametrize(
    "params_hash",
    ["sha256:" + "A" * 64, "sha256:" + "a" * 63, "a" * 64, "md5:" + "a" * 32],
)
def test_action_rejects_malformed_params_hash(params_hash):
    with pytest.raises(ValidationError):
        Action(
            type="payment.charge",
            target="https://api.example.com/v1/orders",
            params_hash=params_hash,
        )


@pytest.mark.parametrize(
    "target", ["/v1/orders", "api.example.com/v1/orders", "ftp://example.com/f"]
)
def test_action_rejects_target_that_is_not_an_absolute_http_url(target):
    with pytest.raises(ValidationError):
        Action(type="payment.charge", target=target, params_hash=PARAMS_HASH)


def test_action_stores_target_verbatim():
    # A normalizing URL type would append a trailing slash here and change the
    # bytes we sign relative to what the caller supplied.
    action = Action(type="order.read", target="https://api.example.com", params_hash=PARAMS_HASH)

    assert action.target == "https://api.example.com"


def test_money_rejects_negative_amount():
    with pytest.raises(ValidationError):
        Money(amount=Decimal("-1.00"), currency="USD")


def test_money_rejects_non_iso_currency():
    with pytest.raises(ValidationError):
        Money(amount=Decimal("1.00"), currency="usd")


def test_money_amount_serializes_as_a_string():
    receipt = build_receipt()

    assert receipt.model_dump(mode="json")["action"]["value"]["amount"] == "42.5"


def test_outcome_attestation_rejects_a_receipt_id_of_the_wrong_type():
    with pytest.raises(ValidationError):
        OutcomeAttestation(
            id=new_outcome_id(),
            receipt_id=new_outcome_id(),
            receipt_hash=RECEIPT_HASH,
            issued_at=ISSUED_AT,
            status=OutcomeStatus.DISPUTED,
        )


def test_outcome_attestation_binds_to_its_receipt():
    receipt = build_receipt()
    outcome = OutcomeAttestation(
        id=new_outcome_id(),
        receipt_id=receipt.id,
        receipt_hash=RECEIPT_HASH,
        issued_at=ISSUED_AT + timedelta(days=14),
        status=OutcomeStatus.DISPUTED,
        loss=Money(amount=Decimal("42.50"), currency="USD"),
    )

    assert outcome.receipt_id == receipt.id
