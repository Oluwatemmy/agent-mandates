"""Checking a recorded action against the mandate it was taken under."""

from datetime import timedelta
from decimal import Decimal

import pytest

from agent_mandates.models import ActionReceipt, Decision, DecisionOutcome, Mandate, Money
from agent_mandates.scope import (
    VIOLATION_DESCRIPTIONS,
    ScopeViolation,
    allowed_beyond_mandate,
    scope_violations,
)
from support import MANDATE_VECTOR, RECEIPT_VECTOR, document

PARAMS_HASH = "sha256:" + "a" * 64


@pytest.fixture
def mandate() -> Mandate:
    return document(MANDATE_VECTOR)


@pytest.fixture
def receipt() -> ActionReceipt:
    return document(RECEIPT_VECTOR)


def with_action(receipt: ActionReceipt, **changes) -> ActionReceipt:
    return receipt.model_copy(update={"action": receipt.action.model_copy(update=changes)})


def with_decision(receipt: ActionReceipt, outcome: DecisionOutcome) -> ActionReceipt:
    return receipt.model_copy(update={"decision": Decision(outcome=outcome)})


def test_an_action_inside_its_mandate_has_no_violations(mandate, receipt):
    assert scope_violations(mandate, receipt) == frozenset()


def test_an_action_type_outside_the_scope_is_reported(mandate, receipt):
    wandered = with_action(receipt, type="account.close")

    assert scope_violations(mandate, wandered) == {ScopeViolation.ACTION_OUTSIDE_SCOPE}


def test_a_value_above_the_limit_is_reported(mandate, receipt):
    overspent = with_action(receipt, value=Money(amount=Decimal("500"), currency="USD"))

    assert scope_violations(mandate, overspent) == {ScopeViolation.VALUE_EXCEEDS_LIMIT}


def test_a_value_exactly_at_the_limit_is_allowed(mandate, receipt):
    at_limit = with_action(receipt, value=Money(amount=Decimal("100.00"), currency="USD"))

    assert scope_violations(mandate, at_limit) == frozenset()


def test_a_limit_in_another_currency_fails_closed(mandate, receipt):
    # Converting would mean inventing an exchange rate; passing would mean
    # treating an unconstrained currency as constrained.
    other_currency = with_action(receipt, value=Money(amount=Decimal("1"), currency="EUR"))

    assert scope_violations(mandate, other_currency) == {ScopeViolation.LIMIT_CURRENCY_MISMATCH}


def test_a_currency_mismatch_is_reported_even_when_the_amount_looks_small(mandate, receipt):
    # The amount is far below the numeric limit, so a check that compared
    # amounts before currencies would wave this through.
    trivial = with_action(receipt, value=Money(amount=Decimal("0.01"), currency="JPY"))

    assert ScopeViolation.LIMIT_CURRENCY_MISMATCH in scope_violations(mandate, trivial)


def test_a_mandate_without_a_ceiling_does_not_limit_value(mandate, receipt):
    unlimited = mandate.model_copy(update={"max_value": None})
    expensive = with_action(receipt, value=Money(amount=Decimal("999999"), currency="USD"))

    assert scope_violations(unlimited, expensive) == frozenset()


def test_an_action_under_a_ceiling_must_say_what_it_cost(mandate, receipt):
    # This once passed: an action with no value was treated as not engaging the
    # limit, on the reasoning that a mandate covering both reads and charges
    # legitimately has actions that cost nothing. That left a one-line way
    # around the only number in the grant -- omit the value and spend anything.
    silent = with_action(receipt, type="order.create", params_hash=PARAMS_HASH, value=None)

    assert scope_violations(mandate, silent) == {ScopeViolation.VALUE_NOT_STATED}


def test_a_free_action_states_zero(mandate, receipt):
    # The honest version of the case above: nothing was spent, and it says so.
    free = with_action(
        receipt,
        type="order.create",
        params_hash=PARAMS_HASH,
        value=Money(amount=Decimal("0"), currency="USD"),
    )

    assert scope_violations(mandate, free) == frozenset()


def test_a_mandate_with_no_ceiling_does_not_require_a_value(mandate, receipt):
    # Nothing to compare against, so nothing to withhold.
    unlimited = mandate.model_copy(update={"max_value": None})
    silent = with_action(receipt, type="order.create", params_hash=PARAMS_HASH, value=None)

    assert scope_violations(unlimited, silent) == frozenset()


def test_an_action_after_the_mandate_expired_is_reported(mandate, receipt):
    lapsed = mandate.model_copy(update={"expires_at": receipt.issued_at - timedelta(seconds=1)})

    assert scope_violations(lapsed, receipt) == {ScopeViolation.MANDATE_EXPIRED}


def test_an_action_at_the_instant_the_mandate_expires_is_allowed(mandate, receipt):
    just_in_time = mandate.model_copy(update={"expires_at": receipt.issued_at})

    assert scope_violations(just_in_time, receipt) == frozenset()


def test_every_violation_is_reported_not_just_the_first(mandate, receipt):
    wandered = with_action(
        receipt, type="account.close", value=Money(amount=Decimal("500"), currency="USD")
    )
    lapsed = mandate.model_copy(update={"expires_at": receipt.issued_at - timedelta(days=1)})

    assert scope_violations(lapsed, wandered) == {
        ScopeViolation.ACTION_OUTSIDE_SCOPE,
        ScopeViolation.VALUE_EXCEEDS_LIMIT,
        ScopeViolation.MANDATE_EXPIRED,
    }


def test_scope_matching_is_exact_not_prefix(mandate, receipt):
    # "payment.charge" must not be satisfied by a scope granting
    # "payment.charge.refund" or vice versa.
    narrowed = mandate.model_copy(update={"scope": ("payment.charge.refund",)})

    assert scope_violations(narrowed, receipt) == {ScopeViolation.ACTION_OUTSIDE_SCOPE}


def test_scope_matching_is_case_sensitive(mandate, receipt):
    # Identifiers preserve case throughout the format, so a mandate granting
    # Payment.Charge does not grant payment.charge.
    recased = mandate.model_copy(update={"scope": ("Payment.Charge",)})

    assert scope_violations(recased, receipt) == {ScopeViolation.ACTION_OUTSIDE_SCOPE}


def test_every_violation_has_a_description():
    assert set(VIOLATION_DESCRIPTIONS) == set(ScopeViolation)


def test_an_action_inside_its_mandate_was_not_allowed_beyond_it(mandate, receipt):
    assert allowed_beyond_mandate(mandate, receipt) is False


def test_going_ahead_with_an_out_of_scope_action_is_flagged(mandate, receipt):
    wandered = with_action(receipt, type="account.close")

    assert allowed_beyond_mandate(mandate, wandered) is True


@pytest.mark.parametrize("outcome", [DecisionOutcome.ALLOW, DecisionOutcome.STEP_UP])
def test_any_decision_short_of_refusal_counts_as_going_ahead(mandate, receipt, outcome):
    wandered = with_decision(with_action(receipt, type="account.close"), outcome)

    assert allowed_beyond_mandate(mandate, wandered) is True


def test_refusing_an_out_of_scope_action_is_the_system_working(mandate, receipt):
    # The violation is still reported, but the receipt documents a refusal,
    # which is a good record rather than a problem.
    refused = with_decision(with_action(receipt, type="account.close"), DecisionOutcome.DENY)

    assert scope_violations(mandate, refused) == {ScopeViolation.ACTION_OUTSIDE_SCOPE}
    assert allowed_beyond_mandate(mandate, refused) is False
