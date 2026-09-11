"""Checking a recorded action against the mandate it was taken under.

A receipt records both what an agent did and the authority it claims to have
done it under. These checks ask whether the first actually falls inside the
second: the right kind of action, within any value ceiling, before the mandate
ran out.

What this does not do, and cannot: verify that the record is true. A receipt is
signed by its agent, and the mandate travels inside that receipt, so an agent
signs its own statement of what it was permitted to do. These checks catch
over-reach and mistakes in honest records. They do not catch a dishonest signer,
who could simply write a mandate that permits whatever it did. Closing that
requires the mandate to be attested by the principal granting it, independently
of the agent using it.
"""

from __future__ import annotations

from enum import StrEnum

from agent_receipts.models import ActionReceipt, DecisionOutcome


class ScopeViolation(StrEnum):
    ACTION_OUTSIDE_SCOPE = "action_outside_scope"
    VALUE_EXCEEDS_LIMIT = "value_exceeds_limit"
    LIMIT_CURRENCY_MISMATCH = "limit_currency_mismatch"
    MANDATE_EXPIRED = "mandate_expired"


VIOLATION_DESCRIPTIONS = {
    ScopeViolation.ACTION_OUTSIDE_SCOPE: "the action type is not in the mandate's scope",
    ScopeViolation.VALUE_EXCEEDS_LIMIT: "the action's value is above the mandate's limit",
    ScopeViolation.LIMIT_CURRENCY_MISMATCH: (
        "the mandate's limit is in another currency, so the value cannot be checked against it"
    ),
    ScopeViolation.MANDATE_EXPIRED: "the mandate had expired when the action was taken",
}


def scope_violations(receipt: ActionReceipt) -> frozenset[ScopeViolation]:
    """Every way this action falls outside its mandate, or an empty set.

    Reports all violations rather than the first, for the same reason binding
    does: whoever has to act on the report needs to see the whole picture.
    """
    violations = set()
    mandate, action = receipt.mandate, receipt.action

    if action.type not in mandate.scope:
        violations.add(ScopeViolation.ACTION_OUTSIDE_SCOPE)

    if receipt.issued_at > mandate.expires_at:
        violations.add(ScopeViolation.MANDATE_EXPIRED)

    # A mandate with no ceiling places no monetary limit on the action, and an
    # action with no value has nothing to check against one. Neither is a
    # violation: a mandate covering both reads and charges legitimately has a
    # limit that only some of its actions engage.
    if mandate.max_value is not None and action.value is not None:
        if action.value.currency != mandate.max_value.currency:
            # Converting would mean inventing an exchange rate, and passing
            # would mean treating an unconstrained currency as constrained.
            # Neither is honest, so this fails closed.
            violations.add(ScopeViolation.LIMIT_CURRENCY_MISMATCH)
        elif action.value.amount > mandate.max_value.amount:
            violations.add(ScopeViolation.VALUE_EXCEEDS_LIMIT)

    return frozenset(violations)


def allowed_beyond_mandate(receipt: ActionReceipt) -> bool:
    """Whether this receipt records permitting something the mandate did not.

    A refused action that fell outside its mandate is not a problem: it is the
    system working, and the receipt documenting it is a perfectly good record.
    What matters is a receipt that records going ahead anyway.
    """
    return bool(scope_violations(receipt)) and receipt.decision.outcome is not DecisionOutcome.DENY
