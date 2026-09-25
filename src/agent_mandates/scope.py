"""Checking a recorded action against the mandate it was taken under.

A receipt records both what an agent did and the authority it claims to have
done it under. These checks ask whether the first actually falls inside the
second: the right kind of action, within any value ceiling, before the mandate
ran out.

The mandate is a separate document signed by the principal who granted it, so
these checks measure an agent's action against authority it did not write for
itself. Confirming that this grant is the one the receipt was taken under is a
different question, answered by mandate_problems in binding.py; these checks
assume the pair has already been matched.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from agent_mandates.models import Action, ActionReceipt, DecisionOutcome, Mandate


class ScopeViolation(StrEnum):
    ACTION_OUTSIDE_SCOPE = "action_outside_scope"
    VALUE_EXCEEDS_LIMIT = "value_exceeds_limit"
    VALUE_NOT_STATED = "value_not_stated"
    LIMIT_CURRENCY_MISMATCH = "limit_currency_mismatch"
    MANDATE_EXPIRED = "mandate_expired"


VIOLATION_DESCRIPTIONS = {
    ScopeViolation.ACTION_OUTSIDE_SCOPE: "the action type is not in the mandate's scope",
    ScopeViolation.VALUE_EXCEEDS_LIMIT: "the action's value is above the mandate's limit",
    ScopeViolation.VALUE_NOT_STATED: (
        "the mandate sets a limit and the action does not say what it cost"
    ),
    ScopeViolation.LIMIT_CURRENCY_MISMATCH: (
        "the mandate's limit is in another currency, so the value cannot be checked against it"
    ),
    ScopeViolation.MANDATE_EXPIRED: "the mandate had expired when the action was taken",
}


def scope_violations(mandate: Mandate, receipt: ActionReceipt) -> frozenset[ScopeViolation]:
    """Every way this action falls outside the mandate, or an empty set.

    Reports all violations rather than the first, for the same reason binding
    does: whoever has to act on the report needs to see the whole picture.
    """
    return permits(mandate, receipt.action, at=receipt.issued_at)


def permits(mandate: Mandate, action: Action, *, at: datetime) -> frozenset[ScopeViolation]:
    """Every way this action would fall outside the mandate, or an empty set.

    The same check as scope_violations, asked before acting rather than after.
    An agent that consults its own grant catches a runaway loop or a misread
    instruction before the money is spent, rather than documenting it
    afterwards.

    It is not enforcement. Nothing here sits between an agent and the thing it
    is calling, and an agent that lies about what it did will not honestly ask
    permission first. This catches the honest failures, which are most of them.
    """
    violations = set()

    if action.type not in mandate.scope:
        violations.add(ScopeViolation.ACTION_OUTSIDE_SCOPE)

    if at > mandate.expires_at:
        violations.add(ScopeViolation.MANDATE_EXPIRED)

    # A mandate with no ceiling places no monetary limit on the action.
    if mandate.max_value is not None:
        if action.value is None:
            # Under a ceiling, saying nothing is not the same as spending
            # nothing. An action that omits its value would otherwise slip past
            # the limit entirely, which is a one-line way around the only number
            # in the grant. A free action states zero and says so.
            violations.add(ScopeViolation.VALUE_NOT_STATED)
        elif action.value.currency != mandate.max_value.currency:
            # Converting would mean inventing an exchange rate, and passing
            # would mean treating an unconstrained currency as constrained.
            # Neither is honest, so this fails closed.
            violations.add(ScopeViolation.LIMIT_CURRENCY_MISMATCH)
        elif action.value.amount > mandate.max_value.amount:
            violations.add(ScopeViolation.VALUE_EXCEEDS_LIMIT)

    return frozenset(violations)


def allowed_beyond_mandate(mandate: Mandate, receipt: ActionReceipt) -> bool:
    """Whether this receipt records permitting something the mandate did not.

    A refused action that fell outside its mandate is not a problem: it is the
    system working, and the receipt documenting it is a perfectly good record.
    What matters is a receipt that records going ahead anyway.
    """
    return (
        bool(scope_violations(mandate, receipt))
        and receipt.decision.outcome is not DecisionOutcome.DENY
    )
