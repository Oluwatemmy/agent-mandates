"""Authority passed from one agent to another.

The property under test is attenuation: a delegated grant may narrow what it
received but never widen it, on any dimension.
"""

from datetime import timedelta
from decimal import Decimal

import pytest

from agent_mandates.binding import mandate_digest
from agent_mandates.delegation import (
    DELEGATION_PROBLEM_DESCRIPTIONS,
    MAX_CHAIN_DEPTH,
    DelegationProblem,
    accountable_principal,
    chain_problems,
    delegate,
    delegation_problems,
)
from agent_mandates.models import (
    Agent,
    Mandate,
    Money,
    Principal,
    PrincipalType,
    new_mandate_id,
)
from support import DELEGATED_VECTOR, MANDATE_VECTOR, document


@pytest.fixture
def root() -> Mandate:
    return document(MANDATE_VECTOR)


@pytest.fixture
def delegated() -> Mandate:
    return document(DELEGATED_VECTOR)


def relink(child: Mandate, parent: Mandate) -> Mandate:
    """Re-point a child at a parent whose content has changed."""
    return child.model_copy(
        update={
            "delegated_from": child.delegated_from.model_copy(
                update={"mandate_id": parent.id, "mandate_hash": mandate_digest(parent)}
            )
        }
    )


def test_a_properly_attenuated_grant_has_no_problems(root, delegated):
    assert delegation_problems(root, delegated) == frozenset()


def test_the_chain_answers_to_the_root_principal(root, delegated):
    assert accountable_principal([root, delegated]) == root.principal


def test_a_grant_that_is_not_delegated_cannot_be_a_child(root):
    assert delegation_problems(root, root) == {DelegationProblem.NOT_DELEGATED}


def test_scope_cannot_be_widened(root, delegated):
    overreaching = delegated.model_copy(update={"scope": (*delegated.scope, "account.close")})

    assert delegation_problems(root, overreaching) == {DelegationProblem.SCOPE_WIDENED}


def test_scope_may_be_narrowed(root, delegated):
    narrower = delegated.model_copy(update={"scope": ("payment.charge",)})

    assert delegation_problems(root, narrower) == frozenset()


def test_the_ceiling_cannot_be_raised(root, delegated):
    richer = delegated.model_copy(
        update={"max_value": Money(amount=Decimal("500"), currency="USD")}
    )

    assert delegation_problems(root, richer) == {DelegationProblem.CEILING_RAISED}


def test_the_ceiling_cannot_be_removed(root, delegated):
    # Dropping the limit is the widest possible widening, so an absent ceiling
    # under a limited parent is a violation rather than a default.
    unlimited = delegated.model_copy(update={"max_value": None})

    assert delegation_problems(root, unlimited) == {DelegationProblem.CEILING_REMOVED}


def test_a_ceiling_in_another_currency_fails_closed(root, delegated):
    elsewhere = delegated.model_copy(
        update={"max_value": Money(amount=Decimal("1"), currency="EUR")}
    )

    assert delegation_problems(root, elsewhere) == {DelegationProblem.CEILING_CURRENCY_CHANGED}


def test_an_unlimited_parent_may_delegate_any_ceiling(root, delegated):
    unlimited_parent = root.model_copy(update={"max_value": None})
    child = relink(delegated, unlimited_parent)

    assert delegation_problems(unlimited_parent, child) == frozenset()


def test_an_unlimited_parent_may_delegate_no_ceiling(root, delegated):
    unlimited_parent = root.model_copy(update={"max_value": None})
    child = relink(delegated.model_copy(update={"max_value": None}), unlimited_parent)

    assert delegation_problems(unlimited_parent, child) == frozenset()


def test_expiry_cannot_be_extended(root, delegated):
    longer = delegated.model_copy(update={"expires_at": root.expires_at + timedelta(days=30)})

    assert delegation_problems(root, longer) == {DelegationProblem.EXPIRY_EXTENDED}


def test_expiry_may_match_the_parent_exactly(root, delegated):
    same = delegated.model_copy(update={"expires_at": root.expires_at})

    assert delegation_problems(root, same) == frozenset()


def test_a_parent_with_different_content_does_not_match(root, delegated):
    widened = root.model_copy(update={"scope": (*root.scope, "account.close")})

    assert DelegationProblem.PARENT_HASH_MISMATCH in delegation_problems(widened, delegated)


def test_an_agent_cannot_pass_on_authority_it_never_held(root, delegated):
    # The delegating agent must be the one the parent grant was made to.
    impostor = delegated.model_copy(
        update={
            "delegated_from": delegated.delegated_from.model_copy(
                update={"agent": Agent(id="agent:stranger", key_id="key-9")}
            )
        }
    )

    assert DelegationProblem.DELEGATOR_WAS_NOT_THE_GRANTEE in delegation_problems(root, impostor)


def test_an_agent_sharing_an_id_but_not_a_key_cannot_pass_authority_on(root, delegated):
    rekeyed = delegated.model_copy(
        update={
            "delegated_from": delegated.delegated_from.model_copy(
                update={"agent": Agent(id=root.agent.id, key_id="key-9")}
            )
        }
    )

    assert DelegationProblem.DELEGATOR_WAS_NOT_THE_GRANTEE in delegation_problems(root, rekeyed)


def test_the_chain_cannot_change_which_principal_it_answers_to(root, delegated):
    switched = delegated.model_copy(
        update={"principal": Principal(id="user:9999", type=PrincipalType.HUMAN, key_id="other")}
    )

    assert DelegationProblem.PRINCIPAL_CHANGED in delegation_problems(root, switched)


def test_authority_cannot_be_passed_on_before_it_was_granted(root, delegated):
    early = delegated.model_copy(update={"issued_at": root.issued_at - timedelta(seconds=1)})

    assert DelegationProblem.DELEGATED_BEFORE_ITS_GRANT in delegation_problems(root, early)


def test_authority_cannot_be_passed_on_after_its_grant_expired(root, delegated):
    late = delegated.model_copy(
        update={
            "issued_at": root.expires_at + timedelta(seconds=1),
            "expires_at": root.expires_at + timedelta(days=1),
        }
    )

    assert DelegationProblem.DELEGATED_AFTER_ITS_GRANT_EXPIRED in delegation_problems(root, late)


def test_every_widening_is_reported_separately(root, delegated):
    # Which dimension was widened is the difference between a misconfiguration
    # and an agent granting itself the ability to spend more.
    everything = delegated.model_copy(
        update={
            "scope": (*delegated.scope, "account.close"),
            "max_value": Money(amount=Decimal("500"), currency="USD"),
            "expires_at": root.expires_at + timedelta(days=1),
        }
    )

    assert delegation_problems(root, everything) == {
        DelegationProblem.SCOPE_WIDENED,
        DelegationProblem.CEILING_RAISED,
        DelegationProblem.EXPIRY_EXTENDED,
    }


def test_a_sound_chain_reports_no_problems_at_any_position(root, delegated):
    assert chain_problems([root, delegated]) == (frozenset(), frozenset())


def test_chain_problems_say_which_hop_broke(root, delegated):
    richer = delegated.model_copy(
        update={"max_value": Money(amount=Decimal("500"), currency="USD")}
    )

    positions = chain_problems([root, richer])

    assert positions[0] == frozenset()
    assert positions[1] == {DelegationProblem.CEILING_RAISED}


def test_the_first_grant_in_a_chain_must_not_itself_be_delegated(root, delegated):
    assert DelegationProblem.ROOT_IS_DELEGATED in chain_problems([delegated, delegated])[0]


def test_an_agent_appearing_twice_is_a_cycle(root, delegated):
    looped = delegated.model_copy(update={"agent": root.agent})

    assert DelegationProblem.AGENT_APPEARS_TWICE in chain_problems([root, looped])[0]


def test_a_chain_longer_than_the_limit_is_rejected(root, delegated):
    # A verifier walks a chain link by link, so an unbounded one is free work
    # for an attacker to hand it.
    long_chain = [root] + [
        delegated.model_copy(
            update={"id": new_mandate_id(), "agent": Agent(id=f"agent:{i}", key_id=f"key-{i}")}
        )
        for i in range(MAX_CHAIN_DEPTH)
    ]

    assert DelegationProblem.CHAIN_TOO_DEEP in chain_problems(long_chain)[0]


def test_a_chain_at_the_limit_is_allowed(root, delegated):
    at_limit = [root] + [
        delegated.model_copy(
            update={"id": new_mandate_id(), "agent": Agent(id=f"agent:{i}", key_id=f"key-{i}")}
        )
        for i in range(MAX_CHAIN_DEPTH - 1)
    ]

    assert DelegationProblem.CHAIN_TOO_DEEP not in chain_problems(at_limit)[0]


def test_an_empty_chain_has_no_positions():
    assert chain_problems([]) == ()


def test_an_empty_chain_has_no_principal():
    with pytest.raises(ValueError, match="empty chain"):
        accountable_principal([])


def test_every_problem_has_a_description():
    assert set(DELEGATION_PROBLEM_DESCRIPTIONS) == set(DelegationProblem)


def test_delegate_inherits_everything_left_unspecified(root):
    passed_on = delegate(root, to=Agent(id="agent:sub", key_id="key-2"), issued_at=root.issued_at)

    assert delegation_problems(root, passed_on) == frozenset()
    assert passed_on.scope == root.scope
    assert passed_on.expires_at == root.expires_at
    assert passed_on.max_value == root.max_value


def test_delegate_narrows_what_it_is_given(root):
    passed_on = delegate(
        root,
        to=Agent(id="agent:sub", key_id="key-2"),
        issued_at=root.issued_at,
        max_value=Money(amount=Decimal("1"), currency="USD"),
        expires_at=root.issued_at,
    )

    assert delegation_problems(root, passed_on) == frozenset()


@pytest.mark.parametrize(
    "widening",
    [
        {"max_value": Money(amount=Decimal("100000"), currency="USD")},
        {"scope": ("payment.charge", "account.close")},
        {"max_value": Money(amount=Decimal("1"), currency="EUR")},
    ],
)
def test_delegate_refuses_to_build_a_widening_grant(root, widening):
    # The verifying side checks this too, since documents arrive from outside,
    # but a widening grant should not be producible by accident.
    with pytest.raises(ValueError, match="cannot widen what it received"):
        delegate(
            root, to=Agent(id="agent:sub", key_id="key-2"), issued_at=root.issued_at, **widening
        )


def test_delegate_cannot_remove_a_ceiling(root):
    # Passing no ceiling inherits the parent's rather than dropping it, since
    # dropping one is the widest possible widening.
    passed_on = delegate(root, to=Agent(id="agent:sub", key_id="key-2"), issued_at=root.issued_at)

    assert passed_on.max_value == root.max_value
