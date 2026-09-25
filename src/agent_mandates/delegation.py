"""Authority passed from one agent to another, and back to an accountable human.

An agent acting under a grant can pass some of that authority on. The grant it
issues names the grant it was itself acting under, so a chain of mandates leads
back to the principal who started it.

The property that makes this safe is **attenuation**: a delegated grant can
narrow what it received but never widen it. Fewer permissions, a lower ceiling,
an earlier expiry -- or the same. Anything else would let an agent manufacture
authority it was never given, which is the whole thing a delegation chain exists
to prevent.

Widening is therefore reported in detail rather than as one failure. Which
dimension was widened is the difference between a misconfigured integration and
an agent quietly granting itself the ability to spend more.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from itertools import pairwise

from agent_mandates.binding import mandate_digest
from agent_mandates.models import Agent, DelegationLink, Mandate, Money, Principal, new_mandate_id

# A verifier walks a chain link by link, so an unbounded one is work an attacker
# can hand it for free. Eight is far past any plausible real delegation depth.
MAX_CHAIN_DEPTH = 8


class DelegationProblem(StrEnum):
    NOT_DELEGATED = "not_delegated"
    PARENT_ID_MISMATCH = "parent_id_mismatch"
    PARENT_HASH_MISMATCH = "parent_hash_mismatch"
    DELEGATOR_WAS_NOT_THE_GRANTEE = "delegator_was_not_the_grantee"
    PRINCIPAL_CHANGED = "principal_changed"
    DELEGATED_BEFORE_ITS_GRANT = "delegated_before_its_grant"
    DELEGATED_AFTER_ITS_GRANT_EXPIRED = "delegated_after_its_grant_expired"
    SCOPE_WIDENED = "scope_widened"
    EXPIRY_EXTENDED = "expiry_extended"
    CEILING_RAISED = "ceiling_raised"
    CEILING_REMOVED = "ceiling_removed"
    CEILING_CURRENCY_CHANGED = "ceiling_currency_changed"
    ROOT_IS_DELEGATED = "root_is_delegated"
    CHAIN_TOO_DEEP = "chain_too_deep"
    AGENT_APPEARS_TWICE = "agent_appears_twice"


DELEGATION_PROBLEM_DESCRIPTIONS = {
    DelegationProblem.NOT_DELEGATED: "the grant does not say what authority it was passed from",
    DelegationProblem.PARENT_ID_MISMATCH: "the grant names a different parent mandate",
    DelegationProblem.PARENT_HASH_MISMATCH: "the grant commits to different parent content",
    DelegationProblem.DELEGATOR_WAS_NOT_THE_GRANTEE: (
        "the delegating agent is not the one the parent mandate was granted to"
    ),
    DelegationProblem.PRINCIPAL_CHANGED: "the chain changes which principal it answers to",
    DelegationProblem.DELEGATED_BEFORE_ITS_GRANT: (
        "the authority was passed on before it had been granted"
    ),
    DelegationProblem.DELEGATED_AFTER_ITS_GRANT_EXPIRED: (
        "the authority was passed on after the grant it came from had expired"
    ),
    DelegationProblem.SCOPE_WIDENED: "the delegated scope includes permissions the parent lacked",
    DelegationProblem.EXPIRY_EXTENDED: "the delegated grant outlives the one it came from",
    DelegationProblem.CEILING_RAISED: "the delegated ceiling is above the parent's",
    DelegationProblem.CEILING_REMOVED: "the parent had a ceiling and the delegated grant has none",
    DelegationProblem.CEILING_CURRENCY_CHANGED: (
        "the ceilings are in different currencies, so attenuation cannot be checked"
    ),
    DelegationProblem.ROOT_IS_DELEGATED: "the first grant in the chain is itself delegated",
    DelegationProblem.CHAIN_TOO_DEEP: f"the chain is longer than {MAX_CHAIN_DEPTH} grants",
    DelegationProblem.AGENT_APPEARS_TWICE: "an agent appears more than once in the chain",
}


def delegation_problems(parent: Mandate, child: Mandate) -> frozenset[DelegationProblem]:
    """Everything wrong with passing authority from parent to child."""
    link = child.delegated_from
    if link is None:
        return frozenset({DelegationProblem.NOT_DELEGATED})

    problems = set()

    if link.mandate_id != parent.id:
        problems.add(DelegationProblem.PARENT_ID_MISMATCH)
    if link.mandate_hash != mandate_digest(parent):
        problems.add(DelegationProblem.PARENT_HASH_MISMATCH)
    # Compared whole, so an agent sharing an id but presenting another signing
    # key cannot pass on authority it was never given.
    if link.agent != parent.agent:
        problems.add(DelegationProblem.DELEGATOR_WAS_NOT_THE_GRANTEE)
    if child.principal != parent.principal:
        problems.add(DelegationProblem.PRINCIPAL_CHANGED)

    if child.issued_at < parent.issued_at:
        problems.add(DelegationProblem.DELEGATED_BEFORE_ITS_GRANT)
    if child.issued_at > parent.expires_at:
        problems.add(DelegationProblem.DELEGATED_AFTER_ITS_GRANT_EXPIRED)

    problems |= _attenuation_problems(parent, child)
    return frozenset(problems)


def chain_problems(chain: Sequence[Mandate]) -> tuple[frozenset[DelegationProblem], ...]:
    """Problems at each position in a chain, root first.

    Entry zero holds problems with the chain as a whole; entry i holds problems
    delegating from chain[i - 1] to chain[i]. Reported per position rather than
    flattened, because knowing a chain is broken is much less useful than
    knowing which hop broke it.

    An empty chain raises rather than reporting nothing. A caller writing the
    idiomatic `if any(chain_problems(chain))` would otherwise read "there is no
    chain" as "the chain is sound", and accountable_principal already refuses
    the same input.
    """
    if not chain:
        raise ValueError("an empty chain is not a sound chain; there is nothing to check")

    root_problems = set()
    if chain[0].delegated_from is not None:
        root_problems.add(DelegationProblem.ROOT_IS_DELEGATED)
    if len(chain) > MAX_CHAIN_DEPTH:
        root_problems.add(DelegationProblem.CHAIN_TOO_DEEP)

    # Catches a cycle, and an agent delegating to itself, in one check.
    agents = [mandate.agent for mandate in chain]
    if len(set(agents)) != len(agents):
        root_problems.add(DelegationProblem.AGENT_APPEARS_TWICE)

    links = (delegation_problems(parent, child) for parent, child in pairwise(chain))
    return (frozenset(root_problems), *links)


def accountable_principal(chain: Sequence[Mandate]) -> Principal:
    """The principal a chain answers to, which is the root grant's."""
    if not chain:
        raise ValueError("an empty chain has no principal")
    return chain[0].principal


def delegate(
    mandate: Mandate,
    *,
    to: Agent,
    issued_at: datetime,
    scope: tuple[str, ...] | None = None,
    expires_at: datetime | None = None,
    max_value: Money | None = None,
    mandate_id: str | None = None,
) -> Mandate:
    """Pass some of a grant's authority on to another agent.

    Anything left unspecified is inherited from the parent, so the default is to
    narrow nothing. A ceiling cannot be removed through this function, because
    removing one is the widest possible widening; pass a lower one instead.

    Refuses to build a grant that widens what it received. The check exists
    anyway on the verifying side, since documents arrive from outside, but a
    widening grant is not something a caller should be able to produce by
    accident.
    """
    delegated = Mandate(
        id=mandate_id or new_mandate_id(),
        issued_at=issued_at,
        principal=mandate.principal,
        agent=to,
        scope=scope if scope is not None else mandate.scope,
        expires_at=expires_at if expires_at is not None else mandate.expires_at,
        max_value=max_value if max_value is not None else mandate.max_value,
        delegated_from=DelegationLink(
            mandate_id=mandate.id,
            mandate_hash=mandate_digest(mandate),
            agent=mandate.agent,
        ),
    )

    # Checked against everything a verifier will check, not just attenuation.
    # Delegating from a grant that had already expired produces a document that
    # is refused downstream, and finding that out here is better than finding
    # out when somebody tries to rely on it.
    problems = delegation_problems(mandate, delegated)
    if problems:
        raise ValueError(
            "this delegation would not verify: "
            + ", ".join(sorted(DELEGATION_PROBLEM_DESCRIPTIONS[problem] for problem in problems))
        )
    return delegated


def _attenuation_problems(parent: Mandate, child: Mandate) -> set[DelegationProblem]:
    problems = set()

    if not set(child.scope) <= set(parent.scope):
        problems.add(DelegationProblem.SCOPE_WIDENED)
    if child.expires_at > parent.expires_at:
        problems.add(DelegationProblem.EXPIRY_EXTENDED)

    if parent.max_value is None:
        # An unlimited grant may be narrowed to any ceiling, or left unlimited.
        return problems

    if child.max_value is None:
        problems.add(DelegationProblem.CEILING_REMOVED)
    elif child.max_value.currency != parent.max_value.currency:
        # Comparing would mean inventing an exchange rate, so this fails closed,
        # as the same situation does when checking an action against a mandate.
        problems.add(DelegationProblem.CEILING_CURRENCY_CHANGED)
    elif child.max_value.amount > parent.max_value.amount:
        problems.add(DelegationProblem.CEILING_RAISED)

    return problems
