"""Binding documents to the documents they refer to.

The property under test, in both pairings: two documents that each verify on
their own must not be presentable as a pair unless the referring one actually
commits to the referenced one.
"""

import copy
from datetime import timedelta
from decimal import Decimal

import pytest

from agent_mandates.binding import (
    MANDATE_PROBLEM_DESCRIPTIONS,
    PROBLEM_DESCRIPTIONS,
    BindingProblem,
    MandateProblem,
    binding_problems,
    mandate_digest,
    mandate_problems,
    outcome_for,
    receipt_digest,
)
from agent_mandates.models import (
    ActionReceipt,
    Agent,
    Decision,
    DecisionOutcome,
    DisputeResolution,
    Mandate,
    Money,
    OutcomeAttestation,
    OutcomeStatus,
    Principal,
    PrincipalType,
    new_mandate_id,
    new_receipt_id,
)
from support import MANDATE_VECTOR, OUTCOME_VECTOR, RECEIPT_VECTOR, document


@pytest.fixture
def mandate() -> Mandate:
    return document(MANDATE_VECTOR)


@pytest.fixture
def receipt() -> ActionReceipt:
    return document(RECEIPT_VECTOR)


@pytest.fixture
def outcome() -> OutcomeAttestation:
    return document(OUTCOME_VECTOR)


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


def test_a_receipt_taken_under_its_mandate_has_no_problems(mandate, receipt):
    assert mandate_problems(mandate, receipt) == frozenset()


def test_a_mandate_with_the_same_id_but_different_terms_does_not_bind(mandate, receipt):
    # Quietly widening a grant after the fact is the attack this closes.
    widened = mandate.model_copy(update={"scope": ("payment.charge", "account.close")})

    assert mandate_problems(widened, receipt) == {MandateProblem.MANDATE_HASH_MISMATCH}
    assert widened.id == receipt.mandate_id


def test_a_mandate_granted_to_another_agent_cannot_be_claimed(mandate, receipt):
    someone_else = mandate.model_copy(update={"agent": Agent(id="agent:other", key_id="key-9")})

    assert MandateProblem.GRANTED_TO_ANOTHER_AGENT in mandate_problems(someone_else, receipt)


def test_an_agent_sharing_an_id_but_not_a_key_cannot_claim_the_grant(mandate, receipt):
    # Compared whole rather than by id, so a different signing key is enough to
    # make this a different agent.
    rekeyed = mandate.model_copy(update={"agent": Agent(id=mandate.agent.id, key_id="key-9")})

    assert MandateProblem.GRANTED_TO_ANOTHER_AGENT in mandate_problems(rekeyed, receipt)


def test_a_mandate_from_another_principal_is_reported(mandate, receipt):
    elsewhere = mandate.model_copy(
        update={
            "principal": Principal(
                id="user:9999", type=PrincipalType.HUMAN, key_id="other-principal"
            )
        }
    )

    assert MandateProblem.GRANTED_BY_ANOTHER_PRINCIPAL in mandate_problems(elsewhere, receipt)


def test_an_entirely_different_mandate_fails_on_id_and_hash(mandate, receipt):
    unrelated = mandate.model_copy(update={"id": new_mandate_id()})

    assert mandate_problems(unrelated, receipt) >= {
        MandateProblem.MANDATE_ID_MISMATCH,
        MandateProblem.MANDATE_HASH_MISMATCH,
    }


def test_an_action_taken_before_the_grant_existed_is_reported(mandate, receipt):
    granted_later = mandate.model_copy(
        update={"issued_at": receipt.issued_at + timedelta(seconds=1)}
    )

    assert MandateProblem.ACTION_PRECEDES_MANDATE in mandate_problems(granted_later, receipt)


def test_an_action_at_the_instant_of_the_grant_is_allowed(mandate, receipt):
    granted_then = mandate.model_copy(update={"issued_at": receipt.issued_at})
    rebound = receipt.model_copy(update={"mandate_hash": mandate_digest(granted_then)})

    assert mandate_problems(granted_then, rebound) == frozenset()


def test_the_mandate_digest_covers_canonical_bytes_not_the_written_form():
    as_received = Mandate.model_validate(MANDATE_VECTOR["input"])
    as_canonical = Mandate.model_validate(MANDATE_VECTOR["canonical"])

    assert mandate_digest(as_received) == mandate_digest(as_canonical)


def test_every_mandate_problem_has_a_description():
    assert set(MANDATE_PROBLEM_DESCRIPTIONS) == set(MandateProblem)


def test_receipt_under_binds_to_the_grant_it_was_taken_under(mandate):
    from agent_mandates.binding import receipt_under
    from agent_mandates.models import Action, Decision, DecisionOutcome

    recorded = receipt_under(
        mandate,
        action=Action(
            type="payment.charge",
            target="https://api.example.com/v1/orders",
            params_hash="sha256:" + "a" * 64,
        ),
        decision=Decision(outcome=DecisionOutcome.ALLOW),
        issued_at=mandate.issued_at,
    )

    assert mandate_problems(mandate, recorded) == frozenset()
    assert recorded.agent == mandate.agent
    assert recorded.principal == mandate.principal


def test_an_outcome_can_cite_evidence_from_outside_this_format(receipt):
    import hashlib

    from agent_mandates.models import Evidence

    report = b"provider incident report"
    attested = outcome_for(
        receipt,
        status=OutcomeStatus.DISPUTED,
        issued_at=receipt.issued_at + timedelta(days=2),
        evidence=(
            Evidence(
                kind="provider.report",
                source="video-provider",
                digest="sha256:" + hashlib.sha256(report).hexdigest(),
            ),
        ),
    )

    assert binding_problems(receipt, attested) == frozenset()
    assert attested.evidence[0].digest == "sha256:" + hashlib.sha256(report).hexdigest()


def test_cited_evidence_pins_the_attester_to_one_artifact(receipt):
    # The point is falsifiability, not proof: whoever holds the original can
    # tell whether it is the one that was cited.
    import hashlib

    from agent_mandates.models import Evidence

    genuine = b"provider incident report"
    doctored = b"provider incident report (edited)"

    cited = Evidence(
        kind="provider.report",
        source="video-provider",
        digest="sha256:" + hashlib.sha256(genuine).hexdigest(),
    )

    assert cited.digest == "sha256:" + hashlib.sha256(genuine).hexdigest()
    assert cited.digest != "sha256:" + hashlib.sha256(doctored).hexdigest()


def test_an_outcome_cites_nothing_by_default(receipt):
    attested = outcome_for(
        receipt, status=OutcomeStatus.COMPLETED, issued_at=receipt.issued_at + timedelta(days=1)
    )

    assert attested.evidence == ()
    # Absent rather than an empty list in the canonical form would be wrong here:
    # an empty tuple is not None, so it serializes, and stays stable.
    assert attested.model_dump(mode="json")["evidence"] == []


def test_evidence_order_is_preserved(receipt):
    from agent_mandates.models import Evidence

    settlement = Evidence(kind="payment.settlement", source="acme", digest="sha256:" + "a" * 64)
    report = Evidence(kind="provider.report", source="video", digest="sha256:" + "b" * 64)

    attested = outcome_for(
        receipt,
        status=OutcomeStatus.DISPUTED,
        issued_at=receipt.issued_at + timedelta(days=2),
        evidence=(settlement, report),
    )

    assert [e.kind for e in attested.evidence] == ["payment.settlement", "provider.report"]
