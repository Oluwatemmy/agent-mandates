"""Invariants that must hold for every document, not just the ones we thought of.

The hand-written tests cover inputs somebody imagined. These cover the ones
nobody did, which is where a canonicalization bug lives.
"""

import json
from datetime import timedelta

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from agent_receipts.binding import binding_problems, mandate_digest, outcome_for
from agent_receipts.canonical import canonical_bytes, canonical_json_bytes, canonical_json_value
from agent_receipts.delegation import DelegationProblem, delegation_problems
from agent_receipts.models import (
    ActionReceipt,
    Agent,
    DecisionOutcome,
    DelegationLink,
    Mandate,
    OutcomeAttestation,
    OutcomeStatus,
)
from agent_receipts.signing import SignedEnvelope, decode_signature, sign, verified_signers
from strategies import documents, json_values, mandates, outcomes, receipts

WIDENING = {
    DelegationProblem.SCOPE_WIDENED,
    DelegationProblem.EXPIRY_EXTENDED,
    DelegationProblem.CEILING_RAISED,
    DelegationProblem.CEILING_REMOVED,
    DelegationProblem.CEILING_CURRENCY_CHANGED,
}

THOROUGH = settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow], deadline=None)
SIGNING = settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow], deadline=None)

DOCUMENT_TYPES = {
    "mandate": Mandate,
    "action": ActionReceipt,
    "outcome": OutcomeAttestation,
}


def reparse(document):
    return DOCUMENT_TYPES[document.type].model_validate(canonical_json_value(document))


def key_for(document) -> tuple[str, ed25519.Ed25519PrivateKey]:
    """A key id the envelope will accept as this document's author."""
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(32))
    if isinstance(document, Mandate):
        link = document.delegated_from
        return (link.agent.key_id if link else document.principal.key_id, private_key)
    if isinstance(document, ActionReceipt):
        return document.agent.key_id, private_key
    return "observer", private_key


@THOROUGH
@given(documents)
def test_canonical_form_is_a_fixed_point(document):
    # Feeding a canonical document back in must return it unchanged, otherwise
    # the format has two stable forms and a verifier cannot re-canonicalize
    # what it received.
    once = canonical_json_value(document)

    assert canonical_json_value(reparse(document)) == once


@THOROUGH
@given(documents)
def test_canonical_bytes_are_deterministic(document):
    assert canonical_bytes(document) == canonical_bytes(document)


@THOROUGH
@given(documents)
def test_canonical_bytes_survive_a_json_round_trip(document):
    written = json.loads(canonical_bytes(document).decode("utf-8"))
    restored = DOCUMENT_TYPES[document.type].model_validate(written)

    assert canonical_bytes(restored) == canonical_bytes(document)


@THOROUGH
@given(documents)
def test_no_canonical_document_contains_a_json_number(document):
    def scalars(node):
        if isinstance(node, dict):
            for value in node.values():
                yield from scalars(value)
        elif isinstance(node, list):
            for value in node:
                yield from scalars(value)
        else:
            yield node

    assert not [s for s in scalars(canonical_json_value(document)) if isinstance(s, int | float)]


@THOROUGH
@given(json_values)
def test_canonicalizer_agrees_with_the_reference_implementation(value):
    # The hand-written differential test covers nine structures somebody chose.
    # This covers whatever Hypothesis can think of.
    assert canonical_json_bytes(value) == rfc8785.dumps(value)


@SIGNING
@given(documents)
def test_signing_then_verifying_always_succeeds(document):
    key_id, private_key = key_for(document)

    envelope = sign(document, key_id, private_key)

    assert verified_signers(envelope, {key_id: private_key.public_key()}) == {key_id}


@SIGNING
@given(documents)
def test_a_signature_survives_being_written_to_json_and_read_back(document):
    key_id, private_key = key_for(document)
    envelope = sign(document, key_id, private_key)

    restored = SignedEnvelope.model_validate_json(envelope.model_dump_json(exclude_none=True))

    assert verified_signers(restored, {key_id: private_key.public_key()}) == {key_id}


@SIGNING
@given(documents, st.integers(min_value=0, max_value=10_000))
def test_flipping_any_byte_of_the_payload_breaks_verification(document, offset):
    key_id, private_key = key_for(document)
    envelope = sign(document, key_id, private_key)
    signed = canonical_bytes(document)

    position = offset % len(signed)
    tampered = bytearray(signed)
    tampered[position] ^= 0x01

    public_key = private_key.public_key()
    assume(bytes(tampered) != signed)

    with pytest.raises(InvalidSignature):
        public_key.verify(decode_signature(envelope.signatures[0].value), bytes(tampered))


@SIGNING
@given(mandates, receipts, outcomes)
def test_a_signature_never_verifies_against_a_different_document(mandate, receipt, outcome):
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(32))
    signed = canonical_bytes(mandate)
    signature = private_key.sign(signed)

    for other in (receipt, outcome):
        if canonical_bytes(other) == signed:
            continue
        with pytest.raises(InvalidSignature):
            private_key.public_key().verify(signature, canonical_bytes(other))


@pytest.mark.parametrize("surrogate", ["\ud800", "\udfff", "a\ud800b"])
def test_unpaired_surrogates_are_rejected_at_every_document_entry_point(surrogate):
    # A lone surrogate is representable in a Python str but not encodable as
    # UTF-8, so one reaching canonicalization would raise from the depths rather
    # than being refused at the boundary. Nothing here arranges that: pydantic
    # core is Rust, whose strings cannot hold one. Pinned so the guarantee is
    # explicit rather than incidental, and so a change upstream is caught.
    with pytest.raises(ValidationError):
        Agent(id=surrogate, key_id="key-1")


@SIGNING
@given(receipts)
def test_an_attested_outcome_is_always_bound_to_its_receipt(receipt):
    assume(receipt.decision.outcome is not DecisionOutcome.DENY)

    attested = outcome_for(
        receipt, status=OutcomeStatus.COMPLETED, issued_at=receipt.issued_at + timedelta(days=1)
    )

    assert binding_problems(receipt, attested) == frozenset()


@SIGNING
@given(mandates)
def test_narrowing_a_grant_never_introduces_a_widening_problem(mandate):
    # Whatever the parent looks like, a child that keeps the same scope, the
    # same expiry and the same ceiling has widened nothing.
    child = mandate.model_copy(
        update={
            "agent": Agent(id="agent:downstream", key_id="key-downstream"),
            "delegated_from": DelegationLink(
                mandate_id=mandate.id, mandate_hash=mandate_digest(mandate), agent=mandate.agent
            ),
            "issued_at": mandate.issued_at,
        }
    )

    assert not (delegation_problems(mandate, child) & WIDENING)
