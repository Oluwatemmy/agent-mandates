"""The payload-only signing boundary.

Every test here attacks the same property: a signature covers the canonical
bytes of the payload and nothing else, so rewrapping a payload cannot change
what was signed or who signed it.
"""

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError

from agent_receipts.canonical import canonical_bytes
from agent_receipts.signing import SignedEnvelope, add_signature, sign, verified_signers
from support import MANDATE_VECTOR, PRIVATE_KEYS, PUBLIC_KEYS, VECTOR_PATHS, document

ATTACKER_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([0xFF] * 32))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def receipt_vector() -> dict:
    return next(v for v in map(load, VECTOR_PATHS) if v["document_type"] == "action")


def outcome_vector() -> dict:
    return next(v for v in map(load, VECTOR_PATHS) if v["document_type"] == "outcome")


@pytest.mark.parametrize("vector_path", VECTOR_PATHS, ids=lambda path: path.stem)
def test_golden_envelope_verifies_and_covers_the_pinned_bytes(vector_path):
    vector = load(vector_path)
    envelope = SignedEnvelope.model_validate(vector["envelope"])

    signed_bytes = canonical_bytes(envelope.payload)

    assert hashlib.sha256(signed_bytes).hexdigest() == vector["canonical_bytes_sha256"]
    assert verified_signers(envelope, PUBLIC_KEYS) == {envelope.signatures[0].key_id}


@pytest.mark.parametrize("vector_path", VECTOR_PATHS, ids=lambda path: path.stem)
def test_signing_is_reproducible_from_the_seed(vector_path):
    vector = load(vector_path)
    signer = vector["envelope"]["signatures"][0]["key_id"]

    resigned = sign(document(vector), signer, PRIVATE_KEYS[signer])

    assert resigned.model_dump(mode="json", exclude_none=True) == vector["envelope"]


def test_envelope_key_order_does_not_affect_verification():
    vector = receipt_vector()
    reordered = {
        "signatures": vector["envelope"]["signatures"],
        "payload": vector["envelope"]["payload"],
    }

    envelope = SignedEnvelope.model_validate(reordered)

    assert verified_signers(envelope, PUBLIC_KEYS) == {"key-1"}


def test_payload_key_order_does_not_affect_verification():
    # The payload is re-canonicalized before verification, so the order it
    # happened to arrive in is irrelevant.
    vector = receipt_vector()
    shuffled = dict(reversed(list(vector["envelope"]["payload"].items())))

    envelope = SignedEnvelope.model_validate({**vector["envelope"], "payload": shuffled})

    assert verified_signers(envelope, PUBLIC_KEYS) == {"key-1"}


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("id", "rcpt_ffffffffffffffffffffffffffffffff"),
        ("issued_at", "2027-01-01T00:00:00.000Z"),
    ],
)
def test_changing_any_payload_field_breaks_verification(field, replacement):
    vector = receipt_vector()
    tampered = {**vector["envelope"]["payload"], field: replacement}

    envelope = SignedEnvelope.model_validate({**vector["envelope"], "payload": tampered})

    assert verified_signers(envelope, PUBLIC_KEYS) == frozenset()


def test_raising_the_action_amount_breaks_verification():
    vector = receipt_vector()
    payload = copy.deepcopy(vector["envelope"]["payload"])
    payload["action"]["value"]["amount"] = "4200"

    envelope = SignedEnvelope.model_validate({**vector["envelope"], "payload": payload})

    assert verified_signers(envelope, PUBLIC_KEYS) == frozenset()


def test_a_signature_from_another_document_does_not_verify():
    receipt, outcome = receipt_vector(), outcome_vector()
    transplanted = [{**receipt["envelope"]["signatures"][0], "key_id": "merchant-key"}]

    envelope = SignedEnvelope.model_validate({**outcome["envelope"], "signatures": transplanted})

    assert verified_signers(envelope, PUBLIC_KEYS) == frozenset()


def test_a_receipt_cannot_be_re_enveloped_under_a_different_agent_key():
    # The structural check refuses to build the envelope at all: the payload
    # names key-1 as its agent, so nothing else may present it as its own.
    vector = receipt_vector()

    with pytest.raises(ValidationError, match="must be signed by the key it names"):
        sign(document(vector), "merchant-key", PRIVATE_KEYS["merchant-key"])


def test_claiming_the_agent_key_id_without_its_private_key_does_not_verify():
    # Passing the structural check is not enough; the signature still has to
    # verify under the real public key for that id.
    vector = receipt_vector()

    forged = sign(document(vector), "key-1", ATTACKER_KEY)

    assert forged.signatures[0].key_id == "key-1"
    assert verified_signers(forged, PUBLIC_KEYS) == frozenset()


def test_appending_a_forged_signature_cannot_invalidate_the_real_signer():
    vector = receipt_vector()
    envelope = SignedEnvelope.model_validate(vector["envelope"])

    with_attacker = add_signature(envelope, "attacker-key", ATTACKER_KEY)
    keys = {**PUBLIC_KEYS, "attacker-key": PRIVATE_KEYS["merchant-key"].public_key()}

    assert verified_signers(with_attacker, keys) == {"key-1"}


def test_countersigning_does_not_change_what_the_first_signature_covers():
    vector = receipt_vector()
    envelope = SignedEnvelope.model_validate(vector["envelope"])

    countersigned = add_signature(envelope, "merchant-key", PRIVATE_KEYS["merchant-key"])

    assert canonical_bytes(countersigned.payload) == canonical_bytes(envelope.payload)
    assert countersigned.signatures[0] == envelope.signatures[0]
    assert verified_signers(countersigned, PUBLIC_KEYS) == {"key-1", "merchant-key"}


def test_a_signature_from_an_unknown_key_is_ignored_rather_than_fatal():
    vector = receipt_vector()
    envelope = SignedEnvelope.model_validate(vector["envelope"])
    countersigned = add_signature(envelope, "unknown-key", ATTACKER_KEY)

    assert verified_signers(countersigned, PUBLIC_KEYS) == {"key-1"}


def test_rejects_an_algorithm_other_than_ed25519():
    vector = receipt_vector()
    signatures = [{**vector["envelope"]["signatures"][0], "alg": "HS256"}]

    with pytest.raises(ValidationError):
        SignedEnvelope.model_validate({**vector["envelope"], "signatures": signatures})


def test_rejects_the_same_key_signing_twice():
    vector = receipt_vector()
    signature = vector["envelope"]["signatures"][0]

    with pytest.raises(ValidationError, match="only once"):
        SignedEnvelope.model_validate({**vector["envelope"], "signatures": [signature, signature]})


def test_rejects_an_envelope_with_no_signatures():
    vector = receipt_vector()

    with pytest.raises(ValidationError):
        SignedEnvelope.model_validate({**vector["envelope"], "signatures": []})


def test_rejects_unknown_envelope_fields():
    vector = receipt_vector()

    with pytest.raises(ValidationError):
        SignedEnvelope.model_validate({**vector["envelope"], "verified": True})


def decode_signature(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_rejects_a_non_canonical_base64_signature():
    # The final base64 character carries unused bits, so the same 64 signature
    # bytes have more than one spelling unless the encoding is pinned.
    vector = receipt_vector()
    original = vector["envelope"]["signatures"][0]["value"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    altered = original[:-1] + alphabet[alphabet.index(original[-1]) ^ 1]

    assert decode_signature(altered) == decode_signature(original)

    with pytest.raises(ValidationError, match="canonical unpadded base64url"):
        SignedEnvelope.model_validate(
            {
                **vector["envelope"],
                "signatures": [{**vector["envelope"]["signatures"][0], "value": altered}],
            }
        )


def mandate_vector() -> dict:
    return MANDATE_VECTOR


def test_an_agent_cannot_sign_its_own_mandate():
    # The point of separating the grant from the receipt. A mandate signed by
    # the agent receiving it would be the agent authorizing itself.
    with pytest.raises(ValidationError, match="must be signed by the key it names"):
        sign(document(mandate_vector()), "key-1", PRIVATE_KEYS["key-1"])


def test_a_mandate_must_be_signed_by_the_principal_it_names():
    granted = sign(document(mandate_vector()), "principal-key", PRIVATE_KEYS["principal-key"])

    assert verified_signers(granted, PUBLIC_KEYS) == {"principal-key"}


def test_claiming_the_principal_key_id_without_its_private_key_does_not_verify():
    forged = sign(document(mandate_vector()), "principal-key", ATTACKER_KEY)

    assert forged.signatures[0].key_id == "principal-key"
    assert verified_signers(forged, PUBLIC_KEYS) == frozenset()


def test_an_outcome_has_no_required_signer():
    # Outcomes are issued by whichever party observed the result, which the
    # document does not name, so the verifier decides whose attestation to
    # trust rather than the format deciding for it.
    outcome = document(outcome_vector())

    signed = sign(outcome, "key-1", PRIVATE_KEYS["key-1"])

    assert verified_signers(signed, PUBLIC_KEYS) == {"key-1"}
