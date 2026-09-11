"""Ed25519 signing, and the envelope that carries a signed document.

A signature covers the canonical bytes of the payload and nothing else. The
envelope around it is never signed, so rewrapping a payload -- reordering the
envelope's keys, reformatting it, adding a second signature -- cannot change
what was signed or who signed it.

Ed25519 signatures are deterministic (RFC 8032), so signing the same document
with the same key always produces the same bytes. That is what makes the golden
vectors reproducible by an independent implementation.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from agent_receipts.canonical import SignedDocument, canonical_bytes
from agent_receipts.models import ActionReceipt, Identifier, Mandate, OutcomeAttestation

ED25519_SIGNATURE_SIZE = 64
SIGNATURE_TEXT_LENGTH = 86  # 64 bytes as unpadded base64url

# The envelope is not signed, but it is parsed from untrusted input, so unknown
# fields must be rejected rather than ignored, and it must not be mutable after
# validation.
ENVELOPE = ConfigDict(extra="forbid", frozen=True)


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _require_canonical_signature(text: str) -> str:
    raw = _decode(text)
    if len(raw) != ED25519_SIGNATURE_SIZE:
        raise ValueError(f"an Ed25519 signature is {ED25519_SIGNATURE_SIZE} bytes")
    # Trailing bits in the final base64 character are unconstrained, so the same
    # signature has more than one spelling unless the encoding is pinned.
    if _encode(raw) != text:
        raise ValueError("signature must use canonical unpadded base64url")
    return text


SignatureText = Annotated[
    str,
    StringConstraints(pattern=rf"^[A-Za-z0-9_-]{{{SIGNATURE_TEXT_LENGTH}}}$"),
    AfterValidator(_require_canonical_signature),
]


class Signature(BaseModel):
    model_config = ENVELOPE

    # Pinned rather than dispatched on. A verifier rejects anything else instead
    # of selecting an algorithm from the document, which is how algorithm
    # confusion attacks get in. The field exists for future versioning only.
    alg: Literal["Ed25519"] = "Ed25519"
    key_id: Identifier
    value: SignatureText


class SignedEnvelope(BaseModel):
    """A document together with the signatures over its canonical bytes."""

    model_config = ENVELOPE

    payload: Annotated[ActionReceipt | OutcomeAttestation | Mandate, Field(discriminator="type")]
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def _reject_repeated_signers(self) -> SignedEnvelope:
        key_ids = [signature.key_id for signature in self.signatures]
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("each key may sign an envelope only once")
        return self

    @model_validator(mode="after")
    def _require_the_document_to_be_signed_by_its_author(self) -> SignedEnvelope:
        # A document asserting what somebody did or granted must carry a
        # signature from the key it names as having done so. Without this, a
        # valid payload could be rewrapped and presented as signed by somebody
        # else entirely. This is a structural check only; whether the signature
        # verifies is a separate question answered by verified_signers.
        #
        # An outcome attestation is exempt: it is issued by whichever party
        # observed the result, which the document does not name, and the
        # verifier decides whose attestation it trusts.
        required = _required_signer(self.payload)
        if required is None:
            return self

        if required not in {signature.key_id for signature in self.signatures}:
            raise ValueError(f"this document must be signed by the key it names: {required}")
        return self


def _required_signer(payload: SignedDocument) -> str | None:
    if isinstance(payload, ActionReceipt):
        # The receipt asserts what this agent did.
        return payload.agent.key_id
    if isinstance(payload, Mandate):
        # A grant is signed by whoever made it. Directly from the principal,
        # that is the principal; delegated onward, it is the agent passing its
        # authority along. Either way it is never the agent receiving it, which
        # is what separating the documents prevents.
        if payload.delegated_from is not None:
            return payload.delegated_from.agent.key_id
        return payload.principal.key_id
    return None


def sign(
    document: SignedDocument, key_id: str, private_key: ed25519.Ed25519PrivateKey
) -> SignedEnvelope:
    """Wrap a document in an envelope carrying one signature over its payload."""
    return SignedEnvelope(payload=document, signatures=(_signature(document, key_id, private_key),))


def add_signature(
    envelope: SignedEnvelope, key_id: str, private_key: ed25519.Ed25519PrivateKey
) -> SignedEnvelope:
    """Countersign an existing envelope, leaving its payload untouched."""
    countersigned = _signature(envelope.payload, key_id, private_key)
    return SignedEnvelope(
        payload=envelope.payload, signatures=(*envelope.signatures, countersigned)
    )


def verified_signers(
    envelope: SignedEnvelope, public_keys: Mapping[str, ed25519.Ed25519PublicKey]
) -> frozenset[str]:
    """The key ids whose signatures verify against the payload.

    Deliberately not a boolean. A caller must decide whether the keys that
    actually signed are the ones it trusts, and returning "valid" alone would
    let that question be skipped. Signatures from unknown keys are ignored
    rather than failing the envelope, so an attacker cannot invalidate someone
    else's evidence by appending a signature to it.
    """
    signed = canonical_bytes(envelope.payload)
    verified = set()
    for signature in envelope.signatures:
        public_key = public_keys.get(signature.key_id)
        if public_key is None:
            continue
        try:
            public_key.verify(_decode(signature.value), signed)
        except InvalidSignature:
            continue
        verified.add(signature.key_id)
    return frozenset(verified)


def _signature(
    document: SignedDocument, key_id: str, private_key: ed25519.Ed25519PrivateKey
) -> Signature:
    return Signature(key_id=key_id, value=_encode(private_key.sign(canonical_bytes(document))))
