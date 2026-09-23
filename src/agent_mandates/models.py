"""Document formats for agent action receipts and outcome attestations.

These models define exactly what gets signed. Any change to a field name, type,
or serialization changes the bytes a signature covers and invalidates documents
produced by earlier versions of this package.

Every value is normalized to a single canonical form on construction, so a
document cannot exist in a non-canonical state and signing is deterministic.
Serialization ordering and escaping are a separate concern, handled by RFC 8785.
"""

from __future__ import annotations

import unicodedata
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    PlainSerializer,
    StringConstraints,
    field_serializer,
    model_validator,
)

# Signed documents are frozen because mutating one after signing silently
# desynchronizes it from its signature. Unknown fields are rejected rather than
# ignored: a verifier that drops a field it does not understand would display
# different content than the signature actually covers.
SIGNED_DOCUMENT = ConfigDict(extra="forbid", frozen=True)


def _canonical_timestamp(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    utc = moment.astimezone(UTC)
    # Truncated to milliseconds because datetime.isoformat() omits the
    # fractional part entirely when it is zero, giving one instant two written
    # forms. Sub-millisecond precision is not meaningful for these documents.
    return utc.replace(microsecond=(utc.microsecond // 1000) * 1000)


def _format_timestamp(moment: datetime) -> str:
    # Built field by field rather than with strftime, whose %Y delegates to the
    # platform and does not zero-pad years below 1000 everywhere. Canonical
    # bytes must not depend on which C library is underneath.
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}"
        f"T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
        f".{moment.microsecond // 1000:03d}Z"
    )


def _reject_inexact_amount(amount: object) -> object:
    # A float cannot represent most decimal amounts exactly, and pydantic would
    # otherwise coerce one silently: 0.1 + 0.2 would be signed as
    # 0.30000000000000004. Callers have to say what they mean.
    if isinstance(amount, float):
        raise ValueError("amount must not be a float; pass a Decimal or a string")
    return amount


def _canonical_amount(amount: Decimal) -> Decimal:
    if not amount.is_finite():
        raise ValueError("amount must be finite")
    if amount < 0:
        raise ValueError("amount must not be negative")

    # Trailing zeros are stripped by rebuilding the digit tuple rather than with
    # normalize(), which runs under the thread's decimal context and silently
    # ROUNDS anything past its precision: an amount of 29 significant digits
    # came back as 1. Silently changing a value is the exact failure this format
    # exists to prevent, so the arithmetic here is exact and context-free.
    sign, digits, exponent = amount.as_tuple()
    assert isinstance(exponent, int)  # guaranteed finite above
    while exponent < 0 and digits and digits[-1] == 0:
        digits = digits[:-1]
        exponent += 1

    canonical = Decimal((sign, digits or (0,), exponent))
    # Negative zero passes the sign check above and would serialize as "-0".
    if canonical.is_zero():
        canonical = Decimal(0)
    return canonical


def _format_amount(amount: Decimal) -> str:
    # Plain notation always. str() renders small and large magnitudes in
    # scientific notation (0.0000001 as 1E-7), which the format forbids and
    # which an independent implementation would write differently, producing
    # bytes that do not match.
    return format(amount, "f")


def _canonical_text(text: str) -> str:
    # NFC collapses the two Unicode spellings of characters like e-acute into
    # one. It is not a defence against homoglyphs: Cyrillic and Latin lookalike
    # letters remain distinct, so callers must not treat this as identity
    # verification.
    return unicodedata.normalize("NFC", text)


def _canonical_identifier(identifier: str) -> str:
    canonical = _canonical_text(identifier)
    if canonical != canonical.strip():
        raise ValueError("identifier must not have leading or trailing whitespace")
    if not canonical:
        raise ValueError("identifier must not be empty")
    # Case is preserved: folding it would silently merge principals that the
    # caller's own system treats as distinct.
    return canonical


def _canonical_scope(scope: tuple[str, ...]) -> tuple[str, ...]:
    if not scope:
        raise ValueError("scope must not be empty")
    # A mandate's scope is a set of permissions, so the order it was written in
    # carries no meaning and must not change the bytes we sign.
    #
    # Sorted by UTF-16 code unit, matching how RFC 8785 orders object keys.
    # Python sorts by code point, and the two disagree above U+FFFF, so a
    # JavaScript implementation sorting the same scope natively would otherwise
    # produce different bytes.
    return tuple(sorted(set(scope), key=lambda entry: entry.encode("utf-16-be")))


def _require_absolute_http_url(target: str) -> str:
    canonical = _canonical_text(target)
    # urlsplit strips control characters and tabs before parsing, so checking
    # its view while storing the original would mean the value that gets signed
    # is not the value that was validated: "ht<TAB>tps://good@evil" parses as
    # https://good@evil and would then be stored, and printed, verbatim.
    if any(unicodedata.category(character) in ("Cc", "Cf") for character in canonical):
        raise ValueError("target must not contain control characters")

    parsed = urlparse(canonical)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("target must be an absolute http(s) URL")
    return canonical


UtcTimestamp = Annotated[
    datetime,
    AfterValidator(_canonical_timestamp),
    PlainSerializer(_format_timestamp, return_type=str, when_used="json"),
]

# Stored verbatim rather than as pydantic's AnyHttpUrl, which normalizes its
# input (appending a trailing slash to a bare origin, for example). That would
# make the bytes we sign differ from the target the caller actually supplied.
TargetUrl = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2048),
    AfterValidator(_require_absolute_http_url),
]

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]
ReceiptId = Annotated[str, StringConstraints(pattern=r"^rcpt_[0-9a-f]{32}$")]
OutcomeId = Annotated[str, StringConstraints(pattern=r"^outc_[0-9a-f]{32}$")]
MandateId = Annotated[str, StringConstraints(pattern=r"^mndt_[0-9a-f]{32}$")]
Identifier = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512),
    AfterValidator(_canonical_identifier),
]
FreeText = Annotated[str, StringConstraints(max_length=512), AfterValidator(_canonical_text)]
CanonicalAmount = Annotated[
    Decimal, BeforeValidator(_reject_inexact_amount), AfterValidator(_canonical_amount)
]


class PrincipalType(StrEnum):
    HUMAN = "human"
    ORGANIZATION = "organization"


class DecisionOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"


class OutcomeStatus(StrEnum):
    COMPLETED = "completed"
    DISPUTED = "disputed"
    REFUNDED = "refunded"
    REVERSED = "reversed"


class DisputeResolution(StrEnum):
    PENDING = "pending"
    MERCHANT_WON = "merchant_won"
    MERCHANT_LOST = "merchant_lost"
    WITHDRAWN = "withdrawn"


class Money(BaseModel):
    model_config = SIGNED_DOCUMENT

    amount: CanonicalAmount
    currency: CurrencyCode

    @field_serializer("amount")
    def _serialize_amount(self, amount: Decimal) -> str:
        # Serialized as a string so that no JSON reader can round-trip the
        # value through a float and change the amount that was signed.
        return _format_amount(amount)


class Agent(BaseModel):
    model_config = SIGNED_DOCUMENT

    id: Identifier
    key_id: Identifier


class Principal(BaseModel):
    """The human or organization whose authority the agent acted under."""

    model_config = SIGNED_DOCUMENT

    id: Identifier
    type: PrincipalType
    # A principal grants authority by signing a mandate, so it needs a key of
    # its own. Without one there is nobody a verifier can check a grant against.
    key_id: Identifier


class DelegationLink(BaseModel):
    """The grant an agent was itself acting under when it delegated onward."""

    model_config = SIGNED_DOCUMENT

    mandate_id: MandateId
    mandate_hash: Sha256Digest
    # The delegating agent, which must also be the key that signed the grant.
    # Named here rather than inferred so the link stands on its own.
    agent: Agent


class Mandate(BaseModel):
    """Authority granted by a principal to a particular agent.

    A signed document in its own right, issued by the principal rather than
    embedded in the receipts that rely on it. An agent signing its own
    statement of what it was permitted to do proves nothing; a verifier has to
    be able to check a grant against whoever granted it.
    """

    model_config = SIGNED_DOCUMENT

    v: Literal["0.2"] = "0.2"
    type: Literal["mandate"] = "mandate"
    id: MandateId
    issued_at: UtcTimestamp
    principal: Principal
    # Named explicitly so a mandate cannot be picked up and used by an agent it
    # was never granted to.
    agent: Agent
    scope: Annotated[tuple[Identifier, ...], AfterValidator(_canonical_scope)]
    expires_at: UtcTimestamp
    max_value: Money | None = None
    # Absent on a grant made by the principal directly. Present when one agent
    # passes authority to another, naming the grant it was acting under so the
    # chain can be walked back to an accountable human.
    delegated_from: DelegationLink | None = None


class Action(BaseModel):
    model_config = SIGNED_DOCUMENT

    type: Identifier
    target: TargetUrl
    params_hash: Sha256Digest
    # Value-bearing actions carry the amount in the clear because checking an
    # action against a mandate limit requires comparing them; the parameter
    # hash alone would make that check impossible.
    value: Money | None = None


class Decision(BaseModel):
    model_config = SIGNED_DOCUMENT

    outcome: DecisionOutcome
    # Order is preserved here, unlike a mandate's scope: reasons are recorded in
    # the order the policy produced them.
    reasons: tuple[FreeText, ...] = ()


class ActionReceipt(BaseModel):
    """What an agent did, and the authority it did it under."""

    model_config = SIGNED_DOCUMENT

    v: Literal["0.2"] = "0.2"
    type: Literal["action"] = "action"
    id: ReceiptId
    issued_at: UtcTimestamp
    agent: Agent
    principal: Principal
    # References the mandate rather than restating it. The hash commits to the
    # grant's content, so the receipt cannot be checked against a mandate other
    # than the one it was actually taken under.
    mandate_id: MandateId
    mandate_hash: Sha256Digest
    action: Action
    decision: Decision
    # Links to the agent's previous action, so a run of receipts is a sequence
    # rather than a pile. Without it a receipt proves what it records and says
    # nothing about what is missing: an agent that made five hundred calls and
    # produced receipts for fifty-nine would pass every other check here.
    #
    # Both together or neither. An id alone names a receipt without committing
    # to it, which is the mistake this field was removed for once already.
    prev: ReceiptId | None = None
    prev_hash: Sha256Digest | None = None

    @model_validator(mode="after")
    def _link_is_complete(self) -> ActionReceipt:
        if (self.prev is None) != (self.prev_hash is None):
            raise ValueError("prev and prev_hash are set together or not at all")
        return self


class OutcomeAttestation(BaseModel):
    """What ultimately happened as a result of a previously receipted action.

    Issued separately and later than the receipt it refers to, because the
    outcome of an action is usually not known when the action is taken.
    """

    model_config = SIGNED_DOCUMENT

    v: Literal["0.2"] = "0.2"
    type: Literal["outcome"] = "outcome"
    id: OutcomeId
    receipt_id: ReceiptId
    # Commits to the receipt's canonical bytes, not just its name. A receipt id
    # is chosen by whoever issues it, so a reference alone would let an outcome
    # be presented against a receipt whose content nobody has checked.
    receipt_hash: Sha256Digest
    issued_at: UtcTimestamp
    status: OutcomeStatus
    resolution: DisputeResolution | None = None
    loss: Money | None = None


def new_receipt_id() -> str:
    return f"rcpt_{uuid.uuid4().hex}"


def new_outcome_id() -> str:
    return f"outc_{uuid.uuid4().hex}"


def new_mandate_id() -> str:
    return f"mndt_{uuid.uuid4().hex}"
