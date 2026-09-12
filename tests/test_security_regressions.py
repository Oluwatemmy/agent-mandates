"""Regressions for defects found in the pre-release security and code review.

Every test here corresponds to something that was once wrong and is written to
fail loudly if it comes back. The comments say what the original defect was,
because a test whose point is invisible gets "simplified" away later.
"""

import base64
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError

from agent_mandates.binding import receipt_under
from agent_mandates.canonical import canonical_bytes, canonical_json_value
from agent_mandates.cli import NOT_VERIFIED, _printable, main
from agent_mandates.delegation import delegate
from agent_mandates.keys import jwks_from_public_keys
from agent_mandates.models import (
    Action,
    Agent,
    Decision,
    DecisionOutcome,
    Mandate,
    Money,
    Principal,
    PrincipalType,
    new_mandate_id,
)
from agent_mandates.signing import Signature, SignedEnvelope, author_signed, sign
from support import MANDATE_VECTOR, PUBLIC_KEYS, RECEIPT_VECTOR, document

ATTACKER = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([0xAB] * 32))
PARAMS = "sha256:" + "0" * 64


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forged_envelope(payload, impersonated_key: str, attacker_key_id: str) -> SignedEnvelope:
    """A document naming someone else as author, signed only by the attacker.

    The junk signature exists purely to satisfy the envelope's structural rule
    that a signature labelled with the author's key id is present.
    """
    return SignedEnvelope(
        payload=payload,
        signatures=(
            Signature(key_id=impersonated_key, value="A" * 86),
            Signature(
                key_id=attacker_key_id, value=encode(ATTACKER.sign(canonical_bytes(payload)))
            ),
        ),
    )


# --- Authority forgery -------------------------------------------------------
# A non-empty set of verified signers was treated as sufficient, so any key the
# directory trusted could mint a grant in anybody else's name.


@pytest.fixture
def keys_with_attacker() -> dict:
    return {**PUBLIC_KEYS, "attacker-key": ATTACKER.public_key()}


def test_a_mandate_not_signed_by_its_principal_is_refused(keys_with_attacker):
    grant = document(MANDATE_VECTOR)
    forged = forged_envelope(grant, grant.principal.key_id, "attacker-key")

    assert author_signed(forged, keys_with_attacker) is False


def test_a_receipt_not_signed_by_its_agent_is_refused(keys_with_attacker):
    receipt = document(RECEIPT_VECTOR)
    forged = forged_envelope(receipt, receipt.agent.key_id, "attacker-key")

    assert author_signed(forged, keys_with_attacker) is False


def test_a_genuinely_authored_document_passes(keys_with_attacker):
    genuine = SignedEnvelope.model_validate(MANDATE_VECTOR["envelope"])

    assert author_signed(genuine, keys_with_attacker) is True


def test_an_outcome_names_no_author_so_any_signer_is_acceptable():
    # Outcomes are issued by whoever observed the result, which the document
    # does not name; the caller decides whose attestation it trusts.
    from support import OUTCOME_VECTOR

    assert author_signed(SignedEnvelope.model_validate(OUTCOME_VECTOR["envelope"]), PUBLIC_KEYS)


def test_the_cli_refuses_a_forged_grant_end_to_end(tmp_path, capsys):
    alice = Principal(id="user:alice", type=PrincipalType.HUMAN, key_id="alice-key")
    attacker = Agent(id="agent:attacker", key_id="attacker-key")
    now = datetime.now(UTC)

    # A grant Alice never made: no ceiling, signed only by the attacker.
    forged = Mandate(
        id=new_mandate_id(),
        issued_at=now,
        principal=alice,
        agent=attacker,
        scope=("payment.charge",),
        expires_at=now + timedelta(days=365),
        max_value=None,
    )
    (tmp_path / "mandate.json").write_text(
        forged_envelope(forged, "alice-key", "attacker-key").to_json(), encoding="utf-8"
    )

    receipt = receipt_under(
        forged,
        action=Action(
            type="payment.charge",
            target="https://bank.example.com/v1/transfer",
            params_hash=PARAMS,
            value=Money(amount=Decimal("1000000"), currency="EUR"),
        ),
        decision=Decision(outcome=DecisionOutcome.ALLOW),
        issued_at=now + timedelta(minutes=1),
    )
    (tmp_path / "receipt.json").write_text(
        sign(receipt, "attacker-key", ATTACKER).to_json(), encoding="utf-8"
    )
    (tmp_path / "keys.json").write_text(
        json.dumps(
            jwks_from_public_keys(
                {
                    "alice-key": ed25519.Ed25519PrivateKey.generate().public_key(),
                    "attacker-key": ATTACKER.public_key(),
                }
            )
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "verify",
            str(tmp_path / "receipt.json"),
            "--keys",
            str(tmp_path / "keys.json"),
            "--mandate",
            str(tmp_path / "mandate.json"),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "is not signed by alice-key" in out
    assert "VERIFIED" not in out.replace("NOT VERIFIED", "")


# --- Terminal escape injection ----------------------------------------------
# Attacker-controlled fields were printed raw, so a document could forge its own
# result line and conceal the real one with an ANSI sequence.


@pytest.mark.parametrize("control", ["\n", "\r", "\x1b", "\x00", "\u0085", "\u2028", "\u200e"])
def test_control_characters_never_reach_the_terminal(control):
    rendered = _printable(f"before{control}after")

    assert control not in rendered
    assert "before" in rendered and "after" in rendered


def test_a_forged_result_line_is_escaped_rather_than_printed():
    injection = "evil\nresult     VERIFIED\x1b[8m"

    rendered = _printable(injection)

    assert "\n" not in rendered
    assert "\x1b" not in rendered


# --- Amount handling ---------------------------------------------------------
# normalize() ran under the decimal context and silently rounded, and str()
# emitted scientific notation the format forbids.


def test_an_amount_beyond_the_decimal_context_is_not_rounded():
    # This came back as Decimal("1") before: a money format silently changing
    # the amount, which is the single worst thing it could do.
    precise = Decimal("1.0000000000000000000000000000001")

    assert Money(amount=precise, currency="USD").amount == precise


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("0.0000001", "0.0000001"),
        ("1E-7", "0.0000001"),
        ("1E+2", "100"),
        ("1E+30", "1" + "0" * 30),
        ("100.00", "100"),
        ("0.00", "0"),
        ("-0", "0"),
    ],
)
def test_amounts_never_serialize_in_scientific_notation(written, expected):
    serialized = Money(amount=Decimal(written), currency="USD").model_dump(mode="json")["amount"]

    assert serialized == expected
    assert "E" not in serialized and "e" not in serialized


def test_a_float_amount_is_refused_rather_than_coerced():
    # 0.1 + 0.2 would otherwise have been signed as 0.30000000000000004.
    with pytest.raises(ValidationError):
        Money(amount=0.1 + 0.2, currency="USD")


def test_a_huge_exponent_is_a_validation_error_not_an_arithmetic_one():
    # quantize raised decimal.InvalidOperation, which derives from
    # ArithmeticError, so it escaped pydantic and reached callers as a crash
    # rather than a rejected document.
    envelope = json.loads(json.dumps(RECEIPT_VECTOR["envelope"]))
    envelope["payload"]["action"]["value"]["amount"] = "1E+999"

    parsed = SignedEnvelope.model_validate(envelope)

    assert "E" not in parsed.payload.action.value.model_dump(mode="json")["amount"]


# --- Cross-implementation determinism ---------------------------------------


def test_scope_is_sorted_by_utf16_like_object_keys():
    # Sorted by code point, a scope containing an astral character ordered
    # differently from the way RFC 8785 orders object keys, so a JavaScript
    # implementation would produce different signed bytes.
    # Built from chr() so no escape has to survive an editor, and U+E000 is
    # stable under NFC unlike presentation forms such as U+FB33, which
    # decompose and would make this test measure the wrong thing.
    astral, bmp = chr(0x10000), chr(0xE000)
    grant = document(MANDATE_VECTOR).model_copy(update={"scope": (bmp, astral)})

    assert canonical_json_value(grant)["scope"] == [astral, bmp]


def test_years_below_1000_are_zero_padded():
    # strftime's %Y does not zero-pad on every platform, which would make
    # canonical bytes differ between Linux and Windows for the same document.
    early = datetime(1, 2, 3, tzinfo=UTC)
    grant = document(MANDATE_VECTOR).model_copy(update={"issued_at": early})

    assert canonical_json_value(grant)["issued_at"] == "0001-02-03T00:00:00.000Z"


# --- Validation integrity ----------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "ht\ttps://good.test@evil.test/pay",
        "http\n://good.test/",
        "\x00https://good.test/",
        "https://good.test/\r\nSet-Cookie: x",
    ],
)
def test_a_url_containing_control_characters_is_refused(target):
    # urlsplit strips these before parsing, so the value that was validated was
    # not the value that would have been stored and signed.
    with pytest.raises(ValidationError):
        Action(type="payment.charge", target=target, params_hash=PARAMS)


def test_delegate_refuses_a_grant_that_would_not_verify():
    # It checked attenuation only, so it would happily build a grant delegated
    # after its parent had expired, which a verifier then refuses.
    root = document(MANDATE_VECTOR)

    with pytest.raises(ValueError, match="would not verify"):
        delegate(
            root,
            to=Agent(id="agent:sub", key_id="key-2"),
            issued_at=root.expires_at + timedelta(days=1),
        )
