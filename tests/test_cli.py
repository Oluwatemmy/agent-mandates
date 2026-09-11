import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from datetime import timedelta
from decimal import Decimal

from agent_receipts.cli import BAD_INPUT, NOT_VERIFIED, VERIFIED, main
from agent_receipts.models import ActionReceipt, Decision, DecisionOutcome, Money
from agent_receipts.signing import sign
from agent_receipts.keys import jwks_from_public_keys

VECTOR_DIR = Path(__file__).parent / "vectors"
KEY_MATERIAL = json.loads((VECTOR_DIR / "keys.json").read_text(encoding="utf-8"))["keys"]
PUBLIC_KEYS = {
    key_id: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(entry["seed_hex"])).public_key()
    for key_id, entry in KEY_MATERIAL.items()
}

RECEIPT_VECTOR = json.loads(
    (VECTOR_DIR / "001-receipt-written-non-canonically.json").read_text(encoding="utf-8")
)
OUTCOME_VECTOR = json.loads(
    (VECTOR_DIR / "003-outcome-disputed-with-loss.json").read_text(encoding="utf-8")
)


PRIVATE_KEYS = {
    key_id: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(entry["seed_hex"]))
    for key_id, entry in KEY_MATERIAL.items()
}


def signed_receipt(path: Path, receipt: ActionReceipt) -> Path:
    envelope = sign(receipt, "key-1", PRIVATE_KEYS["key-1"])
    return write_envelope(path, envelope.model_dump(mode="json"))


def over_mandate(receipt: ActionReceipt) -> ActionReceipt:
    return receipt.model_copy(
        update={
            "action": receipt.action.model_copy(
                update={"value": Money(amount=Decimal("500"), currency="USD")}
            ),
            "mandate": receipt.mandate.model_copy(
                update={"expires_at": receipt.issued_at - timedelta(days=1)}
            ),
        }
    )


def write_envelope(path: Path, envelope: dict) -> Path:
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return path


@pytest.fixture
def keys_file(tmp_path) -> Path:
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(jwks_from_public_keys(PUBLIC_KEYS)), encoding="utf-8")
    return path


@pytest.fixture
def envelope_file(tmp_path) -> Path:
    return write_envelope(tmp_path / "envelope.json", RECEIPT_VECTOR["envelope"])


@pytest.fixture
def outcome_file(tmp_path) -> Path:
    return write_envelope(tmp_path / "outcome.json", OUTCOME_VECTOR["envelope"])


@pytest.fixture
def receipt_file(tmp_path) -> Path:
    return write_envelope(tmp_path / "receipt.json", RECEIPT_VECTOR["envelope"])


def test_verifies_a_good_envelope(envelope_file, keys_file, capsys):
    exit_code = main(["verify", str(envelope_file), "--keys", str(keys_file)])

    assert exit_code == VERIFIED
    assert "VERIFIED" in capsys.readouterr().out


def test_always_reports_who_signed(envelope_file, keys_file, capsys):
    # Reporting only that a document is valid would drop the question the
    # evidence exists to answer: valid according to whom.
    main(["verify", str(envelope_file), "--keys", str(keys_file)])

    assert "signed by  key-1" in capsys.readouterr().out


def test_shows_what_the_document_claims(envelope_file, keys_file, capsys):
    main(["verify", str(envelope_file), "--keys", str(keys_file)])

    out = capsys.readouterr().out
    assert "payment.charge" in out
    assert "42.5 USD" in out
    assert "user:1234" in out


def test_a_tampered_payload_is_shown_but_not_verified(tmp_path, keys_file, capsys):
    tampered = copy.deepcopy(RECEIPT_VECTOR["envelope"])
    tampered["payload"]["action"]["value"]["amount"] = "4200"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(tampered), encoding="utf-8")

    exit_code = main(["verify", str(path), "--keys", str(keys_file)])

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "4200 USD" in out
    assert "NOT VERIFIED" in out


def test_require_fails_when_the_named_key_did_not_sign(envelope_file, keys_file, capsys):
    exit_code = main(
        ["verify", str(envelope_file), "--keys", str(keys_file), "--require", "merchant-key"]
    )

    assert exit_code == NOT_VERIFIED
    assert "required merchant-key did not sign" in capsys.readouterr().out


def test_require_passes_when_the_named_key_signed(envelope_file, keys_file):
    exit_code = main(["verify", str(envelope_file), "--keys", str(keys_file), "--require", "key-1"])

    assert exit_code == VERIFIED


def test_a_directory_without_the_signer_does_not_verify(tmp_path, envelope_file, capsys):
    path = tmp_path / "other-keys.json"
    path.write_text(json.dumps(jwks_from_public_keys({"merchant-key": PUBLIC_KEYS["merchant-key"]})), encoding="utf-8")

    exit_code = main(["verify", str(envelope_file), "--keys", str(path)])

    assert exit_code == NOT_VERIFIED
    assert "signed by  -" in capsys.readouterr().out


def test_an_unusable_key_directory_is_an_input_error(tmp_path, envelope_file, capsys):
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": [{"kty": "RSA", "kid": "k"}]}), encoding="utf-8")

    exit_code = main(["verify", str(envelope_file), "--keys", str(path)])

    assert exit_code == BAD_INPUT
    assert "cannot read key directory" in capsys.readouterr().err


def test_a_malformed_envelope_is_an_input_error(tmp_path, keys_file, capsys):
    path = tmp_path / "envelope.json"
    path.write_text('{"payload": {}, "signatures": []}', encoding="utf-8")

    exit_code = main(["verify", str(path), "--keys", str(keys_file)])

    assert exit_code == BAD_INPUT
    assert "not a valid envelope" in capsys.readouterr().err


def test_a_missing_file_is_an_input_error(tmp_path, keys_file, capsys):
    exit_code = main(["verify", str(tmp_path / "absent.json"), "--keys", str(keys_file)])

    assert exit_code == BAD_INPUT
    assert "cannot read envelope" in capsys.readouterr().err


def test_input_errors_are_distinguishable_from_a_failed_verification():
    # A caller scripting this needs to tell "the signature is bad" apart from
    # "you pointed me at the wrong file".
    assert BAD_INPUT != NOT_VERIFIED != VERIFIED


def test_verifies_a_bound_pair(outcome_file, receipt_file, keys_file, capsys):
    exit_code = main(
        ["verify", str(outcome_file), "--keys", str(keys_file), "--receipt", str(receipt_file)]
    )

    out = capsys.readouterr().out
    assert exit_code == VERIFIED
    assert "binding    OK" in out


def test_a_receipt_altered_after_the_fact_breaks_the_binding(tmp_path, outcome_file, keys_file, capsys):
    # The receipt id is unchanged, so only the content commitment catches this.
    altered = copy.deepcopy(RECEIPT_VECTOR["envelope"])
    altered["payload"]["action"]["value"]["amount"] = "4200"
    path = write_envelope(tmp_path / "altered.json", altered)

    exit_code = main(["verify", str(outcome_file), "--keys", str(keys_file), "--receipt", str(path)])

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "binding    BROKEN" in out
    assert "commits to different receipt content" in out


def test_an_outcome_shown_against_an_unrelated_receipt_is_rejected(
    tmp_path, outcome_file, keys_file, capsys
):
    unrelated = copy.deepcopy(RECEIPT_VECTOR["envelope"])
    unrelated["payload"]["id"] = "rcpt_ffffffffffffffffffffffffffffffff"
    path = write_envelope(tmp_path / "unrelated.json", unrelated)

    exit_code = main(["verify", str(outcome_file), "--keys", str(keys_file), "--receipt", str(path)])

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "names a different receipt" in out


def test_receipt_flag_is_rejected_when_verifying_a_receipt(envelope_file, receipt_file, keys_file, capsys):
    exit_code = main(
        ["verify", str(envelope_file), "--keys", str(keys_file), "--receipt", str(receipt_file)]
    )

    assert exit_code == BAD_INPUT
    assert "applies when verifying an outcome" in capsys.readouterr().err


def test_receipt_flag_pointing_at_an_outcome_is_rejected(outcome_file, keys_file, capsys):
    exit_code = main(
        ["verify", str(outcome_file), "--keys", str(keys_file), "--receipt", str(outcome_file)]
    )

    assert exit_code == BAD_INPUT
    assert "does not contain an action receipt" in capsys.readouterr().err


def test_names_the_receipt_it_checked_the_binding_against(
    tmp_path, outcome_file, receipt_file, keys_file, capsys
):
    main(["verify", str(outcome_file), "--keys", str(keys_file), "--receipt", str(receipt_file)])

    out = capsys.readouterr().out
    assert "receipt    rcpt_0123456789abcdef0123456789abcdef signed by key-1" in out


def test_a_receipt_within_its_mandate_reports_scope_ok(envelope_file, keys_file, capsys):
    main(["verify", str(envelope_file), "--keys", str(keys_file)])

    assert "scope      OK" in capsys.readouterr().out


def test_going_ahead_beyond_the_mandate_fails_with_every_reason(tmp_path, keys_file, capsys):
    receipt = ActionReceipt.model_validate(RECEIPT_VECTOR["input"])
    path = signed_receipt(tmp_path / "over.json", over_mandate(receipt))

    exit_code = main(["verify", str(path), "--keys", str(keys_file)])

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "scope      EXCEEDED" in out
    assert "value is above the mandate's limit" in out
    assert "mandate had expired" in out


def test_a_refused_out_of_scope_action_still_verifies(tmp_path, keys_file, capsys):
    # The receipt documents the system refusing something it should refuse.
    # That is a good record, not a failed verification.
    receipt = ActionReceipt.model_validate(RECEIPT_VECTOR["input"])
    refused = over_mandate(receipt).model_copy(
        update={"decision": Decision(outcome=DecisionOutcome.DENY)}
    )
    path = signed_receipt(tmp_path / "refused.json", refused)

    exit_code = main(["verify", str(path), "--keys", str(keys_file)])

    out = capsys.readouterr().out
    assert exit_code == VERIFIED
    assert "EXCEEDED, and refused" in out


def test_the_receipt_in_a_pair_is_scope_checked_too(tmp_path, outcome_file, keys_file, capsys):
    main(["verify", str(outcome_file), "--keys", str(keys_file), "--receipt", str(
        write_envelope(tmp_path / "receipt.json", RECEIPT_VECTOR["envelope"])
    )])

    out = capsys.readouterr().out
    assert "binding    OK" in out
    assert "scope      OK" in out
