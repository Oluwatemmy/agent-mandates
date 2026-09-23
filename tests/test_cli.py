import copy
import json
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from agent_mandates.binding import mandate_digest
from agent_mandates.cli import BAD_INPUT, NOT_VERIFIED, VERIFIED, main
from agent_mandates.keys import jwks_from_public_keys
from agent_mandates.models import ActionReceipt, Decision, DecisionOutcome, Mandate, Money
from agent_mandates.signing import sign
from support import (
    DELEGATED_RECEIPT_VECTOR,
    DELEGATED_VECTOR,
    MANDATE_VECTOR,
    OUTCOME_VECTOR,
    PRIVATE_KEYS,
    PUBLIC_KEYS,
    RECEIPT_VECTOR,
    document,
)


def signed_receipt(path: Path, receipt: ActionReceipt) -> Path:
    envelope = sign(receipt, "key-1", PRIVATE_KEYS["key-1"])
    return write_envelope(path, envelope.model_dump(mode="json"))


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


@pytest.fixture
def mandate_file(tmp_path) -> Path:
    return write_envelope(tmp_path / "mandate.json", MANDATE_VECTOR["envelope"])


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
    path.write_text(
        json.dumps(jwks_from_public_keys({"merchant-key": PUBLIC_KEYS["merchant-key"]})),
        encoding="utf-8",
    )

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


def test_a_receipt_altered_after_the_fact_breaks_the_binding(
    tmp_path, outcome_file, keys_file, capsys
):
    # The receipt id is unchanged, so only the content commitment catches this.
    altered = copy.deepcopy(RECEIPT_VECTOR["envelope"])
    altered["payload"]["action"]["value"]["amount"] = "4200"
    path = write_envelope(tmp_path / "altered.json", altered)

    exit_code = main(
        ["verify", str(outcome_file), "--keys", str(keys_file), "--receipt", str(path)]
    )

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

    exit_code = main(
        ["verify", str(outcome_file), "--keys", str(keys_file), "--receipt", str(path)]
    )

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "names a different receipt" in out


def test_receipt_flag_is_rejected_when_verifying_a_receipt(
    envelope_file, receipt_file, keys_file, capsys
):
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


def signed_mandate(path: Path, mandate: Mandate) -> Path:
    envelope = sign(mandate, "principal-key", PRIVATE_KEYS["principal-key"])
    return write_envelope(path, envelope.model_dump(mode="json"))


def rebind(receipt: ActionReceipt, mandate: Mandate) -> ActionReceipt:
    return receipt.model_copy(
        update={"mandate_id": mandate.id, "mandate_hash": mandate_digest(mandate)}
    )


def beyond_the_grant(tmp_path, decision: DecisionOutcome) -> tuple[Path, Path]:
    """A receipt spending above its ceiling under a mandate that had expired."""
    mandate = document(MANDATE_VECTOR)
    receipt = document(RECEIPT_VECTOR)

    lapsed = mandate.model_copy(update={"expires_at": receipt.issued_at - timedelta(days=1)})
    overspent = rebind(receipt, lapsed).model_copy(
        update={
            "action": receipt.action.model_copy(
                update={"value": Money(amount=Decimal("500"), currency="USD")}
            ),
            "decision": Decision(outcome=decision),
        }
    )
    return (
        signed_receipt(tmp_path / "receipt.json", overspent),
        signed_mandate(tmp_path / "mandate.json", lapsed),
    )


def test_a_receipt_within_its_mandate_reports_scope_ok(
    envelope_file, mandate_file, keys_file, capsys
):
    exit_code = main(
        ["verify", str(envelope_file), "--keys", str(keys_file), "--mandate", str(mandate_file)]
    )

    out = capsys.readouterr().out
    assert exit_code == VERIFIED
    assert "scope      OK" in out
    assert "granted by principal-key" in out


def test_scope_is_not_claimed_to_be_checked_without_a_mandate(envelope_file, keys_file, capsys):
    # A bare signature check must not read as an authority check.
    exit_code = main(["verify", str(envelope_file), "--keys", str(keys_file)])

    assert exit_code == VERIFIED
    assert "not checked (no mandate supplied)" in capsys.readouterr().out


def test_going_ahead_beyond_the_grant_fails_with_every_reason(tmp_path, keys_file, capsys):
    receipt_path, mandate_path = beyond_the_grant(tmp_path, DecisionOutcome.ALLOW)

    exit_code = main(
        ["verify", str(receipt_path), "--keys", str(keys_file), "--mandate", str(mandate_path)]
    )

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "scope      EXCEEDED" in out
    assert "value is above the mandate's limit" in out
    assert "mandate had expired" in out


def test_a_refused_out_of_scope_action_still_verifies(tmp_path, keys_file, capsys):
    # The receipt documents the system refusing something it should refuse.
    # That is a good record, not a failed verification.
    receipt_path, mandate_path = beyond_the_grant(tmp_path, DecisionOutcome.DENY)

    exit_code = main(
        ["verify", str(receipt_path), "--keys", str(keys_file), "--mandate", str(mandate_path)]
    )

    out = capsys.readouterr().out
    assert exit_code == VERIFIED
    assert "EXCEEDED, and refused" in out


def test_a_mandate_the_receipt_was_not_taken_under_is_rejected(
    tmp_path, envelope_file, keys_file, capsys
):
    widened = document(MANDATE_VECTOR).model_copy(
        update={"scope": ("payment.charge", "account.close")}
    )
    path = signed_mandate(tmp_path / "widened.json", widened)

    exit_code = main(
        ["verify", str(envelope_file), "--keys", str(keys_file), "--mandate", str(path)]
    )

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "NOT THIS RECEIPT'S" in out
    assert "commits to different mandate content" in out
    # Measuring the action against the wrong grant would answer a question
    # nobody asked, so scope is not reported at all.
    assert "scope" not in out


def test_the_receipt_in_a_pair_is_checked_against_its_grant(
    tmp_path, outcome_file, receipt_file, mandate_file, keys_file, capsys
):
    exit_code = main(
        [
            "verify",
            str(outcome_file),
            "--keys",
            str(keys_file),
            "--receipt",
            str(receipt_file),
            "--mandate",
            str(mandate_file),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == VERIFIED
    assert "binding    OK" in out
    assert "scope      OK" in out


def test_a_mandate_without_an_action_receipt_is_a_usage_error(
    outcome_file, mandate_file, keys_file, capsys
):
    exit_code = main(
        ["verify", str(outcome_file), "--keys", str(keys_file), "--mandate", str(mandate_file)]
    )

    assert exit_code == BAD_INPUT
    assert "applies when an action receipt" in capsys.readouterr().err


def test_mandate_flag_pointing_at_a_receipt_is_rejected(envelope_file, keys_file, capsys):
    exit_code = main(
        ["verify", str(envelope_file), "--keys", str(keys_file), "--mandate", str(envelope_file)]
    )

    assert exit_code == BAD_INPUT
    assert "does not contain a mandate" in capsys.readouterr().err


@pytest.fixture
def delegated_mandate_file(tmp_path) -> Path:
    return write_envelope(tmp_path / "delegated.json", DELEGATED_VECTOR["envelope"])


@pytest.fixture
def delegated_receipt_file(tmp_path) -> Path:
    return write_envelope(tmp_path / "sub-receipt.json", DELEGATED_RECEIPT_VECTOR["envelope"])


def test_a_sound_delegation_chain_verifies(
    delegated_receipt_file, mandate_file, delegated_mandate_file, keys_file, capsys
):
    exit_code = main(
        [
            "verify",
            str(delegated_receipt_file),
            "--keys",
            str(keys_file),
            "--mandate",
            str(mandate_file),
            "--mandate",
            str(delegated_mandate_file),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == VERIFIED
    assert "chain      OK, answering to user:1234 (human)" in out
    assert "scope      OK" in out


def test_a_widened_delegation_names_the_hop_that_broke(
    tmp_path, delegated_receipt_file, mandate_file, keys_file, capsys
):
    widened = document(DELEGATED_VECTOR).model_copy(
        update={"max_value": Money(amount=Decimal("500"), currency="USD")}
    )
    path = write_envelope(
        tmp_path / "widened.json",
        sign(widened, "key-1", PRIVATE_KEYS["key-1"]).model_dump(mode="json", exclude_none=True),
    )

    exit_code = main(
        [
            "verify",
            str(delegated_receipt_file),
            "--keys",
            str(keys_file),
            "--mandate",
            str(mandate_file),
            "--mandate",
            str(path),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "chain      BROKEN" in out
    assert "grant 2: the delegated ceiling is above the parent's" in out
    # Scope is not reported against a chain that does not hold up.
    assert "scope" not in out


def test_a_chain_given_out_of_order_is_rejected(
    delegated_receipt_file, mandate_file, delegated_mandate_file, keys_file, capsys
):
    exit_code = main(
        [
            "verify",
            str(delegated_receipt_file),
            "--keys",
            str(keys_file),
            "--mandate",
            str(delegated_mandate_file),
            "--mandate",
            str(mandate_file),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "the first grant in the chain is itself delegated" in out


def test_the_sequence_command_reports_an_intact_run(tmp_path, keys_file, capsys):
    from support import FOLLOWING_RECEIPT_VECTOR

    first = write_envelope(tmp_path / "1.json", RECEIPT_VECTOR["envelope"])
    second = write_envelope(tmp_path / "2.json", FOLLOWING_RECEIPT_VECTOR["envelope"])

    exit_code = main(["sequence", str(first), str(second), "--keys", str(keys_file)])

    out = capsys.readouterr().out
    assert exit_code == VERIFIED
    assert "sequence   intact, 2 receipt(s)" in out


def test_the_sequence_command_reports_a_gap(tmp_path, keys_file, capsys):
    from support import FOLLOWING_RECEIPT_VECTOR

    # The second receipt links to a predecessor that was not handed over.
    only_the_second = write_envelope(tmp_path / "2.json", FOLLOWING_RECEIPT_VECTOR["envelope"])

    exit_code = main(["sequence", str(only_the_second), "--keys", str(keys_file)])

    out = capsys.readouterr().out
    assert exit_code == NOT_VERIFIED
    assert "begins part-way through a longer sequence" in out


def test_the_sequence_command_rejects_a_non_receipt(tmp_path, mandate_file, keys_file, capsys):
    exit_code = main(["sequence", str(mandate_file), "--keys", str(keys_file)])

    assert exit_code == BAD_INPUT
    assert "does not contain an action receipt" in capsys.readouterr().err
