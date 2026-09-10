import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_receipts.cli import BAD_INPUT, NOT_VERIFIED, VERIFIED, main
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


@pytest.fixture
def keys_file(tmp_path) -> Path:
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(jwks_from_public_keys(PUBLIC_KEYS)), encoding="utf-8")
    return path


@pytest.fixture
def envelope_file(tmp_path) -> Path:
    path = tmp_path / "envelope.json"
    path.write_text(json.dumps(RECEIPT_VECTOR["envelope"]), encoding="utf-8")
    return path


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
