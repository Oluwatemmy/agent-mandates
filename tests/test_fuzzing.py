"""Malformed input at every untrusted boundary.

Everything here has one shape: garbage in must produce a clean refusal, never an
unexpected exception and never acceptance. A verifier that crashes on bad input
is a verifier that can be knocked over by anyone who can hand it a file.
"""

import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from agent_mandates.canonical import MAX_DEPTH, canonical_json_bytes
from agent_mandates.cli import BAD_INPUT, main
from agent_mandates.keys import public_keys_from_jwks
from agent_mandates.signing import SignedEnvelope
from support import MANDATE_VECTOR, RECEIPT_VECTOR

FUZZ = settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow], deadline=None)

# Anything a caller can reasonably be asked to handle. A refusal outside this
# set is a crash wearing a different name.
CLEAN_REFUSAL = (ValidationError, ValueError, TypeError)


def nested(depth: int) -> dict:
    root: dict = {}
    node = root
    for _ in range(depth):
        node["k"] = {}
        node = node["k"]
    return root


@FUZZ
@given(st.binary(max_size=2000))
def test_arbitrary_bytes_never_parse_as_an_envelope(payload):
    with pytest.raises(CLEAN_REFUSAL):
        SignedEnvelope.model_validate_json(payload)


@FUZZ
@given(st.text(max_size=2000))
def test_arbitrary_text_never_parses_as_an_envelope(payload):
    with pytest.raises(CLEAN_REFUSAL):
        SignedEnvelope.model_validate_json(payload)


@FUZZ
@given(
    st.recursive(
        st.none()
        | st.booleans()
        | st.integers()
        | st.floats(allow_nan=False)
        | st.text(max_size=20),
        lambda children: (
            st.lists(children, max_size=3)
            | st.dictionaries(st.text(max_size=10), children, max_size=3)
        ),
        max_leaves=8,
    )
)
def test_arbitrary_json_values_never_parse_as_an_envelope(value):
    with pytest.raises(CLEAN_REFUSAL):
        SignedEnvelope.model_validate(value)


@FUZZ
@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=20),
        lambda children: (
            st.lists(children, max_size=3)
            | st.dictionaries(st.text(max_size=10), children, max_size=3)
        ),
        max_leaves=8,
    )
)
def test_arbitrary_json_values_never_parse_as_a_key_directory(value):
    with pytest.raises(CLEAN_REFUSAL):
        public_keys_from_jwks(value)


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("truncated", json.dumps(MANDATE_VECTOR["envelope"])[:200]),
        ("empty", ""),
        ("null", "null"),
        ("array", "[]"),
        ("payload is a string", '{"payload":"x","signatures":[]}'),
        ("signatures is a string", '{"payload":{},"signatures":"x"}'),
        ("deeply nested", "[" * 5000 + "]" * 5000),
        ("unknown document type", '{"payload":{"type":"invoice"},"signatures":[]}'),
    ],
)
def test_malformed_envelopes_are_refused_cleanly(label, payload):
    with pytest.raises(CLEAN_REFUSAL):
        SignedEnvelope.model_validate_json(payload)


def test_an_oversized_identifier_is_refused_rather_than_processed():
    envelope = json.loads(json.dumps(MANDATE_VECTOR["envelope"]))
    envelope["payload"]["agent"]["id"] = "a" * 1_000_000

    with pytest.raises(ValidationError):
        SignedEnvelope.model_validate(envelope)


def test_deep_nesting_is_refused_rather_than_exhausting_the_stack():
    # Serialization recurses. Before the depth limit this raised RecursionError,
    # which is a crash rather than a refusal, and callers may hand this
    # untrusted input.
    with pytest.raises(ValueError, match="nested deeper than"):
        canonical_json_bytes(nested(MAX_DEPTH + 1))


def test_nesting_at_the_limit_is_still_serialized():
    assert canonical_json_bytes(nested(MAX_DEPTH - 1))


@pytest.mark.parametrize(
    "directory",
    [
        {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": "A" * 1_000_000}]},
        {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": [1, 2]}]},
        {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": None, "x": "AAAA"}]},
        {"keys": [[]]},
        {"keys": [None]},
    ],
)
def test_malformed_key_directories_are_refused_cleanly(directory):
    with pytest.raises(CLEAN_REFUSAL):
        public_keys_from_jwks(directory)


@pytest.mark.parametrize(
    "content",
    [b"", b"not json", b"[]", b"null", b'{"payload":{}}', bytes(range(256))],
)
def test_the_cli_reports_bad_input_rather_than_crashing(tmp_path, content, capsys):
    envelope = tmp_path / "envelope.json"
    envelope.write_bytes(content)
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": []}), encoding="utf-8")

    assert main(["verify", str(envelope), "--keys", str(keys)]) == BAD_INPUT
    assert capsys.readouterr().err.startswith("error:")


@pytest.mark.parametrize("content", [b"", b"not json", b'{"keys":{}}', b'{"keys":[{}]}'])
def test_the_cli_reports_a_bad_key_directory_rather_than_crashing(tmp_path, content, capsys):
    envelope = tmp_path / "envelope.json"
    envelope.write_text(json.dumps(RECEIPT_VECTOR["envelope"]), encoding="utf-8")
    keys = tmp_path / "keys.json"
    keys.write_bytes(content)

    assert main(["verify", str(envelope), "--keys", str(keys)]) == BAD_INPUT
    assert "cannot read key directory" in capsys.readouterr().err


def test_the_cli_reports_a_missing_file_rather_than_crashing(tmp_path, capsys):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": []}), encoding="utf-8")

    assert main(["verify", str(tmp_path / "absent.json"), "--keys", str(keys)]) == BAD_INPUT
    assert capsys.readouterr().err.startswith("error:")
