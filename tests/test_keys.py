import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_mandates.canonical import canonical_bytes
from agent_mandates.keys import (
    KeyDirectory,
    _base58_decode,
    _base58_encode,
    did_to_public_key,
    jwks_from_public_keys,
    public_key_to_did,
    public_keys_from_jwks,
    read_key_directory,
)
from agent_mandates.signing import (
    Signature,
    SignedEnvelope,
    author_signed,
    sign,
    verified_signers,
)
from support import RECEIPT_VECTOR, document

SIGNING_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_KEY = SIGNING_KEY.public_key()


def directory_with(**overrides) -> dict:
    jwk = {**jwks_from_public_keys({"key-1": PUBLIC_KEY})["keys"][0], **overrides}
    return {"keys": [jwk]}


def test_a_published_directory_reads_back_as_the_same_keys():
    directory = jwks_from_public_keys({"key-1": PUBLIC_KEY})

    restored = public_keys_from_jwks(directory)

    assert list(restored) == ["key-1"]
    restored["key-1"].verify(SIGNING_KEY.sign(b"payload"), b"payload")


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"kty": "RSA"}, "not an Ed25519 OKP key"),
        ({"crv": "X25519"}, "not an Ed25519 OKP key"),
        ({"kid": ""}, "no usable 'kid'"),
        ({"x": "not-base-64-!"}, "not valid base64url"),
        ({"x": "AAAA"}, "Ed25519 public key"),
    ],
)
def test_rejects_keys_it_cannot_use(overrides, reason):
    with pytest.raises(ValueError, match=reason):
        public_keys_from_jwks(directory_with(**overrides))


def test_rejects_a_kid_that_appears_twice():
    directory = jwks_from_public_keys({"key-1": PUBLIC_KEY})
    directory["keys"].append(directory["keys"][0])

    with pytest.raises(ValueError, match="more than once"):
        public_keys_from_jwks(directory)


@pytest.mark.parametrize("directory", [[], {}, {"keys": {}}, "keys", None])
def test_rejects_anything_that_is_not_a_key_directory(directory):
    with pytest.raises(ValueError, match="'keys' array"):
        public_keys_from_jwks(directory)


def test_ignores_unrecognized_jwk_members():
    # A key directory is not covered by any signature, and only crv and x decide
    # what the key is, so extra members are harmless here.
    restored = public_keys_from_jwks(directory_with(use="sig", alg="EdDSA", ext=True))

    assert list(restored) == ["key-1"]


def test_reports_the_file_when_the_directory_is_not_json(tmp_path):
    path = tmp_path / "jwks.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError, match="is not valid JSON"):
        read_key_directory(path)


def test_reads_a_directory_from_disk(tmp_path):
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(jwks_from_public_keys({"key-1": PUBLIC_KEY})), encoding="utf-8")

    assert list(read_key_directory(path)) == ["key-1"]


# Published in the did:key specification's examples and test vectors, and
# produced by implementations that are not this one. They are the conformance
# anchor: the alphabet, the ordering and the multicodec tag all have to be
# right for an externally minted identifier to decode to 0xed01 plus exactly
# thirty-two bytes and re-encode to the same string.
SPEC_DIDS = [
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
]

OUR_DID = public_key_to_did(PUBLIC_KEY)


@pytest.mark.parametrize("did", SPEC_DIDS)
def test_an_identifier_minted_elsewhere_decodes_and_encodes_back(did):
    assert public_key_to_did(did_to_public_key(did)) == did


def test_a_key_survives_the_round_trip_through_its_identifier():
    restored = did_to_public_key(public_key_to_did(PUBLIC_KEY))

    restored.verify(SIGNING_KEY.sign(b"payload"), b"payload")


def test_base58btc_carries_leading_zero_bytes():
    # Unreachable through Ed25519, whose multicodec tag begins 0xed, but the
    # encoding is named in FORMAT.md as base58btc and a partial implementation
    # of a named standard is a trap for whoever reuses it next.
    assert _base58_encode(b"\x00\x00\x01") == "11" + _base58_encode(b"\x01")
    assert _base58_decode("11" + _base58_encode(b"\x01"), "test") == b"\x00\x00\x01"


@pytest.mark.parametrize(
    ("did", "reason"),
    [
        ("key-1", "not a did:key identifier"),
        ("did:key:" + OUR_DID[len("did:key:z") :], "not a did:key identifier"),
        ("did:key:z" + "0" + OUR_DID[len("did:key:z") + 1 :], "not base58btc"),
        ("did:key:zIOl", "not base58btc"),
        # 0xec 0x01 is X25519: the right length under the wrong algorithm.
        ("did:key:z" + _base58_encode(bytes((0xEC, 0x01)) + bytes(32)), "not carry an Ed25519"),
        (OUR_DID[:-1], "does not carry an Ed25519 key"),
        ("did:key:z" + _base58_encode(bytes((0xED, 0x01)) + bytes(31)), "31 bytes"),
        ("did:key:z" + _base58_encode(bytes((0xED, 0x01)) + bytes(33)), "33 bytes"),
    ],
)
def test_rejects_identifiers_that_are_not_a_usable_key(did, reason):
    with pytest.raises(ValueError, match=reason):
        did_to_public_key(did)


def test_a_directory_still_answers_for_the_keys_it_lists():
    directory = KeyDirectory({"key-1": PUBLIC_KEY})

    assert directory["key-1"] is PUBLIC_KEY
    assert "key-1" in directory
    assert list(directory) == ["key-1"] and len(directory) == 1


def test_a_directory_answers_for_a_key_it_was_never_given():
    directory = KeyDirectory()

    directory[OUR_DID].verify(SIGNING_KEY.sign(b"payload"), b"payload")
    assert OUR_DID in directory


def test_self_describing_keys_are_not_enumerable():
    # Membership is open but iteration is not, so nothing can treat the listed
    # entries as the complete set of keys this directory will answer for.
    directory = KeyDirectory({"key-1": PUBLIC_KEY})

    assert OUR_DID in directory
    assert OUR_DID not in list(directory)


def test_a_malformed_self_describing_key_is_absent_rather_than_an_error():
    # Consulted while checking signatures on input from outside, where a raised
    # exception would take down the whole verification instead of failing the
    # one signature that deserves to fail.
    directory = KeyDirectory()

    assert directory.get("did:key:znonsense") is None
    with pytest.raises(KeyError):
        directory["did:key:znonsense"]


def test_a_listed_did_key_that_disagrees_with_itself_is_refused():
    # One identifier naming two different keys. Caught when the directory loads
    # rather than as a signature that mysteriously fails to verify.
    other = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key()

    with pytest.raises(ValueError, match="does not match the key its own id carries"):
        KeyDirectory({OUR_DID: other})


def test_a_listed_did_key_agreeing_with_itself_is_allowed():
    # Publishing one in a JWKS alongside other keys is redundant, not wrong.
    # What comes back is decoded from the identifier rather than taken from the
    # listing, which is immaterial only because the two were checked to agree.
    listed = KeyDirectory({OUR_DID: PUBLIC_KEY})[OUR_DID]

    listed.verify(SIGNING_KEY.sign(b"payload"), b"payload")


def test_a_receipt_verifies_with_no_directory_at_all():
    # The point of the whole convention. An agent generates a keypair, names
    # itself by it, and its receipts are checkable by someone who has never
    # heard of it and has nothing to look the key up in.
    receipt = document(RECEIPT_VECTOR)
    self_named = receipt.model_copy(
        update={"agent": receipt.agent.model_copy(update={"key_id": OUR_DID})}
    )

    envelope = sign(self_named, OUR_DID, SIGNING_KEY)

    assert author_signed(envelope, KeyDirectory())
    assert verified_signers(envelope, KeyDirectory()) == {OUR_DID}


def test_naming_yourself_by_a_key_you_do_not_hold_still_fails():
    # Self-describing removes the lookup, not the signature check. Claiming
    # somebody else's did gets you a document that verifies against nobody.
    receipt = document(RECEIPT_VECTOR)
    impostor = receipt.model_copy(
        update={"agent": receipt.agent.model_copy(update={"key_id": SPEC_DIDS[0]})}
    )
    # Labelled with the did it claims, signed by the key it actually holds.
    # Built by hand because sign() refuses to produce it.
    forged = base64.urlsafe_b64encode(SIGNING_KEY.sign(canonical_bytes(impostor)))
    envelope = SignedEnvelope(
        payload=impostor,
        signatures=(Signature(key_id=SPEC_DIDS[0], value=forged.rstrip(b"=").decode("ascii")),),
    )

    assert verified_signers(envelope, KeyDirectory()) == frozenset()
    assert author_signed(envelope, KeyDirectory()) is False
