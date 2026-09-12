import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_mandates.keys import jwks_from_public_keys, public_keys_from_jwks, read_key_directory

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
