"""Public key directories.

Keys are read from a JWKS (RFC 7517) holding Ed25519 keys in the OKP form
defined by RFC 8037. Reusing that standard rather than inventing a format means
a directory already published for any other Ed25519 consumer works here
unchanged, and the encoding of a public key is somebody else's settled problem.

Unlike a signed document, a key directory is not covered by any signature, so
unrecognized members of a JWK are ignored rather than rejected. Nothing a
verifier ignores here can change which bytes a signature was checked against;
only `crv` and `x` decide what the key is, and both are validated strictly.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ED25519_PUBLIC_KEY_SIZE = 32


def _raw(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """The 32 bytes of a public key, which is what every encoding here wraps."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def read_key_directory(path: Path) -> dict[str, ed25519.Ed25519PublicKey]:
    try:
        directory = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path} is not valid JSON: {error}") from error
    return public_keys_from_jwks(directory)


def public_keys_from_jwks(directory: Any) -> dict[str, ed25519.Ed25519PublicKey]:
    if not isinstance(directory, dict) or not isinstance(directory.get("keys"), list):
        raise ValueError("a key directory is a JSON object with a 'keys' array")

    public_keys: dict[str, ed25519.Ed25519PublicKey] = {}
    for position, jwk in enumerate(directory["keys"]):
        key_id, public_key = _read_jwk(jwk, position)
        if key_id in public_keys:
            raise ValueError(f"key id {key_id!r} appears more than once")
        public_keys[key_id] = public_key
    return public_keys


def _read_jwk(jwk: Any, position: int) -> tuple[str, ed25519.Ed25519PublicKey]:
    where = f"key {position}"
    if not isinstance(jwk, dict):
        raise ValueError(f"{where} is not a JSON object")

    key_id = jwk.get("kid")
    if not isinstance(key_id, str) or not key_id:
        raise ValueError(f"{where} has no usable 'kid'")

    # Every key in the directory must be one this format can actually use. A
    # directory carrying key types we silently skip would fail later as an
    # unknown signer, which is a much harder failure to diagnose.
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError(f"key {key_id!r} is not an Ed25519 OKP key")

    encoded = jwk.get("x")
    if not isinstance(encoded, str):
        raise ValueError(f"key {key_id!r} has no 'x' value")

    try:
        # validate=True matters: by default the decoder discards characters
        # outside the alphabet, so a corrupted value decodes to something
        # shorter instead of failing, and would be accepted outright if it
        # happened to land on the right length.
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except Exception as error:
        raise ValueError(f"key {key_id!r} is not valid base64url") from error

    if len(raw) != ED25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"key {key_id!r} is {len(raw)} bytes, but an Ed25519 public key is "
            f"{ED25519_PUBLIC_KEY_SIZE}"
        )

    return key_id, ed25519.Ed25519PublicKey.from_public_bytes(raw)


def jwks_from_public_keys(public_keys: dict[str, ed25519.Ed25519PublicKey]) -> dict[str, Any]:
    """Build a key directory. Used to publish a directory and in tests."""
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": key_id,
                "x": base64.urlsafe_b64encode(_raw(public_key)).rstrip(b"=").decode("ascii"),
            }
            for key_id, public_key in public_keys.items()
        ]
    }


DID_KEY_PREFIX = "did:key:z"

# The multicodec tag for an Ed25519 public key, written as the varint 0xed 0x01.
# Spelled as integers rather than an escaped literal so the value is readable.
ED25519_MULTICODEC = bytes((0xED, 0x01))

# base58btc, the alphabet multibase selects with a leading "z". It omits 0, O,
# I and l, so an identifier survives being read aloud or copied by hand.
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def is_did_key(key_id: str) -> bool:
    """Whether a key id claims to carry the public key it names.

    A claim only. Whether it carries a usable key is answered by
    did_to_public_key, which is the function that decides.
    """
    return key_id.startswith(DID_KEY_PREFIX)


def public_key_to_did(public_key: ed25519.Ed25519PublicKey) -> str:
    """The did:key identifier for a public key.

    This is the whole of the convention: the identifier is the key, so a
    verifier holding a document needs nothing else to check the signature on it.
    """
    return DID_KEY_PREFIX + _base58_encode(ED25519_MULTICODEC + _raw(public_key))


def did_to_public_key(did: str) -> ed25519.Ed25519PublicKey:
    """The public key a did:key identifier carries.

    Every failure is a ValueError, because an identifier that does not decode
    to an Ed25519 key is not a key this format can use, and guessing at what
    was meant is how an unusable key becomes a trusted one.
    """
    if not is_did_key(did):
        raise ValueError(f"{did!r} is not a did:key identifier")

    decoded = _base58_decode(did[len(DID_KEY_PREFIX) :], did)

    # Checked before the length, so a key of the right size under another
    # algorithm's tag is refused as the wrong algorithm rather than accepted.
    # This is the same reason the signature's alg field is pinned instead of
    # dispatched on: the document does not get to choose the algorithm.
    if not decoded.startswith(ED25519_MULTICODEC):
        raise ValueError(f"{did!r} does not carry an Ed25519 key")

    raw = decoded[len(ED25519_MULTICODEC) :]
    if len(raw) != ED25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"{did!r} carries {len(raw)} bytes, but an Ed25519 public key is "
            f"{ED25519_PUBLIC_KEY_SIZE}"
        )

    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


class KeyDirectory(Mapping[str, ed25519.Ed25519PublicKey]):
    """A key directory that also resolves key ids carrying their own key.

    Wraps a directory read from a JWKS, and answers for any did:key identifier
    besides. It is a Mapping, so it goes wherever a directory goes --
    verified_signers and author_signed take it unchanged.

    **What a self-describing key settles, and what it does not.** Resolving one
    proves that the signature came from the key named in the identifier, and
    nothing more. It does not say that key is anybody in particular; a did:key
    is trivial to mint, so an attacker can produce a document that verifies
    perfectly against a principal nobody has ever heard of. The listed entries
    in a JWKS are the part that says *whose* key it is.

    So this is right for an agent, whose key is generated per deployment and
    would otherwise have to be registered somewhere before it could act, and
    the caller still has to recognise the principal at the root of the chain.

    Membership is open: `key_id in directory` answers for any valid did:key,
    while iteration and len cover only the listed entries, since the
    self-describing ones are not a set anybody can enumerate.
    """

    def __init__(self, listed: Mapping[str, ed25519.Ed25519PublicKey] | None = None) -> None:
        self._listed = dict(listed or {})
        for key_id, entry in self._listed.items():
            if not is_did_key(key_id):
                continue
            # A listed did:key that disagrees with the key it carries is either
            # a corrupted directory or an attempt to have one identifier mean
            # two keys. Caught when the directory is loaded rather than when
            # something fails to verify, which is much harder to read.
            if _raw(did_to_public_key(key_id)) != _raw(entry):
                raise ValueError(f"key {key_id!r} does not match the key its own id carries")

    def __getitem__(self, key_id: str) -> ed25519.Ed25519PublicKey:
        if is_did_key(key_id):
            try:
                return did_to_public_key(key_id)
            except ValueError as error:
                # Reported as absent, not raised: this is consulted while
                # checking signatures on input from outside, and a malformed
                # identifier must fail that check rather than the whole run.
                raise KeyError(key_id) from error
        return self._listed[key_id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._listed)

    def __len__(self) -> int:
        return len(self._listed)

    def __repr__(self) -> str:
        return f"KeyDirectory({self._listed!r})"


def _base58_encode(raw: bytes) -> str:
    value = int.from_bytes(raw, "big")
    digits = ""
    while value > 0:
        value, remainder = divmod(value, 58)
        digits = BASE58_ALPHABET[remainder] + digits

    # A leading zero byte contributes nothing to the integer, so it has to be
    # carried across separately or every key beginning 0x00 would encode short.
    leading_zeros = len(raw) - len(raw.lstrip(b"\x00"))
    return BASE58_ALPHABET[0] * leading_zeros + digits


def _base58_decode(text: str, did: str) -> bytes:
    value = 0
    for character in text:
        position = BASE58_ALPHABET.find(character)
        if position < 0:
            # Not skipped. A decoder that ignores what it does not recognise
            # turns a corrupted identifier into a different valid one.
            raise ValueError(f"{did!r} contains {character!r}, which is not base58btc")
        value = value * 58 + position

    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    leading_zeros = len(text) - len(text.lstrip(BASE58_ALPHABET[0]))
    return b"\x00" * leading_zeros + body
