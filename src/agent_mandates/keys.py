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
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ED25519_PUBLIC_KEY_SIZE = 32


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
                "x": base64.urlsafe_b64encode(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                )
                .rstrip(b"=")
                .decode("ascii"),
            }
            for key_id, public_key in public_keys.items()
        ]
    }
