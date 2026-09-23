"""Shared access to the golden vectors.

Every test that needs a document or a key reads it from here, so a change to the
vectors is a change in one place rather than in each test file that happened to
hardcode a filename.
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_mandates.models import ActionReceipt, Mandate, OutcomeAttestation

VECTOR_DIR = Path(__file__).parent / "vectors"
VECTOR_PATHS = sorted(VECTOR_DIR.glob("[0-9]*.json"))

DOCUMENT_TYPES = {
    "mandate": Mandate,
    "action": ActionReceipt,
    "outcome": OutcomeAttestation,
}


def load(name: str) -> dict:
    return json.loads((VECTOR_DIR / f"{name}.json").read_text(encoding="utf-8"))


def document(vector: dict):
    """The document a vector's input describes, as the model would build it."""
    return DOCUMENT_TYPES[vector["document_type"]].model_validate(vector["input"])


KEY_MATERIAL = load("keys")["keys"]
PRIVATE_KEYS = {
    key_id: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(entry["seed_hex"]))
    for key_id, entry in KEY_MATERIAL.items()
}
PUBLIC_KEYS = {key_id: private.public_key() for key_id, private in PRIVATE_KEYS.items()}

MANDATE_VECTOR = load("000-mandate-granted")
RECEIPT_VECTOR = load("001-receipt-under-mandate")
MINIMAL_OUTCOME_VECTOR = load("002-outcome-minimal")
OUTCOME_VECTOR = load("003-outcome-disputed-with-loss")
DELEGATED_VECTOR = load("004-mandate-delegated")
DELEGATED_RECEIPT_VECTOR = load("005-receipt-under-delegated-mandate")
FOLLOWING_RECEIPT_VECTOR = load("006-receipt-following-another")
