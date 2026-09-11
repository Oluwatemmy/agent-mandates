"""Reduction of a document to the exact form that gets signed.

The pipeline is:

    document -> canonical JSON value -> canonical bytes -> signature

Values are already canonical by the time a document exists (see models.py), so
canonical_json_value only settles how the document is shaped as JSON, and
canonical_json_bytes settles how that shape is written out.
"""

from __future__ import annotations

import json
from typing import Any

from agent_receipts.models import ActionReceipt, Mandate, OutcomeAttestation

SignedDocument = ActionReceipt | OutcomeAttestation | Mandate

# Only these appear in a canonical document. There are deliberately no JSON
# numbers: RFC 8785 serializes them as IEEE 754 doubles, which would silently
# round any amount or large integer before it was signed.
JsonValue = dict[str, "JsonValue"] | list["JsonValue"] | str


def canonical_json_value(document: SignedDocument) -> dict[str, Any]:
    """The JSON value that will be serialized and signed.

    Absent optional fields are omitted rather than written as null, so that a
    document carrying no loss has one representation instead of two.

    The document is revalidated first. Pydantic's model_copy(update=...) skips
    validators, so an object in memory is not guaranteed to hold canonical
    values -- an unsorted scope, say. Without this, signing such an object would
    produce a signature that stops verifying the moment the document is written
    to JSON and read back, which is silent and precisely the failure this
    library exists to prevent. Canonical form is defined by the rules, not by
    however the object happened to be built.
    """
    normalized = type(document).model_validate(document.model_dump())
    return normalized.model_dump(mode="json", exclude_none=True)


def canonical_json_bytes(value: JsonValue) -> bytes:
    """Serialize a JSON value to its RFC 8785 canonical bytes.

    Four rules, all of them normative:

    1. Object keys are sorted by their **UTF-16 code units** compared as
       unsigned integers -- not by code point. The two orders disagree above
       U+FFFF, because a character there becomes a surrogate pair whose lead
       unit (U+D800-U+DBFF) sorts below ordinary BMP characters such as U+FB33.

    2. Inside strings, U+0008, U+0009, U+000A, U+000C and U+000D are written as
       \\b, \\t, \\n, \\f and \\r. Any other character in U+0000-U+001F is
       written as \\uhhhh with **lowercase** hex. U+0022 and U+005C are written
       as \\" and \\\\.

    3. Every other character is emitted as is, including C1 controls such as
       U+0080. Only the seven characters above are ever escaped.

    4. No whitespace anywhere, and the output is UTF-8.

    Only rule 1 is implemented here. Rules 2 to 4 are exactly what the standard
    library already emits with ensure_ascii disabled and no separators padding,
    verified against the reference implementation in the differential tests.
    """
    return json.dumps(
        _with_keys_in_utf16_order(value),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _with_keys_in_utf16_order(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [_with_keys_in_utf16_order(item) for item in value]
    if isinstance(value, dict):
        # Sorted on the UTF-16 encoding rather than with json's sort_keys, which
        # orders by code point. The two disagree above U+FFFF, where a character
        # becomes a surrogate pair whose lead unit (U+D800-U+DBFF) sorts below
        # ordinary BMP characters such as U+FB33.
        return {
            name: _with_keys_in_utf16_order(value[name])
            for name in sorted(value, key=lambda name: name.encode("utf-16-be"))
        }
    # Reached only if a numeric or boolean field is added to a document. JSON
    # numbers are IEEE 754 doubles under RFC 8785, so allowing one through would
    # mean signing a silently rounded value.
    raise TypeError(f"canonical documents contain no {type(value).__name__} values")


def canonical_bytes(document: SignedDocument) -> bytes:
    """The exact bytes a signature is computed over."""
    return canonical_json_bytes(canonical_json_value(document))
