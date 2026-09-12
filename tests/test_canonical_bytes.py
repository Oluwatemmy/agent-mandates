"""RFC 8785 serialization.

The reference implementation (the rfc8785 package) is the oracle in the
differential tests, but it is a test-only dependency. The implementation under
test is ours, so a disagreement is a real finding rather than version skew.

Expected strings are built from chr() rather than written as escape sequences,
so that a test about escaping does not itself depend on escaping.
"""

import json

import pytest
import rfc8785

from agent_mandates.canonical import canonical_bytes, canonical_json_bytes
from support import DOCUMENT_TYPES, VECTOR_PATHS

BACKSLASH = chr(0x5C)
QUOTE = chr(0x22)
CARRIAGE_RETURN = chr(0x0D)
O_DIAERESIS = chr(0xF6)
C1_CONTROL = chr(0x80)
EURO = chr(0x20AC)
GRINNING_FACE = chr(0x1F600)
DALET_WITH_DAGESH = chr(0xFB33)


def quoted(text):
    return QUOTE + text + QUOTE


def one_key_object(value):
    return ("{" + quoted("k") + ":" + quoted(value) + "}").encode("utf-8")


# RFC 8785 Section 3.2.3. The keys are given out of order and span the BMP
# boundary, so this pins both the sort and the escaping.
RFC_EXAMPLE = {
    EURO: "Euro Sign",
    CARRIAGE_RETURN: "Carriage Return",
    DALET_WITH_DAGESH: "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    GRINNING_FACE: "Emoji: Grinning Face",
    C1_CONTROL: "Control",
    O_DIAERESIS: "Latin Small Letter O With Diaeresis",
}
RFC_EXAMPLE_CANONICAL = (
    "{"
    + quoted(BACKSLASH + "r")
    + ":"
    + quoted("Carriage Return")
    + ","
    + quoted("1")
    + ":"
    + quoted("One")
    + ","
    + quoted(C1_CONTROL)
    + ":"
    + quoted("Control")
    + ","
    + quoted(O_DIAERESIS)
    + ":"
    + quoted("Latin Small Letter O With Diaeresis")
    + ","
    + quoted(EURO)
    + ":"
    + quoted("Euro Sign")
    + ","
    + quoted(GRINNING_FACE)
    + ":"
    + quoted("Emoji: Grinning Face")
    + ","
    + quoted(DALET_WITH_DAGESH)
    + ":"
    + quoted("Hebrew Letter Dalet With Dagesh")
    + "}"
).encode("utf-8")


def test_rfc_worked_example():
    assert canonical_json_bytes(RFC_EXAMPLE) == RFC_EXAMPLE_CANONICAL


def test_keys_sort_by_utf16_code_unit_not_code_point():
    # By code point U+FB33 precedes U+1F600. In UTF-16 the emoji is the
    # surrogate pair D83D DE00, and D83D sorts below FB33, so it comes first.
    serialized = canonical_json_bytes({DALET_WITH_DAGESH: "hebrew", GRINNING_FACE: "emoji"}).decode(
        "utf-8"
    )

    assert serialized.index("emoji") < serialized.index("hebrew")


def test_output_has_no_whitespace():
    serialized = canonical_json_bytes({"b": "two", "a": ["one", {"c": "three"}]})

    assert serialized == b'{"a":["one",{"c":"three"}],"b":"two"}'


@pytest.mark.parametrize(
    ("character", "escaped"),
    [
        (chr(0x08), BACKSLASH + "b"),
        (chr(0x09), BACKSLASH + "t"),
        (chr(0x0A), BACKSLASH + "n"),
        (chr(0x0C), BACKSLASH + "f"),
        (chr(0x0D), BACKSLASH + "r"),
        (QUOTE, BACKSLASH + QUOTE),
        (BACKSLASH, BACKSLASH + BACKSLASH),
    ],
)
def test_short_escapes(character, escaped):
    assert canonical_json_bytes({"k": character}) == one_key_object(escaped)


@pytest.mark.parametrize(
    ("character", "escaped"),
    [
        (chr(0x00), BACKSLASH + "u0000"),
        (chr(0x01), BACKSLASH + "u0001"),
        (chr(0x0B), BACKSLASH + "u000b"),
        (chr(0x1F), BACKSLASH + "u001f"),
    ],
)
def test_remaining_control_characters_use_lowercase_hex_escapes(character, escaped):
    assert canonical_json_bytes({"k": character}) == one_key_object(escaped)


@pytest.mark.parametrize("character", [chr(0x7F), C1_CONTROL, O_DIAERESIS, EURO, GRINNING_FACE])
def test_everything_else_is_emitted_as_is(character):
    # Only the seven short escapes are ever applied. DEL and C1 controls such
    # as U+0080 are written out literally.
    assert canonical_json_bytes({"k": character}) == one_key_object(character)


def test_empty_containers():
    assert canonical_json_bytes({"a": {}, "b": []}) == b'{"a":{},"b":[]}'


def test_array_order_is_preserved():
    assert canonical_json_bytes({"a": ["c", "b", "a"]}) == b'{"a":["c","b","a"]}'


def test_rejects_values_that_have_no_canonical_json_form():
    # A numeric field would be serialized as an IEEE 754 double and silently
    # rounded before signing, so it must fail loudly instead.
    with pytest.raises(TypeError):
        canonical_json_bytes({"retry_count": 3})


@pytest.mark.parametrize("vector_path", VECTOR_PATHS, ids=lambda path: path.stem)
def test_documents_match_the_reference_implementation(vector_path):
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    document = DOCUMENT_TYPES[vector["document_type"]].model_validate(vector["input"])

    assert canonical_bytes(document) == rfc8785.dumps(vector["canonical"])


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"": ""},
        {"a": "", "": "a"},
        RFC_EXAMPLE,
        {"nested": {"deep": {"deeper": ["x", {"y": "z"}]}}},
        {GRINNING_FACE: "a", DALET_WITH_DAGESH: "b", C1_CONTROL: "c", "z": "d"},
        {QUOTE + BACKSLASH: chr(0x09) + chr(0x0A)},
        {chr(0x00) + chr(0x1F): "control soup"},
        {"sorted": [GRINNING_FACE, DALET_WITH_DAGESH]},
    ],
)
def test_matches_the_reference_implementation(value):
    assert canonical_json_bytes(value) == rfc8785.dumps(value)
