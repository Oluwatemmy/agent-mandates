"""Golden vectors: frozen input and its expected canonical form.

The expected forms in tests/vectors are written by hand from FORMAT.md, not
generated from this implementation. They are the check that the canonical form
has not drifted, and they are the artifact another implementation of this format
would test against.

Unlike the equivalence tests, these pin absolute output: a change to the
canonical form fails here even if it stays internally consistent.
"""

import json
from pathlib import Path

import pytest

from agent_receipts.canonical import canonical_json_value
from support import DOCUMENT_TYPES, VECTOR_PATHS


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_vectors_are_present():
    # Guards against the glob silently matching nothing and every vector test
    # being skipped without anyone noticing.
    assert VECTOR_PATHS


@pytest.mark.parametrize("vector_path", VECTOR_PATHS, ids=lambda path: path.stem)
def test_input_reduces_to_the_expected_canonical_form(vector_path):
    vector = load(vector_path)
    document_type = DOCUMENT_TYPES[vector["document_type"]]

    document = document_type.model_validate(vector["input"])

    assert canonical_json_value(document) == vector["canonical"]


@pytest.mark.parametrize("vector_path", VECTOR_PATHS, ids=lambda path: path.stem)
def test_canonical_form_is_a_fixed_point(vector_path):
    # Feeding a canonical document back in must produce the same document,
    # otherwise the format has two stable forms rather than one.
    vector = load(vector_path)
    document_type = DOCUMENT_TYPES[vector["document_type"]]

    revalidated = document_type.model_validate(vector["canonical"])

    assert canonical_json_value(revalidated) == vector["canonical"]
