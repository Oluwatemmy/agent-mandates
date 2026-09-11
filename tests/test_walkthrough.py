"""The README example, executed.

An example nobody runs is an example that stops working. This runs the real
file and verifies its output through the real command line tool, so the
documented flow cannot drift from the library.
"""

import sys
from pathlib import Path

import pytest

from agent_receipts.cli import VERIFIED
from agent_receipts.cli import main as verify

EXAMPLES = Path(__file__).parent.parent / "examples"
sys.path.insert(0, str(EXAMPLES))

import walkthrough  # noqa: E402


@pytest.fixture
def written(tmp_path) -> Path:
    walkthrough.main(tmp_path)
    return tmp_path


def test_the_walkthrough_writes_the_whole_chain(written):
    assert {path.name for path in written.iterdir()} == {
        "mandate.json",
        "receipt.json",
        "outcome.json",
        "jwks.json",
    }


def test_the_whole_chain_verifies_through_the_command_line(written, capsys):
    exit_code = verify(
        [
            "verify",
            str(written / "outcome.json"),
            "--keys",
            str(written / "jwks.json"),
            "--receipt",
            str(written / "receipt.json"),
            "--mandate",
            str(written / "mandate.json"),
        ]
    )

    out = capsys.readouterr().out
    assert exit_code == VERIFIED
    assert "binding    OK" in out
    assert "scope      OK" in out
    assert "answering to user:alice" in out


def test_written_envelopes_omit_absent_optional_fields(written):
    # to_json writes the format's convention rather than pydantic's default,
    # which would emit nulls.
    assert "null" not in (written / "receipt.json").read_text(encoding="utf-8")


def test_the_published_directory_holds_only_public_keys(written):
    published = (written / "jwks.json").read_text(encoding="utf-8")

    assert "seed" not in published
    assert '"d"' not in published  # the JWK member a private key would occupy
