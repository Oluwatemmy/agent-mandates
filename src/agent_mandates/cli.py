"""Command line verifier.

Reads an envelope and, where one is needed, a key directory, and reports what
the document says and which keys signed it. Given an outcome and the receipt it
reports on, also reports whether the two are actually bound together.

Both files are read from the local filesystem: fetching a key directory over the
network would pull in redirect handling, TLS policy and SSRF exposure, none of
which belong in a tool whose job is to answer one question.
"""

from __future__ import annotations

import argparse
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from agent_mandates.binding import (
    MANDATE_PROBLEM_DESCRIPTIONS,
    PROBLEM_DESCRIPTIONS,
    SEQUENCE_PROBLEM_DESCRIPTIONS,
    binding_problems,
    mandate_problems,
    sequence_problems,
)
from agent_mandates.delegation import (
    DELEGATION_PROBLEM_DESCRIPTIONS,
    accountable_principal,
    chain_problems,
)
from agent_mandates.keys import KeyDirectory, is_did_key, read_key_directory
from agent_mandates.models import ActionReceipt, Mandate, Money, OutcomeAttestation
from agent_mandates.scope import VIOLATION_DESCRIPTIONS, allowed_beyond_mandate, scope_violations
from agent_mandates.signing import (
    SignedEnvelope,
    author_signed,
    required_signer,
    verified_signers,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cryptography.hazmat.primitives.asymmetric import ed25519

    PublicKeys = Mapping[str, ed25519.Ed25519PublicKey]

VERIFIED = 0
NOT_VERIFIED = 1
BAD_INPUT = 2

LABEL_WIDTH = 10


class InputError(Exception):
    """A file could not be read or is not what the caller said it was."""


def main(argv: list[str] | None = None) -> int:
    # Receipt fields carry arbitrary Unicode, and consoles on Windows often
    # cannot encode it. Losing a character from the display is better than the
    # verifier dying while reporting a valid result.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(
        prog="mandates",
        description="Verify signed agent mandates, action receipts and outcome attestations.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify", help="check the signatures on an envelope")
    verify.add_argument("envelope", type=Path, help="signed envelope, as JSON")
    verify.add_argument(
        "--keys",
        type=Path,
        metavar="JWKS",
        help="public key directory, as JWKS; not needed for did:key signers",
    )
    verify.add_argument(
        "--receipt",
        type=Path,
        metavar="ENVELOPE",
        help="the receipt an outcome reports on, to check the two are bound",
    )
    verify.add_argument(
        "--mandate",
        type=Path,
        action="append",
        default=[],
        metavar="ENVELOPE",
        help="the grant a receipt was taken under; repeat root first for a delegation chain",
    )
    verify.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="KEY_ID",
        help="fail unless this key signed; may be repeated",
    )

    sequence = commands.add_parser(
        "sequence", help="check a run of receipts for gaps or reordering"
    )
    sequence.add_argument("envelopes", type=Path, nargs="+", help="receipts, earliest first")
    sequence.add_argument(
        "--keys",
        type=Path,
        metavar="JWKS",
        help="public key directory, as JWKS; not needed for did:key signers",
    )

    arguments = parser.parse_args(argv)
    try:
        return _sequence(arguments) if arguments.command == "sequence" else _verify(arguments)
    except InputError as error:
        print(f"error: {error}", file=sys.stderr)
        return BAD_INPUT


def _sequence(arguments: argparse.Namespace) -> int:
    """Report whether a run of receipts is whole, and where it is not."""
    public_keys = _public_keys(arguments.keys)

    receipts: list[ActionReceipt] = []
    failures: list[str] = []
    for path in arguments.envelopes:
        envelope = _read_envelope(path)
        receipt = envelope.payload
        if not isinstance(receipt, ActionReceipt):
            raise InputError(f"{path} does not contain an action receipt")

        signers = verified_signers(envelope, public_keys)
        unauthored = _authorship_failure(envelope, public_keys, f"receipt {receipt.id}")
        _line(f"#{len(receipts)}", f"{receipt.id} signed by {_signers(signers)}")
        if unauthored:
            failures.append(unauthored)
        receipts.append(receipt)

    positions = sequence_problems(receipts)
    if any(positions):
        _line("sequence", "BROKEN")
        for index, problems in enumerate(positions):
            for problem in sorted(problems):
                _line("", f"- at #{index}: {SEQUENCE_PROBLEM_DESCRIPTIONS[problem]}")
        failures.append("the run is missing receipts or out of order")
    else:
        _line("sequence", f"intact, {len(receipts)} receipt(s)")

    if failures:
        _line("result", f"NOT VERIFIED ({'; '.join(failures)})")
        return NOT_VERIFIED

    _line("result", "VERIFIED")
    return VERIFIED


def _verify(arguments: argparse.Namespace) -> int:
    public_keys = _public_keys(arguments.keys)

    envelope = _read_envelope(arguments.envelope)
    payload = envelope.payload

    supporting_receipt: tuple[SignedEnvelope, ActionReceipt] | None = None
    if arguments.receipt:
        supporting_receipt = _read_receipt(arguments.receipt, envelope)
    mandates = [_read_mandate(path) for path in arguments.mandate]

    action: ActionReceipt | None = None
    if isinstance(payload, ActionReceipt):
        action = payload
    elif supporting_receipt is not None:
        action = supporting_receipt[1]

    if mandates and action is None:
        raise InputError("--mandate applies when an action receipt is being verified")

    signers = verified_signers(envelope, public_keys)
    for label, value in _describe(envelope.payload):
        _line(label, value)
    _line("signed by", _signers(signers))

    failures: list[str] = []
    if not signers:
        failures.append("no signature checks out against this directory")

    unauthored = _authorship_failure(envelope, public_keys, "the document")
    if unauthored:
        failures.append(unauthored)

    missing = sorted(set(arguments.require) - signers)
    if missing:
        failures.append(f"required {', '.join(missing)} did not sign")

    if supporting_receipt is not None:
        # _read_receipt only accepts a supporting receipt when the document
        # under test is an outcome, so this narrowing always holds.
        assert isinstance(payload, OutcomeAttestation)
        failures.extend(_report_binding(*supporting_receipt, payload, public_keys))

    if action is not None:
        if not mandates:
            # Authority cannot be checked without the grant, and saying nothing
            # would let a bare signature check read as an authority check.
            _line("scope", "not checked (no mandate supplied)")
        else:
            failures.extend(_report_authority(mandates, action, public_keys))

    if failures:
        _line("result", f"NOT VERIFIED ({'; '.join(failures)})")
        return NOT_VERIFIED

    _line("result", "VERIFIED")
    return VERIFIED


def _public_keys(path: Path | None) -> KeyDirectory:
    """The keys to check signatures against.

    A directory is optional because a did:key signer carries its own key, so a
    document signed only by one is checkable with nothing on hand. Anything
    else fails as an unknown signer, which is the honest answer: without the
    directory there is no way to tell whose key that was.
    """
    if path is None:
        return KeyDirectory()
    try:
        return KeyDirectory(read_key_directory(path))
    except (OSError, ValueError) as error:
        raise InputError(f"cannot read key directory: {error}") from error


def _signers(signers: frozenset[str]) -> str:
    """Key ids as a report line, marking the ones that vouch for themselves.

    A did:key verifies without the directory, which is convenient and easy to
    over-read: it proves the named key signed, never that the key is anybody a
    reader should trust. Marked so that distinction is visible at a glance
    rather than resting on whether the reader recognises the id's shape.
    """
    if not signers:
        return "-"
    return ", ".join(
        f"{key_id} [self-described]" if is_did_key(key_id) else key_id for key_id in sorted(signers)
    )


def _report_binding(
    envelope: SignedEnvelope,
    receipt: ActionReceipt,
    outcome: OutcomeAttestation,
    public_keys: PublicKeys,
) -> list[str]:
    failures = []

    receipt_signers = verified_signers(envelope, public_keys)
    _line("receipt", f"{receipt.id} signed by {', '.join(sorted(receipt_signers)) or '-'}")
    if not receipt_signers:
        failures.append("the receipt itself does not verify")

    unauthored = _authorship_failure(envelope, public_keys, "the receipt")
    if unauthored:
        failures.append(unauthored)

    problems = binding_problems(receipt, outcome)
    if problems:
        _line("binding", "BROKEN")
        for problem in sorted(problems):
            _line("", f"- {PROBLEM_DESCRIPTIONS[problem]}")
        failures.append("the outcome is not bound to this receipt")
    else:
        _line("binding", "OK")

    return failures


def _report_authority(
    mandates: list[tuple[SignedEnvelope, Mandate]],
    receipt: ActionReceipt,
    public_keys: PublicKeys,
) -> list[str]:
    failures = []
    chain = [grant for _, grant in mandates]

    for envelope, grant in mandates:
        granted_by = verified_signers(envelope, public_keys)
        _line("mandate", f"{grant.id} granted by {_signers(granted_by)}")
        if not granted_by:
            failures.append(f"mandate {grant.id} does not verify")

        unauthored = _authorship_failure(envelope, public_keys, f"mandate {grant.id}")
        if unauthored:
            failures.append(unauthored)

    failures.extend(_report_chain(chain))
    if failures:
        # Measuring an action against a chain that does not hold up would
        # produce a confident answer to the wrong question.
        return failures

    grant = chain[-1]
    problems = mandate_problems(grant, receipt)
    if problems:
        _line("grant", "NOT THIS RECEIPT'S")
        for problem in sorted(problems):
            _line("", f"- {MANDATE_PROBLEM_DESCRIPTIONS[problem]}")
        return [*failures, "the receipt was not taken under this mandate"]

    return [*failures, *_report_scope(grant, receipt)]


def _report_chain(chain: list[Mandate]) -> list[str]:
    positions = chain_problems(chain)
    if not any(positions):
        principal = accountable_principal(chain)
        _line("chain", f"OK, answering to {principal.id} ({principal.type})")
        return []

    _line("chain", "BROKEN")
    for index, problems in enumerate(positions):
        for problem in sorted(problems):
            where = "the chain" if index == 0 else f"grant {index + 1}"
            _line("", f"- {where}: {DELEGATION_PROBLEM_DESCRIPTIONS[problem]}")
    return ["the delegation chain does not hold up"]


def _report_scope(mandate: Mandate, receipt: ActionReceipt) -> list[str]:
    violations = scope_violations(mandate, receipt)
    if not violations:
        _line("scope", "OK")
        return []

    went_ahead = allowed_beyond_mandate(mandate, receipt)
    _line("scope", "EXCEEDED" if went_ahead else "EXCEEDED, and refused")
    for violation in sorted(violations):
        _line("", f"- {VIOLATION_DESCRIPTIONS[violation]}")

    # A refused action that fell outside its mandate is the system working, and
    # the receipt documenting it is a good record rather than a failure.
    return ["the action went beyond its mandate"] if went_ahead else []


def _read_envelope(path: Path) -> SignedEnvelope:
    try:
        return SignedEnvelope.model_validate_json(path.read_bytes())
    except OSError as error:
        raise InputError(f"cannot read envelope: {error}") from error
    except ValidationError as error:
        raise InputError(f"{path} is not a valid envelope\n{error}") from error


def _read_mandate(path: Path) -> tuple[SignedEnvelope, Mandate]:
    envelope = _read_envelope(path)
    grant = envelope.payload
    if not isinstance(grant, Mandate):
        raise InputError(f"{path} does not contain a mandate")
    return envelope, grant


def _read_receipt(path: Path, envelope: SignedEnvelope) -> tuple[SignedEnvelope, ActionReceipt]:
    if not isinstance(envelope.payload, OutcomeAttestation):
        raise InputError("--receipt applies when verifying an outcome attestation")

    envelope = _read_envelope(path)
    record = envelope.payload
    if not isinstance(record, ActionReceipt):
        raise InputError(f"{path} does not contain an action receipt")
    return envelope, record


def _describe(payload: ActionReceipt | OutcomeAttestation | Mandate) -> list[tuple[str, str]]:
    if isinstance(payload, Mandate):
        described = [
            ("document", f"{payload.id} (mandate)"),
            ("granted", _timestamp(payload.issued_at)),
            ("principal", f"{payload.principal.id} ({payload.principal.type})"),
            ("to agent", f"{payload.agent.id} using {payload.agent.key_id}"),
            ("scope", ", ".join(payload.scope)),
            ("expires", _timestamp(payload.expires_at)),
        ]
        if payload.max_value is not None:
            described.append(("ceiling", _money(payload.max_value)))
        return described

    if isinstance(payload, ActionReceipt):
        described = [
            ("document", f"{payload.id} (action receipt)"),
            ("issued", _timestamp(payload.issued_at)),
            ("agent", f"{payload.agent.id} using {payload.agent.key_id}"),
            ("principal", f"{payload.principal.id} ({payload.principal.type})"),
            ("action", f"{payload.action.type} -> {payload.action.target}"),
        ]
        if payload.action.value is not None:
            described.append(("value", _money(payload.action.value)))
        described.append(("under", payload.mandate_id))
        described.append(("decision", payload.decision.outcome))
        return described

    described = [
        ("document", f"{payload.id} (outcome attestation)"),
        ("issued", _timestamp(payload.issued_at)),
        ("reports on", payload.receipt_id),
        ("status", payload.status),
    ]
    if payload.resolution is not None:
        described.append(("resolution", payload.resolution))
    if payload.loss is not None:
        described.append(("loss", _money(payload.loss)))
    for cited in payload.evidence:
        # Shown, never checked: the artifact lives outside this format and
        # only whoever holds it can confirm the digest.
        described.append(("evidence", f"{cited.kind} from {cited.source} ({cited.digest})"))
    return described


def _authorship_failure(envelope: SignedEnvelope, public_keys: PublicKeys, what: str) -> str | None:
    """Why this document is not signed by the key it names, if it is not.

    A non-empty set of verified signers is not enough. The envelope only
    requires that a signature *labelled* with the author's key id be present,
    so any key the directory happens to trust can mint a document in somebody
    else's name by attaching a junk signature under theirs.
    """
    if author_signed(envelope, public_keys):
        return None
    return f"{what} is not signed by {required_signer(envelope.payload)}, the key it names"


def _printable(value: str) -> str:
    # Everything here is attacker-controlled and goes straight to a terminal.
    # A control character can forge a result line, and an ANSI sequence can
    # conceal the real one, so the report would say VERIFIED for a document
    # that is not. Escaped rather than stripped, so nothing is silently hidden.
    return "".join(
        character
        if unicodedata.category(character) not in ("Cc", "Cf", "Zl", "Zp")
        else f"\\u{ord(character):04x}"
        for character in value
    )


def _line(label: str, value: str) -> None:
    print(f"{label:<{LABEL_WIDTH}} {_printable(value)}")


def _money(money: Money) -> str:
    return f"{money.amount} {money.currency}"


def _timestamp(moment: datetime) -> str:
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"


if __name__ == "__main__":
    raise SystemExit(main())
