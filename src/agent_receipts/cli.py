"""Command line verifier.

Reads an envelope and a key directory, and reports what the document says and
which keys signed it. Given an outcome and the receipt it reports on, also
reports whether the two are actually bound together.

Both files are read from the local filesystem: fetching a key directory over the
network would pull in redirect handling, TLS policy and SSRF exposure, none of
which belong in a tool whose job is to answer one question.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

from agent_receipts.binding import (
    MANDATE_PROBLEM_DESCRIPTIONS,
    PROBLEM_DESCRIPTIONS,
    binding_problems,
    mandate_problems,
)
from agent_receipts.keys import read_key_directory
from agent_receipts.models import ActionReceipt, Mandate, OutcomeAttestation
from agent_receipts.scope import VIOLATION_DESCRIPTIONS, allowed_beyond_mandate, scope_violations
from agent_receipts.signing import SignedEnvelope, verified_signers

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
        prog="receipts", description="Verify signed agent action receipts and outcome attestations."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify", help="check the signatures on an envelope")
    verify.add_argument("envelope", type=Path, help="signed envelope, as JSON")
    verify.add_argument(
        "--keys", type=Path, required=True, metavar="JWKS", help="public key directory, as JWKS"
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
        metavar="ENVELOPE",
        help="the grant a receipt was taken under, to check its authority",
    )
    verify.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="KEY_ID",
        help="fail unless this key signed; may be repeated",
    )

    try:
        return _verify(parser.parse_args(argv))
    except InputError as error:
        print(f"error: {error}", file=sys.stderr)
        return BAD_INPUT


def _verify(arguments: argparse.Namespace) -> int:
    try:
        public_keys = read_key_directory(arguments.keys)
    except (OSError, ValueError) as error:
        raise InputError(f"cannot read key directory: {error}") from error

    envelope = _read_envelope(arguments.envelope)
    receipt = _read_receipt(arguments.receipt, envelope) if arguments.receipt else None
    mandate = _read_mandate(arguments.mandate) if arguments.mandate else None

    action = envelope.payload if isinstance(envelope.payload, ActionReceipt) else None
    if action is None and receipt is not None:
        action = receipt.payload
    if mandate is not None and action is None:
        raise InputError("--mandate applies when an action receipt is being verified")

    signers = verified_signers(envelope, public_keys)
    for label, value in _describe(envelope.payload):
        _line(label, value)
    _line("signed by", ", ".join(sorted(signers)) if signers else "-")

    failures = []
    if not signers:
        failures.append("no signature checks out against this directory")

    missing = sorted(set(arguments.require) - signers)
    if missing:
        failures.append(f"required {', '.join(missing)} did not sign")

    if receipt is not None:
        failures.extend(_report_binding(receipt, envelope.payload, public_keys))

    if action is not None:
        if mandate is None:
            # Authority cannot be checked without the grant, and saying nothing
            # would let a bare signature check read as an authority check.
            _line("scope", "not checked (no mandate supplied)")
        else:
            failures.extend(_report_authority(mandate, action, public_keys))

    if failures:
        _line("result", f"NOT VERIFIED ({'; '.join(failures)})")
        return NOT_VERIFIED

    _line("result", "VERIFIED")
    return VERIFIED


def _report_binding(
    receipt: SignedEnvelope, outcome: OutcomeAttestation, public_keys: dict
) -> list[str]:
    failures = []

    receipt_signers = verified_signers(receipt, public_keys)
    _line("receipt", f"{receipt.payload.id} signed by {', '.join(sorted(receipt_signers)) or '-'}")
    if not receipt_signers:
        failures.append("the receipt itself does not verify")

    problems = binding_problems(receipt.payload, outcome)
    if problems:
        _line("binding", "BROKEN")
        for problem in sorted(problems):
            _line("", f"- {PROBLEM_DESCRIPTIONS[problem]}")
        failures.append("the outcome is not bound to this receipt")
    else:
        _line("binding", "OK")

    return failures


def _report_authority(
    mandate: SignedEnvelope, receipt: ActionReceipt, public_keys: dict
) -> list[str]:
    failures = []
    grant = mandate.payload

    granted_by = verified_signers(mandate, public_keys)
    _line("mandate", f"{grant.id} granted by {', '.join(sorted(granted_by)) or '-'}")
    if not granted_by:
        failures.append("the mandate itself does not verify")

    problems = mandate_problems(grant, receipt)
    if problems:
        _line("grant", "NOT THIS RECEIPT'S")
        for problem in sorted(problems):
            _line("", f"- {MANDATE_PROBLEM_DESCRIPTIONS[problem]}")
        failures.append("the receipt was not taken under this mandate")
        # Measuring the action against a grant it was not taken under would
        # produce a confident answer to the wrong question.
        return failures

    return failures + _report_scope(grant, receipt)


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


def _read_mandate(path: Path) -> SignedEnvelope:
    mandate = _read_envelope(path)
    if not isinstance(mandate.payload, Mandate):
        raise InputError(f"{path} does not contain a mandate")
    return mandate


def _read_receipt(path: Path, envelope: SignedEnvelope) -> SignedEnvelope:
    if not isinstance(envelope.payload, OutcomeAttestation):
        raise InputError("--receipt applies when verifying an outcome attestation")

    receipt = _read_envelope(path)
    if not isinstance(receipt.payload, ActionReceipt):
        raise InputError(f"{path} does not contain an action receipt")
    return receipt


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
    return described


def _line(label: str, value: str) -> None:
    print(f"{label:<{LABEL_WIDTH}} {value}")


def _money(money) -> str:
    return f"{money.amount} {money.currency}"


def _timestamp(moment) -> str:
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"


if __name__ == "__main__":
    raise SystemExit(main())
