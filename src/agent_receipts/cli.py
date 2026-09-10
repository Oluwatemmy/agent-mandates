"""Command line verifier.

Reads an envelope and a key directory, and reports what the document says and
which keys signed it. Both are read from the local filesystem: fetching a key
directory over the network would pull in redirect handling, TLS policy and SSRF
exposure, none of which belong in a tool whose job is to answer one question.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

from agent_receipts.keys import read_key_directory
from agent_receipts.models import ActionReceipt, OutcomeAttestation
from agent_receipts.signing import SignedEnvelope, verified_signers

VERIFIED = 0
NOT_VERIFIED = 1
BAD_INPUT = 2


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
        "--require",
        action="append",
        default=[],
        metavar="KEY_ID",
        help="fail unless this key signed; may be repeated",
    )

    return _verify(parser.parse_args(argv))


def _verify(arguments: argparse.Namespace) -> int:
    try:
        public_keys = read_key_directory(arguments.keys)
    except (OSError, ValueError) as error:
        return _fail(f"cannot read key directory: {error}")

    try:
        envelope = SignedEnvelope.model_validate_json(arguments.envelope.read_bytes())
    except OSError as error:
        return _fail(f"cannot read envelope: {error}")
    except ValidationError as error:
        return _fail(f"{arguments.envelope} is not a valid envelope\n{error}")

    signers = verified_signers(envelope, public_keys)
    for label, value in _describe(envelope.payload):
        print(f"{label:<10} {value}")
    print(f"{'signed by':<10} {', '.join(sorted(signers)) if signers else '-'}")

    if not signers:
        print(f"{'result':<10} NOT VERIFIED (no signature checks out against this directory)")
        return NOT_VERIFIED

    missing = sorted(set(arguments.require) - signers)
    if missing:
        print(f"{'result':<10} NOT VERIFIED (required {', '.join(missing)} did not sign)")
        return NOT_VERIFIED

    print(f"{'result':<10} VERIFIED")
    return VERIFIED


def _describe(payload: ActionReceipt | OutcomeAttestation) -> list[tuple[str, str]]:
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
        described.append(("mandate", f"{payload.mandate.id} [{', '.join(payload.mandate.scope)}]"))
        described.append(("decision", payload.decision.outcome))
        return described

    described = [
        ("document", f"{payload.id} (outcome attestation)"),
        ("issued", _timestamp(payload.issued_at)),
        ("receipt", payload.receipt_id),
        ("status", payload.status),
    ]
    if payload.resolution is not None:
        described.append(("resolution", payload.resolution))
    if payload.loss is not None:
        described.append(("loss", _money(payload.loss)))
    return described


def _money(money) -> str:
    return f"{money.amount} {money.currency}"


def _timestamp(moment) -> str:
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return BAD_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
