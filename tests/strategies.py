"""Hypothesis strategies that build valid documents.

Deliberately adversarial where the format is delicate: identifiers draw from
combining marks, astral-plane characters and lookalikes, because canonicalization
is where this format breaks if it breaks at all.
"""

import unicodedata
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

from hypothesis import strategies as st

from agent_receipts.models import (
    Action,
    ActionReceipt,
    Agent,
    Decision,
    DecisionOutcome,
    DelegationLink,
    DisputeResolution,
    Mandate,
    Money,
    OutcomeAttestation,
    OutcomeStatus,
    Principal,
    PrincipalType,
)

# Characters chosen to stress normalization rather than to look realistic.
# ruff: noqa: RUF001 - the ambiguous characters below are the entire point.
AWKWARD = "".join(
    [
        "éé",  # e-acute, precomposed and decomposed
        "ÅÅÅ",  # A-ring three ways, including the angstrom sign
        "ẛ̣",  # long s with dot above, plus a combining dot below
        "\U0001f600\U0001d11e",  # astral plane
        "דּ€",  # BMP characters that sort either side of a surrogate
        "аa",  # Cyrillic and Latin a, which NFC must keep distinct
        "​ ",  # zero width space, non-breaking space
        '\\"/',
    ]
)

digests = st.integers(min_value=0, max_value=2**256 - 1).map(lambda n: f"sha256:{n:064x}")

currencies = st.sampled_from(["USD", "EUR", "GBP", "JPY", "BHD"])


def _usable_identifier(text: str) -> bool:
    normalized = unicodedata.normalize("NFC", text)
    return bool(normalized) and normalized == normalized.strip()


identifiers = (
    st.text(alphabet=st.sampled_from(list(AWKWARD) + list("abzAZ09:._-")), min_size=1, max_size=24)
    .filter(_usable_identifier)
    .map(lambda text: unicodedata.normalize("NFC", text))
)

amounts = st.decimals(
    min_value=Decimal(0), max_value=Decimal(10**12), allow_nan=False, allow_infinity=False
)

money = st.builds(Money, amount=amounts, currency=currencies)

timestamps = st.datetimes(min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1)).map(
    lambda moment: moment.replace(tzinfo=UTC)
)

# The same instants written against other offsets, to exercise the conversion.
offset_timestamps = st.tuples(timestamps, st.integers(min_value=-14, max_value=14)).map(
    lambda pair: pair[0].astimezone(timezone(timedelta(hours=pair[1])))
)

agents = st.builds(Agent, id=identifiers, key_id=identifiers)
principals = st.builds(
    Principal, id=identifiers, type=st.sampled_from(PrincipalType), key_id=identifiers
)

targets = st.builds(
    lambda host, path: f"https://{host}.example.com/{path}",
    st.text(alphabet="abc123-", min_size=1, max_size=8),
    st.text(alphabet="abc123/-", max_size=12),
)

document_ids = st.integers(min_value=0, max_value=2**128 - 1)
receipt_ids = document_ids.map(lambda n: f"rcpt_{n:032x}")
outcome_ids = document_ids.map(lambda n: f"outc_{n:032x}")
mandate_ids = document_ids.map(lambda n: f"mndt_{n:032x}")

actions = st.builds(
    Action,
    type=identifiers,
    target=targets,
    params_hash=digests,
    value=st.none() | money,
)

decisions = st.builds(
    Decision,
    outcome=st.sampled_from(DecisionOutcome),
    reasons=st.lists(st.text(max_size=40), max_size=3).map(tuple),
)

mandates = st.builds(
    Mandate,
    id=mandate_ids,
    issued_at=st.one_of(timestamps, offset_timestamps),
    principal=principals,
    agent=agents,
    scope=st.lists(identifiers, min_size=1, max_size=4).map(tuple),
    expires_at=st.one_of(timestamps, offset_timestamps),
    max_value=st.none() | money,
    delegated_from=st.none()
    | st.builds(DelegationLink, mandate_id=mandate_ids, mandate_hash=digests, agent=agents),
)

receipts = st.builds(
    ActionReceipt,
    id=receipt_ids,
    issued_at=st.one_of(timestamps, offset_timestamps),
    agent=agents,
    principal=principals,
    mandate_id=mandate_ids,
    mandate_hash=digests,
    action=actions,
    decision=decisions,
    prev=st.none() | receipt_ids,
)

outcomes = st.builds(
    OutcomeAttestation,
    id=outcome_ids,
    receipt_id=receipt_ids,
    receipt_hash=digests,
    issued_at=st.one_of(timestamps, offset_timestamps),
    status=st.sampled_from(OutcomeStatus),
    resolution=st.none() | st.sampled_from(DisputeResolution),
    loss=st.none() | money,
)

documents = st.one_of(mandates, receipts, outcomes)

# JSON values of the shape a canonical document can take: no numbers anywhere.
json_values = st.recursive(
    st.text(alphabet=st.sampled_from(list(AWKWARD) + list("abZ09 ")), max_size=12),
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(
            st.text(alphabet=st.sampled_from(list(AWKWARD) + list("abZ09 ")), max_size=12),
            children,
            max_size=4,
        )
    ),
    max_leaves=12,
)
