# Canonical form

Two documents describing the same thing MUST produce the same bytes. Signatures
are computed over the canonical form, never over caller-provided formatting.

Canonicalization happens in two layers, and they solve different problems:

| Layer | Question | Where |
|---|---|---|
| **Value** | Is `1.50` the same amount as `1.5`? | On construction, in `models.py` |
| **Serialization** | What order do keys go in? How are strings escaped? | At signing time, RFC 8785 |

RFC 8785 does not answer any layer-one question. A document normalized only by
JCS can still have two byte representations of the same meaning.

Because normalization happens on construction, a document cannot exist in a
non-canonical state. Signing does not need to normalize anything.

## Amounts

Represented as `Decimal`, never a float. Serialized as a JSON **string**, so no
reader can round-trip the value through a float and change what was signed.

Reduced to one written form:

Always written in plain notation. Scientific notation is never produced, at
any magnitude, because an independent implementation would render the same
amount differently and the bytes would not match.

Trailing zeros are stripped exactly, without arithmetic. An implementation that
normalizes through a fixed-precision decimal context will silently round large
amounts, which changes the value being signed.

| Written | Canonical | Rule |
|---|---|---|
| `42.50` | `42.5` | trailing zeros removed |
| `100.00` | `100` | trailing zeros removed |
| `1E+2` | `100` | never scientific notation |
| `1E-7` | `0.0000001` | never scientific notation, at any magnitude |
| `1.0000000000000000000000000000001` | unchanged | never rounded |
| `0.00` | `0` | |
| `-0` | `0` | negative zero is zero |

Rejected: negative, `NaN`, `Infinity`, and any binary floating point value, which cannot represent most decimal amounts exactly.

Currency is a separate field and MUST be a three-letter uppercase code. No
per-currency precision is applied — `100` is `100` whether the currency has two
decimal places or none.

## Timestamps

Timezone-aware input is REQUIRED; naive datetimes are rejected rather than
assumed to be UTC.

- Converted to UTC.
- Truncated to milliseconds.
- Rendered as `YYYY-MM-DDTHH:MM:SS.mmmZ`, always exactly three fractional
  digits and always `Z`.

The fixed fractional width matters: `datetime.isoformat()` omits the fractional
part entirely when it is zero, which gives one instant two written forms.

## Strings

All free-form text is normalized to Unicode **NFC**, collapsing the two
spellings of characters like `é` (`U+00E9` vs `e` + `U+0301`).

NFC is **not** a defence against homoglyphs. Cyrillic `а` and Latin `a` are
genuinely different characters and remain distinct. Do not treat normalization
as identity verification.

Identifiers additionally:

- MUST NOT have leading or trailing whitespace (rejected, not stripped).
- MUST NOT be empty.
- Preserve case. Folding it would silently merge principals that the caller's
  own system treats as distinct subjects.

## Identifiers

Document IDs are prefixed and constrained to lowercase hex, so they have exactly
one written form already:

- Receipts: `rcpt_` + 32 hex characters
- Outcomes: `outc_` + 32 hex characters

A well-formed ID of the wrong kind is rejected — an `outc_…` value will not be
accepted where a receipt ID is required.

## Collections

- **Mandate scope** is a set of permissions: deduplicated, and sorted by
  **UTF-16 code unit** exactly as object keys are. The order a caller writes it
  in carries no meaning and MUST NOT change the bytes. Sorting by code point
  instead would disagree above U+FFFF, so an implementation using a language
  whose native sort is UTF-16 would produce different bytes.
- **Decision reasons** are a sequence: order is preserved, because it records
  the order the policy produced them.

## Optional fields

An absent optional field is **omitted entirely**. It is never serialized as
`null`. `{"loss": null}` and `{}` mean the same thing and MUST NOT produce two
different signatures.

## URLs

Stored verbatim after NFC normalization. Deliberately not passed through a
normalizing URL type: those append a trailing slash to a bare origin, which
would make the signed bytes differ from the target the caller supplied.

Validated as an absolute `http`/`https` URL with a host, and MUST NOT contain
control or format characters. URL parsers commonly strip those before parsing,
so a value validated after stripping would not be the value that gets signed.

## Serialization

Canonical bytes are produced per RFC 8785 (JCS):

1. Object keys are sorted by their **UTF-16 code units** compared as unsigned
   integers, not by code point. The two orders disagree above U+FFFF, where a
   character becomes a surrogate pair whose lead unit (U+D800-U+DBFF) sorts
   below ordinary BMP characters such as U+FB33.
2. Inside strings, U+0008, U+0009, U+000A, U+000C and U+000D use the short
   escapes; any other character in U+0000-U+001F uses `\uhhhh` with lowercase
   hex; U+0022 and U+005C are escaped.
3. Every other character is emitted as is, including DEL and C1 controls such
   as U+0080.
4. No whitespace, and the output is UTF-8.

Array order is never changed; only object keys are sorted.

JCS number serialization does not apply, because this format contains no JSON
numbers. That is deliberate: RFC 8785 serializes numbers as IEEE 754 doubles,
so a numeric amount or a large integer identifier would be silently rounded
before signing, and the resulting signature would be valid over a corrupted
value. Serializing a value that is not an object, array or string is an error.

## Signing

A signature covers **the canonical bytes of `payload` and nothing else**. The
envelope around it is never signed and never canonicalized.

```json
{
  "payload": { "v": "0.1", "type": "action", "id": "rcpt_...", "...": "..." },
  "signatures": [
    { "alg": "Ed25519", "key_id": "key-1", "value": "<unpadded base64url>" }
  ]
}
```

Because the boundary is payload-only, rewrapping a payload cannot change what
was signed or who signed it. Reordering the envelope's keys, reformatting it, or
adding a countersignature all leave existing signatures valid and unchanged.
There is no exclusion rule anywhere -- the payload is a separate object, so the
signed scope is never in question.

A verifier MUST re-canonicalize `payload` rather than trusting the bytes it
arrived in. This is safe because the canonical form is a fixed point: feeding a
canonical document back through canonicalization returns it unchanged.

### Rules

- `alg` is **pinned, not dispatched on**. Version 0.1 permits `Ed25519` only,
  and a verifier MUST reject any other value rather than selecting a handler for
  it. Choosing an algorithm from the document is how algorithm-confusion attacks
  get in. The field exists for future versioning.
- `value` is the 64 raw signature bytes as unpadded base64url, in canonical
  encoding. The final base64 character carries unused bits, so a non-canonical
  spelling of the same signature MUST be rejected.
- An envelope MUST carry at least one signature, and a given `key_id` MUST NOT
  appear more than once.
- An **action receipt MUST be signed by the agent key it names**: some signature
  MUST carry the same `key_id` as `payload.agent.key_id`. This is a structural
  requirement checked when the envelope is parsed; whether that signature
  actually verifies is a separate question. An outcome attestation carries no
  such constraint, because its signer is the platform rather than the agent, and
  the verifier decides whose signature it trusts.
- A verifier MUST check that the key a document names as its author is among
  those that actually verified. The requirement above that such a signature be
  *present* is structural, checked while parsing, when no keys are available.
  Anyone may attach a signature bearing somebody else's key id, so a document
  that merely has *some* valid signature has not been authenticated: any key a
  verifier trusts could otherwise mint a grant in another party's name.
- Verification reports **which keys verified**, never a bare boolean. A caller
  has to decide whether the keys that actually signed are the ones it trusts,
  and returning "valid" alone would let that question be skipped.
- A signature from an unknown key is ignored rather than fatal, so that an
  attacker cannot invalidate somebody else's evidence by appending a signature
  to their envelope.

Ed25519 signing is deterministic (RFC 8032), so the same document and key always
produce the same signature. The golden vectors in `tests/vectors` rely on this:
their seeds are fixed, and any conforming implementation reproduces the same
signature bytes.

## Key directories

Public keys are published as a JWKS (RFC 7517) holding Ed25519 keys in the OKP
form of RFC 8037:

```json
{"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "key-1", "x": "<base64url>"}]}
```

Every key in a directory MUST be an Ed25519 OKP key, and a `kid` MUST NOT
appear twice. Key types this format cannot use are rejected rather than skipped:
a silently skipped key resurfaces later as an unknown signer, which is a far
harder failure to diagnose than a rejected directory.

Unrecognized members of a JWK are ignored. The strictness applied to signed
documents does not apply here, because a key directory is not covered by any
signature and only `crv` and `x` decide what the key is. Both are validated
strictly, including that `x` decodes as base64url with no invalid characters
discarded and yields exactly 32 bytes.

## Binding documents together

### An outcome to its receipt

An outcome attestation carries both `receipt_id` and `receipt_hash`. The id says
which receipt is meant; the hash says which receipt it actually is.

`receipt_hash` is `sha256:` followed by the hex digest of the receipt's
**canonical bytes** -- the same bytes its own signature covers, not the bytes it
happened to arrive in. Two receipts sharing an id but differing anywhere in
content produce different digests, so the commitment cannot be satisfied by the
wrong document.

A reference alone would prove nothing: receipt ids are chosen by whoever issues
them, so an outcome naming `rcpt_...` says only that somebody typed that string.

#### Checking that pair

Checking reports every problem found, not the first. Two kinds are reported
together, and the distinction matters when reading a failure:

**Cryptographic** -- no judgement involved, the commitment either holds or it
does not:

| Problem | Meaning |
|---|---|
| `receipt_id_mismatch` | the outcome names a different receipt |
| `receipt_hash_mismatch` | the outcome commits to different receipt content |

**Coherence** -- whether the pair describes something that could have happened:

| Problem | Meaning |
|---|---|
| `outcome_precedes_action` | the outcome is dated before the action it reports on |
| `action_was_refused` | the receipt records a refused action, which has no outcome |

An outcome issued at the same instant as its action is allowed; only one dated
strictly earlier is a problem.

A receipt whose decision was `deny` records that nothing happened, so there is no
transaction for an outcome to describe. Attaching one means the documents are
wrong about each other, which is worth catching even though both may verify.

Note what is deliberately **not** constrained: an outcome's loss may exceed the
action's value, and may be in a different currency. Chargeback fees and foreign
exchange both make those legitimate, and a format that rejected them would be
wrong about the world rather than strict.


### A receipt to its mandate

A receipt carries `mandate_id` and `mandate_hash` rather than restating the
grant. The hash covers the mandate's canonical bytes, so a grant cannot be
quietly widened after the fact and still satisfy a receipt taken under the
narrower one.

| Problem | Meaning |
|---|---|
| `mandate_id_mismatch` | the receipt names a different mandate |
| `mandate_hash_mismatch` | the receipt commits to different mandate content |
| `granted_to_another_agent` | the mandate was granted to a different agent |
| `granted_by_another_principal` | the mandate was granted by a different principal |
| `action_precedes_mandate` | the action was taken before the mandate was granted |

Agent and principal are compared **whole**, not by id. A different signing key
makes a different agent, so a grant cannot be claimed by something sharing an
id but presenting another key.

An action taken at the instant a mandate is granted is in time; only one
strictly earlier is a problem.

## Authority

A mandate is a document in its own right, signed by the **principal** who grants
it, naming the single agent it is granted to.

This is the whole reason it is not embedded in the receipt. A receipt is signed
by its agent, so a mandate carried inside one would be an agent's own statement
of what it was permitted to do -- an assertion that proves nothing, because a
dishonest agent would simply write itself a permissive one. Separating the
documents means a verifier checks a grant against whoever **granted** it rather
than whoever **used** it.

The envelope enforces this structurally: a mandate must carry a signature from
the `key_id` of the principal it names, so an agent signing its own grant cannot
be represented at all.

An outcome attestation has no required signer, because it is issued by whichever
party observed the result -- which the document does not name. The verifier
decides whose attestation it trusts.

### Checking authority is two questions

Confirming the grant is the one the receipt was taken under, and measuring the
action against it, are separate. A tool that skips the first and reports the
second gives a confident answer to a question nobody asked: whether the action
would have been permitted under some *other* mandate.

## Checking an action against its mandate

A receipt records both what an agent did and the mandate it claims to have acted
under. Checking asks whether the first falls inside the second, and reports every
violation rather than the first.

| Violation | Meaning |
|---|---|
| `action_outside_scope` | the action type is not in the mandate's scope |
| `value_exceeds_limit` | the action's value is above the mandate's limit |
| `limit_currency_mismatch` | the limit is in another currency, so the value cannot be checked against it |
| `mandate_expired` | the mandate had expired when the action was taken |

Scope membership is **exact**: a mandate granting `payment.charge.refund` does
not grant `payment.charge`, and case is significant, consistent with identifiers
everywhere else in the format.

Boundaries are inclusive. A value exactly at the limit is inside it, and an
action taken at the instant a mandate expires is in time.

A mandate with no `max_value` places no monetary limit, and an action with no
`value` does not engage one. Neither is a violation: a mandate covering both
reads and charges legitimately has a ceiling that only some of its actions meet.

### Currency mismatches fail closed

When the action's value and the mandate's ceiling are in different currencies,
the check fails. Converting would mean inventing an exchange rate, and passing
would mean treating an unconstrained currency as constrained. A mandate for
100 USD says nothing about what may be spent in EUR, so an action denominated in
EUR is outside it.

### A refused action is not a failure

`action_was_refused` aside, violations describe the action, not the record. A
receipt whose decision was `deny` documents the system refusing something it
should have refused: the violations are reported, but the record is a good one.

What matters is a receipt recording that the action went ahead anyway -- a
decision of `allow` or `step_up` alongside any violation. Only that is treated
as a failure.

### What this cannot do

These checks validate the record against itself. They do not validate it against
reality, and they cannot.

A receipt is signed by its agent, and the mandate travels inside that receipt, so
an agent signs its own account of what it was permitted to do. A dishonest agent
can simply write a mandate permitting whatever it did, and every check here will
pass. What is caught is over-reach and mistakes in records that are honestly
made.

Closing that gap requires the mandate to be attested by the principal granting
it, independently of the agent using it, so that a verifier can check the
mandate against its grantor rather than against its user.

## Delegation

An agent acting under a grant may pass some of that authority on. The grant it
issues carries `delegated_from`, naming the mandate it was itself acting under
by id and hash, and the agent doing the delegating. A chain of mandates
therefore leads back to the principal who started it, who is the human or
organization the whole chain answers to.

A delegated grant is signed by the **delegating agent**, not by the principal
and never by the agent receiving it. A root grant is signed by its principal.
The envelope enforces whichever applies.

### Attenuation

A delegated grant may narrow what it received but never widen it. This is the
property that makes a chain worth anything: without it an agent could
manufacture authority it was never given, which is the one thing delegation
exists to prevent.

| Problem | Meaning |
|---|---|
| `scope_widened` | the delegated scope includes permissions the parent lacked |
| `expiry_extended` | the delegated grant outlives the one it came from |
| `ceiling_raised` | the delegated ceiling is above the parent's |
| `ceiling_removed` | the parent had a ceiling and the delegated grant has none |
| `ceiling_currency_changed` | the ceilings are in different currencies, so attenuation cannot be checked |

Widening is reported per dimension rather than as a single failure. Which
dimension was widened is the difference between a misconfigured integration and
an agent quietly granting itself the ability to spend more.

An unlimited parent may delegate any ceiling, or none. A removed ceiling under a
limited parent is the widest possible widening, so it is a violation rather than
a default. Currency changes fail closed, as they do when checking an action
against a mandate.

Scope is compared as a subset and matched exactly, so narrowing to nothing in
common is fine and any addition is not.

### Chain structure

| Problem | Meaning |
|---|---|
| `not_delegated` | the grant does not say what authority it was passed from |
| `parent_id_mismatch` | the grant names a different parent mandate |
| `parent_hash_mismatch` | the grant commits to different parent content |
| `delegator_was_not_the_grantee` | the delegating agent is not the one the parent was granted to |
| `principal_changed` | the chain changes which principal it answers to |
| `delegated_before_its_grant` | the authority was passed on before it had been granted |
| `delegated_after_its_grant_expired` | the authority was passed on after its grant had expired |
| `root_is_delegated` | the first grant in the chain is itself delegated |
| `chain_too_deep` | the chain is longer than 8 grants |
| `agent_appears_twice` | an agent appears more than once in the chain |

The delegating agent is compared **whole**, so an agent sharing an id but
presenting another signing key cannot pass on authority it never held.

Chains are capped at 8 grants. A verifier walks a chain link by link, so an
unbounded one is work an attacker can hand it for free, and eight is far past
any plausible real delegation depth. An agent appearing twice is rejected,
which catches both a cycle and an agent delegating to itself.

Problems are reported per position rather than flattened: knowing a chain is
broken is much less useful than knowing which hop broke it.

## Displaying a document

Every identifier, target and reason in a document is written by whoever signed
it, and a verifier that prints them is printing attacker-controlled text. A
consumer MUST escape control and format characters before display: otherwise a
document can forge a line of the verifier's own output and conceal the real
result with a terminal escape sequence.

This is a display rule, not a canonicalization rule. The signed bytes are
unaffected.

## Versioning

Every document carries `v`. Any change to a field name, type, or canonical rule
in this file is a new version. Documents signed under an earlier version remain
verifiable under the rules of that version.

The format version and the package version are different things and do not
track each other. A library release that fixes a bug without touching the wire
format does not change `v`, and must not; equally, a format change does not
require the package version to move in step.

Both start at 0.1 because nothing had been published before then. Versions
identify which rules a verifier should apply, and there is nothing to
disambiguate until documents exist outside this repository.
