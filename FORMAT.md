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

| Written | Canonical | Rule |
|---|---|---|
| `42.50` | `42.5` | trailing zeros removed |
| `100.00` | `100` | trailing zeros removed |
| `1E+2` | `100` | never scientific notation |
| `0.00` | `0` | |
| `-0` | `0` | negative zero is zero |

Rejected: negative, `NaN`, `Infinity`.

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

- **Mandate scope** is a set of permissions: sorted and deduplicated. The order
  a caller writes it in carries no meaning and MUST NOT change the bytes.
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

Validated as an absolute `http`/`https` URL with a host.

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

## Versioning

Every document carries `v`. Any change to a field name, type, or canonical rule
in this file is a new version. Documents signed under an earlier version remain
verifiable under the rules of that version.
