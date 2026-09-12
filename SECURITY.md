# Security

## Reporting a vulnerability

Please report privately through
[GitHub's security advisories](https://github.com/Oluwatemmy/agent-mandates/security/advisories/new)
rather than opening a public issue.

This is maintained by one person, so expect an acknowledgement within a few days
rather than a few hours. If something is being actively exploited, say so in the
subject line.

## What counts

Anything that lets a document be accepted when it should not be, or refused when
it should not be. Concretely:

- a signature that verifies over content it does not cover
- two documents that canonicalize to the same bytes but mean different things
- the same document canonicalizing to different bytes on different platforms or
  Python versions
- a grant that passes checks despite widening what it was delegated
- a receipt accepted against a mandate it was not taken under
- input that crashes a verifier rather than being refused

## What does not

**This library verifies documents, not the world they describe.** An agent signs
its own account of what it did, and nothing here compares that account to
reality. A receipt saying an agent charged 40 USD is evidence that the agent
*claimed* that, under authority its principal *did* grant. It is not evidence
the charge happened.

Key management is out of scope. Generating, storing, rotating and revoking
private keys is left to the caller, deliberately.

Unpaired surrogates, oversized fields and malformed JSON are refused rather than
processed, and there are tests for that. A report showing one gets through is
very much in scope.

## Supported versions

Before 1.0, only the latest release. The format version in a document's `v`
field is separate from the package version; see [FORMAT.md](FORMAT.md).
