# Contributing

## Getting set up

```sh
python -m venv .venv
.venv/bin/pip install -e ".[dev]"     # .venv\Scripts\pip on Windows
.venv/bin/python -m pytest
```

Everything CI runs, you can run:

```sh
python -m pytest          # tests, including property-based and fuzz suites
python -m ruff check .    # lint
python -m ruff format .   # formatting
python -m mypy src        # types, strict
```

Ruff and mypy are pinned to compatible releases on purpose. A formatter that
drifts between your machine and CI produces a check nobody can reproduce, and a
check nobody can reproduce gets ignored.

## What this project is careful about

This library exists so that a signature means something specific, which puts
weight on things that are usually matters of taste.

**Canonical bytes are the product.** Anything that could make two conforming
implementations disagree about the bytes of the same document is a bug, not a
detail — decimal formatting, sort collation, timestamp padding, Unicode
normalization. If a change touches serialization, say in the pull request why
two implementations will still agree.

**The format version is not the package version.** A release that fixes a bug
without changing the wire format does not touch `v` in a document. A change to
any field name, type or canonical rule does. See [FORMAT.md](FORMAT.md).

**Golden vectors are hand-checked, not generated.** The expected canonical forms
in `tests/vectors/` are written from the spec. Regenerating them from the
implementation would make the tests agree with whatever the code happens to do,
which is the one thing they exist to prevent. If a vector needs to change,
justify the new value against FORMAT.md.

**Untrusted input must be refused, not survived.** Everything arriving from a
file or a caller is hostile. A refusal is a `ValidationError`, `ValueError` or
`TypeError`; anything else is a crash wearing a different name.

## Tests

New behaviour needs a test that would fail without it. For anything touching
signing, binding, scope or delegation, the useful question is not "does this
pass?" but "would this test fail if I broke the rule?" — try deliberately
breaking the code and confirm the test notices before you trust it.

`tests/test_security_regressions.py` holds cases for defects that were once
real. Each carries a comment explaining what went wrong, so the test does not
look pointless later and get tidied away.

## Pull requests

Keep changes focused; unrelated cleanup belongs in its own commit. Explain why
in the commit message, not what — the diff already says what.

Do not add a dependency without saying what it replaces and why the standard
library will not do.

## Reporting security issues

Not through a pull request. See [SECURITY.md](SECURITY.md).
