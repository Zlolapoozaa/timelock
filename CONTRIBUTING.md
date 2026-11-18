# Contributing

Thanks for helping. Timelock is small on purpose, so please keep changes small
too.

## Ground rules

- **Never break existing vaults.** Every vault format ever written must keep
  opening. If you change the format, bump `FORMAT_VERSION`, add the new version
  to `READABLE_VERSIONS`, and add tests that old vaults still solve.
  `tests/legacy/timelock_v1.py` is a frozen copy of the original code. Never
  edit it.
- **Standard library only** for the core. gmpy2 stays optional, and the program
  must work the same without it, only slower.
- **One file.** `timelock.py` is also the download for people who just want to
  double-click, so it has to keep working on its own.
- **Windows, macOS and Linux**, Python 3.9+ (macOS still ships 3.9 as
  `/usr/bin/python3`).
- **The menu stays the default.** Running with no arguments must keep giving
  non-technical users the numbered menu.
- **Never commit `*.tlp` or `*.progress` files**, not even test vaults.
  `.gitignore` blocks them. Test fixtures use `.json`.
- Don't overclaim in docs or messages. If something is a limitation, say so.

## Setup

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev,fast]"
```

## Tests and lint

```sh
python -m pytest        # a few seconds
ruff check .
```

Tests use tiny puzzles and 512-bit moduli so they run fast. Most of them run
twice, once with pure Python and once with gmpy2 (skipped if gmpy2 isn't
installed).

Two tests touch the real desktop, so they only run when asked to:

| Variable | Test |
|---|---|
| `TIMELOCK_TEST_CLIPBOARD=1` | Windows: sets and reads the real clipboard (and puts your text back) |
| `TIMELOCK_TEST_CONSOLE=1` | Windows: opens a console window, starts an unlock, closes the window, and checks that progress was saved |

## Pull requests

- One topic per pull request, with a test that fails without your change.
- Update `CHANGELOG.md` under an "Unreleased" heading.
- CI must pass on all three operating systems.

## Reporting security problems

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
