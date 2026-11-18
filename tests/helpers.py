"""Shared test helpers (fixtures live in conftest.py)."""

import timelock as tl

RATE = 1_000_000.0
ENTRIES = [
    {"label": "Apple ID password", "secret": "kQ7ve-Rx2Lm-9TzPa-Wd4nB"},
    {"label": "Notes 🔐", "secret": " pässwörd with spaces "},
]


def make_vault(path, t=20_000, entries=ENTRIES, note="", bits=512):
    """A small, fast vault (512-bit modulus) that takes about t squarings to open."""
    return tl.create_vault(str(path), entries, hours=t / RATE / 3600, rate=RATE, note=note, bits=bits)
