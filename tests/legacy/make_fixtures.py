"""Regenerate tests/fixtures/v1_vault*.json with the ORIGINAL v1 code.

    python tests/legacy/make_fixtures.py

The committed fixtures were made this way; you should never need to rerun it.
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v1  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
ENTRIES = [
    {"label": "Apple ID password", "secret": "kQ7ve-Rx2Lm-9TzPa-Wd4nB"},
    {"label": "Spare PIN", "secret": "pässwörd with spaces & 🔐"},
]

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        vault = os.path.join(tmp, "v1.tlp")
        v1.make_vault(vault, 40_000, ENTRIES, note="Are you sure?")
        shutil.copy(vault, os.path.join(FIXTURES, "v1_vault.json"))
        v1.pause_solve_after(vault, chunks=12)  # original code writes its own progress file
        shutil.copy(vault + ".progress", os.path.join(FIXTURES, "v1_progress.json"))
    print("wrote", FIXTURES)
