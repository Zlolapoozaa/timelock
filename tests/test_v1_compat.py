"""Vaults made by the original v1 code must keep opening, forever.

These run `timelock.py solve` as a subprocess, so they test the shipped command
exactly as a user runs it, independent of internal function names.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

from legacy import v1

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
ENTRIES = [
    {"label": "Apple ID password", "secret": "kQ7ve-Rx2Lm-9TzPa-Wd4nB"},
    {"label": "Spare PIN", "secret": "pässwörd with spaces & 🔐"},
]


def run_cli(*args):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    result = subprocess.run([sys.executable, os.path.join(ROOT, "timelock.py"), *map(str, args)],
                            capture_output=True, env=env, timeout=120)
    out = result.stdout.decode("utf-8") + result.stderr.decode("utf-8")
    assert result.returncode == 0, out
    return out


def assert_unlocked(out, entries):
    for e in entries:
        assert f"{e['label']}: {e['secret']}" in out


@pytest.mark.parametrize("entries", [ENTRIES[:1], ENTRIES])
def test_fresh_v1_vault_from_original_code_solves(tmp_path, entries):
    vault = tmp_path / "made-by-v1-code.tlp"
    v1.make_vault(vault, 20_000, entries, note="Are you sure?")
    assert json.loads(vault.read_text(encoding="utf-8"))["version"] == 1
    assert_unlocked(run_cli("solve", vault), entries)


def test_committed_v1_fixture_solves(tmp_path):
    vault = tmp_path / "v1.tlp"
    shutil.copy(os.path.join(FIXTURES, "v1_vault.json"), vault)
    assert_unlocked(run_cli("solve", vault), ENTRIES)


def test_v1_progress_file_from_original_code_resumes(tmp_path):
    vault = tmp_path / "v1.tlp"
    shutil.copy(os.path.join(FIXTURES, "v1_vault.json"), vault)
    shutil.copy(os.path.join(FIXTURES, "v1_progress.json"), str(vault) + ".progress")
    out = run_cli("solve", vault)
    assert "Resuming from 30.00%" in out
    assert_unlocked(out, ENTRIES)


def test_v1_pause_by_original_code_then_resume(tmp_path):
    vault = tmp_path / "v1.tlp"
    v1.make_vault(vault, 30_000, ENTRIES)
    v1.pause_solve_after(vault, chunks=7)
    assert json.loads((tmp_path / "v1.tlp.progress").read_text())["i"] == 7000
    assert_unlocked(run_cli("solve", vault), ENTRIES)
