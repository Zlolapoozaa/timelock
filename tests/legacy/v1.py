"""Drive the ORIGINAL v1 implementation (timelock_v1.py, a frozen verbatim copy of
timelock.py as first released) so tests can produce real v1 vaults and progress
files. Never edit timelock_v1.py: it is the reference for "old vaults must open".
"""

import builtins
import getpass
import importlib.util
import os
import signal
import time
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
RATE = 1_000_000.0


def load():
    spec = importlib.util.spec_from_file_location("timelock_v1_original", os.path.join(HERE, "timelock_v1.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_vault(path, t, entries, note=""):
    """Create a v1 vault at `path` with the original cmd_create (prompts scripted)."""
    v1 = load()
    v1.benchmark = lambda seconds=5.0: RATE
    labels = iter([e["label"] for e in entries] + [""])
    hidden = iter([s for e in entries for s in (e["secret"], e["secret"])])

    def fake_input(prompt=""):
        if "Continue without gmpy2" in prompt:
            return "y"
        if prompt.startswith("Label for secret"):
            return next(labels)
        if prompt.startswith("Optional note"):
            return note
        raise AssertionError(f"unexpected prompt: {prompt!r}")

    with mock.patch.object(builtins, "input", fake_input), \
            mock.patch.object(getpass, "getpass", lambda prompt="": next(hidden)):
        v1.cmd_create(SimpleNamespace(vault=str(path), hours=t / RATE / 3600, force=False))


def pause_solve_after(path, chunks, chunk_size=1000):
    """Run the original solver and pause it (as Ctrl+C would) after `chunks` chunks,
    leaving the original code's own .progress file behind."""
    v1 = load()
    v1.CHUNK = chunk_size
    calls = {"n": 0}
    real_monotonic = time.monotonic

    def monotonic():  # the original loop calls this once per chunk
        calls["n"] += 1
        if calls["n"] == chunks + 2:  # +2: two calls happen before the loop starts
            signal.raise_signal(signal.SIGINT)
        return real_monotonic()

    saved = {s: signal.getsignal(getattr(signal, s))
             for s in ("SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP") if hasattr(signal, s)}
    try:
        with mock.patch.object(time, "monotonic", monotonic):
            v1.cmd_solve(SimpleNamespace(vault=str(path)))
    finally:
        for name, handler in saved.items():
            signal.signal(getattr(signal, name), handler)
