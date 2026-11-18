"""Real signals sent to a real `timelock solve` process.

POSIX: Ctrl+C (SIGINT), kill (SIGTERM) and closing the terminal (SIGHUP) must
pause and save. Windows: closing the console window must save too; that test
opens a (minimized) console window, so it only runs with TIMELOCK_TEST_CONSOLE=1.
In-process tests of every signal on every OS are in test_solve.py.
"""

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from helpers import make_vault

TIMELOCK_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "timelock.py")


def assert_consistent_progress(path, vault):
    with open(str(path) + ".progress", encoding="utf-8") as f:
        progress = json.load(f)
    i, n = progress["i"], int(vault["n"], 16)
    assert i > 0
    try:
        import gmpy2
        expected = int(gmpy2.powmod(2, gmpy2.mpz(1) << i, n))
    except ImportError:
        expected = pow(2, 1 << i, n)
    assert int(progress["x"], 16) == expected


@pytest.mark.skipif(os.name == "nt", reason="POSIX signals")
@pytest.mark.parametrize("signame", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_signal_pauses_and_saves(tmp_path, signame):
    path = tmp_path / "v.tlp"
    vault = make_vault(path, t=10**10)
    proc = subprocess.Popen([sys.executable, TIMELOCK_PY, "solve", str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONUNBUFFERED="1"))
    seen, deadline = b"", time.time() + 30
    while b"Press Ctrl+C" not in seen and time.time() < deadline:
        seen += proc.stdout.readline()
    time.sleep(0.5)  # well before the first periodic checkpoint
    proc.send_signal(getattr(signal, signame))
    out, _ = proc.communicate(timeout=60)
    assert proc.returncode == 0, out
    assert b"Paused at" in out
    assert_consistent_progress(path, vault)


@pytest.mark.skipif(os.name != "nt" or os.environ.get("TIMELOCK_TEST_CONSOLE") != "1",
                    reason="opens a console window; set TIMELOCK_TEST_CONSOLE=1")
def test_closing_the_console_window_saves_progress(tmp_path):
    import ctypes
    from ctypes import wintypes

    path = tmp_path / "v.tlp"
    vault = make_vault(path, t=10**10)
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 7  # SW_SHOWMINNOACTIVE: don't steal focus
    # conhost.exe forces a classic console window (not a Windows Terminal tab); cmd gives
    # it a unique title so we can find it.
    tag = f"timelock-close-test-{os.getpid()}"
    host = subprocess.Popen(f'conhost.exe cmd.exe /c "title {tag}&& "{sys.executable}" "{TIMELOCK_PY}" '
                            f'solve "{path}""', startupinfo=startup)
    try:
        user32 = ctypes.WinDLL("user32")
        enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows.argtypes = [enum_proc, wintypes.LPARAM]
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        windows = []

        @enum_proc
        def collect(hwnd, _):
            title, name = ctypes.create_unicode_buffer(512), ctypes.create_unicode_buffer(64)
            user32.GetWindowTextW(hwnd, title, 512)
            user32.GetClassNameW(hwnd, name, 64)
            if title.value.startswith(tag) and name.value == "ConsoleWindowClass":
                windows.append(hwnd)
            return True

        deadline = time.time() + 15
        while not windows and time.time() < deadline:
            user32.EnumWindows(collect, 0)
            time.sleep(0.1)
        assert windows, "console window not found"
        time.sleep(3)  # solving by now; the first periodic checkpoint is at 10 s
        assert not os.path.exists(str(path) + ".progress")
        user32.PostMessageW(windows[0], 0x0010, 0, 0)  # WM_CLOSE: same as clicking the X
        host.wait(timeout=30)
    finally:
        if host.poll() is None:
            host.kill()
    assert_consistent_progress(path, vault)
