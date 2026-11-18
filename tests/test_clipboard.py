"""Clipboard helpers. The live Windows test touches the real clipboard, so it only
runs when TIMELOCK_TEST_CLIPBOARD=1 (CI sets it); it puts back any text it found."""

import os
import subprocess

import pytest

import timelock as tl


def test_macos_uses_pbcopy():
    assert tl._clipboard_commands("darwin", {}) == [["pbcopy"]]


def test_linux_prefers_wayland_then_falls_back_to_x11_tools():
    assert tl._clipboard_commands("linux", {"WAYLAND_DISPLAY": "wayland-0"})[0] == ["wl-copy"]
    x11 = tl._clipboard_commands("linux", {})
    assert [c[0] for c in x11] == ["xclip", "xsel"]


def test_falls_through_to_the_next_tool(monkeypatch):
    tried = []

    def fake_run(command, **kw):
        tried.append((command[0], kw["input"]))
        if command[0] == "xclip":
            raise FileNotFoundError("xclip not installed")
        assert kw["stdout"] is subprocess.DEVNULL  # never wait on a tool that stays in the background
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(tl.subprocess, "run", fake_run)
    assert tl._copy_with_commands("pw", tl._clipboard_commands("linux", {}))
    assert tried == [("xclip", b"pw"), ("xsel", b"pw")]


def test_reports_failure_when_no_tool_works(monkeypatch):
    def broken(command, **kw):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(tl.subprocess, "run", broken)
    assert not tl._copy_with_commands("pw", tl._clipboard_commands("linux", {}))


@pytest.mark.skipif(os.name != "nt" or os.environ.get("TIMELOCK_TEST_CLIPBOARD") != "1",
                    reason="touches the real Windows clipboard; set TIMELOCK_TEST_CLIPBOARD=1")
def test_windows_clipboard_live():
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.GetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT

    def read():
        assert user32.OpenClipboard(None)
        try:
            handle = user32.GetClipboardData(13)  # CF_UNICODETEXT
            if not handle:
                return None
            try:
                return ctypes.wstring_at(kernel32.GlobalLock(handle))
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()

    def excluded_from_history():
        fmt = user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing")
        return bool(user32.IsClipboardFormatAvailable(fmt))

    saved = read()
    try:
        assert tl.copy_to_clipboard("tl-Test-1x2y3-pässwörd")
        assert read() == "tl-Test-1x2y3-pässwörd"
        assert excluded_from_history()
        assert tl.clear_clipboard()
        assert read() is None
    finally:
        if saved is not None:
            tl.copy_to_clipboard(saved)
