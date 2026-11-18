"""The command line and the numbered menu, driven with scripted keyboard input."""

import glob
import json
import os
import re

import pytest

import timelock as tl
from helpers import ENTRIES, RATE, make_vault


class Keyboard:
    """Scripted answers for input() and getpass(); EOF when they run out."""

    def __init__(self, monkeypatch, answers, hidden=()):
        self.answers, self.hidden, self.prompts = list(answers), list(hidden), []
        monkeypatch.setattr("builtins.input", self.input)
        monkeypatch.setattr(tl.getpass, "getpass", self.getpass)

    def input(self, prompt=""):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def getpass(self, prompt=""):
        return self.hidden.pop(0)


@pytest.fixture
def ui(monkeypatch):
    """Fast, side-effect-free UI: no screen clearing, fixed speed, small modulus,
    and a fake clipboard (the real one is never touched)."""
    clipboard = []
    monkeypatch.setattr(tl, "clear", lambda: None)
    monkeypatch.setattr(tl, "calibrate", lambda *a, **k: RATE)
    monkeypatch.setattr(tl, "MODULUS_BITS", 512)
    monkeypatch.setattr(tl, "HAVE_GMPY2", False)
    monkeypatch.setattr(tl, "copy_to_clipboard", lambda text: clipboard.append(text) or True)
    monkeypatch.setattr(tl, "clear_clipboard", lambda: clipboard.append(None) or True)
    return clipboard


TINY_HOURS = "0.000005"  # 18,000 squarings at the fixed test speed


# ------------------------------------------------------------ command line

def test_cli_create_then_solve(tmp_path, monkeypatch, capsys, ui):
    Keyboard(monkeypatch, ["y", "PIN", "", "be sure"], hidden=["1234", "1234"])
    assert tl.main(["create", "v.tlp", "--hours", TINY_HOURS]) == 0
    assert json.load(open("v.tlp"))["t"] == 18_000
    assert tl.main(["solve", "v.tlp"]) == 0
    out = capsys.readouterr().out
    assert "PIN: 1234" in out and "Note from past you: be sure" in out


def test_cli_create_refuses_to_overwrite(tmp_path, monkeypatch, capsys, ui):
    make_vault(tmp_path / "v.tlp")
    before = (tmp_path / "v.tlp").read_bytes()
    assert tl.main(["create", "v.tlp", "--hours", "1"]) == 1
    assert "already exists" in capsys.readouterr().err
    assert (tmp_path / "v.tlp").read_bytes() == before


def test_cli_force_keeps_the_old_vault_and_its_progress(tmp_path, monkeypatch, ui):
    make_vault(tmp_path / "v.tlp")
    tl.solve_vault("v.tlp")
    old = (tmp_path / "v.tlp").read_bytes()
    Keyboard(monkeypatch, ["y", "PIN", "", ""], hidden=["1234", "1234"])
    assert tl.main(["create", "v.tlp", "--hours", TINY_HOURS, "--force"]) == 0
    (backup,) = glob.glob(str(tmp_path / "v.bak-*.tlp"))
    assert open(backup, "rb").read() == old
    assert os.path.exists(backup + ".progress") and not os.path.exists("v.tlp.progress")
    assert tl.solve_vault(backup) == ENTRIES  # the old vault still opens


@pytest.mark.parametrize("hours", ["0", "-5", "nan", "inf", "soon"])
def test_cli_rejects_bad_hours(hours, ui):
    with pytest.raises(SystemExit) as e:
        tl.main(["create", "v.tlp", "--hours", hours])
    assert e.value.code == 2
    assert not os.path.exists("v.tlp")


def test_cli_declining_without_gmpy2_creates_nothing(monkeypatch, capsys, ui):
    Keyboard(monkeypatch, ["n"])
    assert tl.main(["create", "v.tlp", "--hours", "1"]) == 1
    out = capsys.readouterr().out
    assert "5-10x faster" in out and "Nothing was created" in out
    assert not os.path.exists("v.tlp")


def test_cli_status(tmp_path, capsys):
    make_vault(tmp_path / "v.tlp")
    assert tl.main(["status", "v.tlp"]) == 0
    assert "(0.00%)" in capsys.readouterr().out
    tl.solve_vault("v.tlp")
    tl.main(["status", "v.tlp"])
    assert "UNLOCKED" in capsys.readouterr().out


def test_cli_solve_with_damaged_progress_explains_what_to_do(tmp_path, capsys):
    make_vault(tmp_path / "v.tlp")
    (tmp_path / "v.tlp.progress").write_text("garbage")
    assert tl.main(["solve", "v.tlp"]) == 1
    assert "damaged" in capsys.readouterr().err


def test_cli_missing_vault(capsys):
    assert tl.main(["solve", "nope.tlp"]) == 1
    assert "no vault file" in capsys.readouterr().err


def test_genpass(capsys):
    assert tl.main(["genpass"]) == 0
    assert re.fullmatch(r"[A-Za-z0-9]{5}(-[A-Za-z0-9]{5}){3}\n", capsys.readouterr().out)
    with pytest.raises(SystemExit):
        tl.main(["genpass", "--groups", "0"])


def test_bench(capsys, ui):
    assert tl.main(["bench"]) == 0
    assert "1,000,000 squarings/sec" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit):
        tl.main(["--version"])
    assert tl.__version__ in capsys.readouterr().out


# ------------------------------------------------------------ menu

def test_menu_quit(monkeypatch, ui):
    Keyboard(monkeypatch, ["0"])
    assert tl.main([]) == 0


def test_menu_create_then_unlock(tmp_path, monkeypatch, capsys, ui):
    Keyboard(monkeypatch, [
        "2", "y", "5", TINY_HOURS, "test",       # create, accept no-gmpy2, custom hours, name
        "PIN", "", "be sure",                     # one secret, then the note
        "",                                       # back to menu
        "3", "",                                  # unlock the only vault, back to menu
        "0",
    ], hidden=["1234", "1234"])
    assert tl.main([]) == 0
    out = capsys.readouterr().out
    assert os.path.exists(tmp_path / "test.tlp")
    assert "Clipboard cleared" in out and ui == [None]
    assert "PIN: 1234" in out and "now spent" in out


def test_menu_never_overwrites(tmp_path, monkeypatch, capsys, ui):
    make_vault(tmp_path / "vault.tlp")
    before = (tmp_path / "vault.tlp").read_bytes()
    Keyboard(monkeypatch, ["2", "y", "5", TINY_HOURS, "", "vault-2", "PIN", "", "", "", "0"],
             hidden=["1234", "1234"])
    tl.main([])
    assert "for example vault-2" in capsys.readouterr().out
    assert (tmp_path / "vault.tlp").read_bytes() == before
    assert os.path.exists(tmp_path / "vault-2.tlp")


def test_menu_declining_without_gmpy2_creates_nothing(tmp_path, monkeypatch, capsys, ui):
    Keyboard(monkeypatch, ["2", "n", "", "0"])
    tl.main([])
    out = capsys.readouterr().out
    assert "Nothing was created" in out and "Your vault" not in out
    assert ui == []  # clipboard left alone
    assert not glob.glob(str(tmp_path / "*.tlp"))


def test_menu_keeps_clipboard_when_creation_fails(tmp_path, monkeypatch, capsys, ui):
    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(tl, "create_vault", boom)
    Keyboard(monkeypatch, ["2", "y", "5", TINY_HOURS, "x", "PIN", "", "", "", "0"], hidden=["1", "1"])
    tl.main([])
    assert "Something went wrong" in capsys.readouterr().out
    assert ui == []  # the generated password must still be on the clipboard


def test_menu_offers_to_start_over_on_damaged_progress(tmp_path, monkeypatch, capsys, ui):
    make_vault(tmp_path / "v.tlp")
    (tmp_path / "v.tlp.progress").write_text("garbage")
    keys = Keyboard(monkeypatch, ["3", "y", "", "0"])
    tl.main([])
    out = capsys.readouterr().out
    assert "damaged" in out and any("Start over from 0%?" in p for p in keys.prompts)
    assert "Apple ID password: kQ7ve" in out


def test_menu_lists_vault_states(tmp_path, monkeypatch, capsys, ui):
    make_vault(tmp_path / "a.tlp")
    make_vault(tmp_path / "b.tlp")
    tl.solve_vault(str(tmp_path / "b.tlp"))
    Keyboard(monkeypatch, ["4", "0", "", "0"])
    tl.main([])
    out = capsys.readouterr().out
    assert "a.tlp" in out and "locked)" in out and "unlocked)" in out
