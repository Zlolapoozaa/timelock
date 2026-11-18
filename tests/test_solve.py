import json
import os
import signal

import pytest

import timelock as tl
from helpers import ENTRIES, make_vault

STOP_SIGNALS = [s for s in ("SIGINT", "SIGBREAK", "SIGTERM", "SIGHUP") if hasattr(signal, s)]
REAL_SQUARE_CHAIN = tl.square_chain


def puzzle(vault, i):
    """2^(2^i) mod n computed directly: what a correct checkpoint must contain."""
    return pow(vault["base"], 1 << i, int(vault["n"], 16))


def pause_after(monkeypatch, chunks, signame="SIGINT"):
    """Deliver a real signal to ourselves after `chunks` chunks, like a Ctrl+C."""
    real, calls = tl.square_chain, {"n": 0}

    def square_chain(x, steps, n):
        result = real(x, steps, n)
        calls["n"] += 1
        if calls["n"] == chunks:
            signal.raise_signal(getattr(signal, signame))
        return result

    monkeypatch.setattr(tl, "square_chain", square_chain)


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------------ round trips

def test_round_trip_multiple_secrets(backend, tmp_path, capsys):
    vault = make_vault(tmp_path / "v.tlp", note="Are you sure?")
    assert tl.solve_vault(str(tmp_path / "v.tlp")) == ENTRIES
    out = capsys.readouterr().out
    assert "Note from past you: Are you sure?" in out
    assert "Unlocking: Apple ID password, Notes" in out
    assert vault["t"] > 10 * tl.CHUNK  # really went through many chunks


def test_single_secret_and_tiny_t(backend, tmp_path):
    entries = [{"label": "pin", "secret": "1234"}]
    make_vault(tmp_path / "v.tlp", t=1, entries=entries)
    assert tl.solve_vault(str(tmp_path / "v.tlp")) == entries


def test_backends_compute_the_same_squarings():
    pytest.importorskip("gmpy2")
    import gmpy2
    n = (1 << 511) + 187  # any odd modulus
    pure = tl.square_chain(3, 5000, n)
    fast = tl.square_chain(gmpy2.mpz(3), 5000, gmpy2.mpz(n))
    assert pure == fast == pow(3, 1 << 5000, n)


def test_rerunning_a_finished_vault_is_instant(backend, tmp_path, monkeypatch):
    make_vault(tmp_path / "v.tlp")
    tl.solve_vault(str(tmp_path / "v.tlp"))
    monkeypatch.setattr(tl, "square_chain", lambda *a: pytest.fail("should not compute again"))
    assert tl.solve_vault(str(tmp_path / "v.tlp")) == ENTRIES


# ------------------------------------------------------------ pause / resume

@pytest.mark.parametrize("signame", STOP_SIGNALS)
def test_pause_saves_consistent_progress_then_resumes(backend, tmp_path, monkeypatch, capsys, signame):
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path)
    handler_before = signal.getsignal(signal.SIGINT)

    pause_after(monkeypatch, chunks=3, signame=signame)
    assert tl.solve_vault(path) is None
    assert "Paused at" in capsys.readouterr().out
    assert signal.getsignal(signal.SIGINT) is handler_before  # handlers restored

    progress = read_json(path + ".progress")
    assert progress["i"] == 3 * tl.CHUNK
    assert int(progress["x"], 16) == puzzle(vault, progress["i"])  # x matches i exactly

    monkeypatch.setattr(tl, "square_chain", REAL_SQUARE_CHAIN)
    assert tl.solve_vault(path) == ENTRIES
    assert "Resuming from" in capsys.readouterr().out


def test_pause_resume_many_times(backend, tmp_path, monkeypatch):
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path, t=12_000)
    for _ in range(5):
        pause_after(monkeypatch, chunks=2)
        assert tl.solve_vault(path) is None
        progress = read_json(path + ".progress")
        assert int(progress["x"], 16) == puzzle(vault, progress["i"])
    monkeypatch.setattr(tl, "square_chain", REAL_SQUARE_CHAIN)
    assert tl.solve_vault(path) == ENTRIES


def test_periodic_checkpoints_are_consistent(tmp_path, monkeypatch):
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path)
    monkeypatch.setattr(tl, "CHECKPOINT_SECONDS", 0)  # save after every chunk
    seen = []
    real = tl.write_progress

    def spy(pp, v, i, x):
        real(pp, v, i, x)
        seen.append(read_json(pp))

    monkeypatch.setattr(tl, "write_progress", spy)
    tl.solve_vault(path)
    assert len(seen) >= 10
    for p in seen:
        assert int(p["x"], 16) == puzzle(vault, p["i"])


# ------------------------------------------------------------ damaged progress

def test_truncated_progress_file_is_reported_not_used(tmp_path, monkeypatch):
    path = str(tmp_path / "v.tlp")
    make_vault(path)
    with open(path + ".progress", "w") as f:
        f.write('{"n": "0x12')
    with pytest.raises(tl.ProgressError, match="damaged"):
        tl.solve_vault(path)
    assert open(path + ".progress").read() == '{"n": "0x12'  # left untouched

    assert tl.solve_vault(path, start_over=True) == ENTRIES
    assert any(".damaged-" in name for name in os.listdir(tmp_path))  # kept, not deleted


def _flip_x(p):
    p["x"] = hex(int(p["x"], 16) ^ 1)  # checksum no longer matches


def _bump_i(p):
    p["i"] += 1


def _past_the_end(p):
    p["i"] = 10**12
    del p["check"]  # like an old-format file


def _wrong_type(p):
    p["i"] = "lots"
    del p["check"]


def _missing_x(p):
    del p["x"]


@pytest.mark.parametrize("edit", [_flip_x, _bump_i, _past_the_end, _wrong_type, _missing_x])
def test_inconsistent_progress_is_detected_before_any_work(tmp_path, monkeypatch, edit):
    path = str(tmp_path / "v.tlp")
    make_vault(path)
    pause_after(monkeypatch, chunks=2)
    tl.solve_vault(path)
    progress = read_json(path + ".progress")
    edit(progress)
    with open(path + ".progress", "w") as f:
        json.dump(progress, f)
    monkeypatch.setattr(tl, "square_chain", lambda *a: pytest.fail("worked on a damaged checkpoint"))
    with pytest.raises(tl.ProgressError):
        tl.solve_vault(path)


def test_old_progress_file_without_checksum_still_resumes(tmp_path, monkeypatch, capsys):
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path)
    with open(path + ".progress", "w") as f:  # exactly what the original v1 code wrote
        json.dump({"n": vault["n"], "i": 5000, "x": hex(puzzle(vault, 5000))}, f)
    assert tl.solve_vault(path) == ENTRIES
    assert "Resuming from" in capsys.readouterr().out


def test_progress_from_another_vault_is_moved_aside(tmp_path, capsys):
    a, b = str(tmp_path / "a.tlp"), str(tmp_path / "b.tlp")
    make_vault(a)
    make_vault(b)
    tl.solve_vault(a)
    os.replace(a + ".progress", b + ".progress")  # e.g. files shuffled by hand
    assert tl.vault_state(b, tl.load_vault(b)) == (0, "a progress file from a different vault will be ignored")
    assert tl.solve_vault(b) == ENTRIES
    assert "different vault" in capsys.readouterr().out
    assert any(".other-" in name for name in os.listdir(tmp_path))


# ------------------------------------------------------------ saving

def test_checkpoint_retries_while_another_program_holds_the_file(tmp_path, monkeypatch):
    real, calls = os.replace, {"n": 0}

    def flaky_replace(src, dst):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise PermissionError(13, "file is open in another program")
        real(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    tl.save_json_atomic(str(tmp_path / "f.json"), {"ok": 1})
    assert read_json(tmp_path / "f.json") == {"ok": 1}
    assert [n for n in os.listdir(tmp_path) if n.endswith(".tmp")] == []


def test_solver_survives_checkpoints_that_keep_failing(tmp_path, monkeypatch, capsys):
    path = str(tmp_path / "v.tlp")
    make_vault(path)
    monkeypatch.setattr(tl, "CHECKPOINT_SECONDS", 0)

    def broken(*a):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(tl, "write_progress", broken)
    assert tl.solve_vault(path) == ENTRIES
    assert "Couldn't save progress" in capsys.readouterr().out


def test_temp_files_are_unique(tmp_path, monkeypatch):
    names = []
    real = tl.tempfile.mkstemp

    def spy(**kw):
        fd, name = real(**kw)
        names.append(name)
        return fd, name

    monkeypatch.setattr(tl.tempfile, "mkstemp", spy)
    for k in range(3):
        tl.save_json_atomic(str(tmp_path / "p.json"), {"k": k})
    assert len(set(names)) == 3


# ------------------------------------------------------------ tampering

def test_tampered_ciphertext_fails_the_mac(tmp_path):
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path)
    ct = bytearray.fromhex(vault["ciphertext"])
    ct[0] ^= 1
    vault["ciphertext"] = ct.hex()
    vault.pop("checksum", None)
    with open(path, "w") as f:
        json.dump(vault, f)
    with pytest.raises(tl.TimelockError, match="(Unlock failed|damaged)"):
        tl.solve_vault(path)


def test_lowering_t_gives_no_shortcut(tmp_path):
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path, t=20_000)
    vault["t"] = 10
    vault.pop("checksum", None)
    with open(path, "w") as f:
        json.dump(vault, f)
    with pytest.raises(tl.TimelockError, match="(Unlock failed|damaged)"):
        tl.solve_vault(path)
