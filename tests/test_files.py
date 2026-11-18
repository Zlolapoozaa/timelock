"""What ends up on disk: no secrets, no overwrites, damaged files recognised."""

import json
import os

import pytest

import timelock as tl
from helpers import ENTRIES, RATE, make_vault


def test_vault_file_holds_no_secret_material(tmp_path, monkeypatch):
    primes = []
    real = tl.random_prime
    monkeypatch.setattr(tl, "random_prime", lambda bits: primes.append(real(bits)) or primes[-1])
    seen = {}
    real_seal = tl._seal
    monkeypatch.setattr(tl, "_seal", lambda vault, b, entries: seen.update(b=b) or real_seal(vault, b, entries))

    make_vault(tmp_path / "v.tlp")
    text = (tmp_path / "v.tlp").read_text(encoding="utf-8").lower()
    p, q = primes[:2]
    phi = (p - 1) * (q - 1)
    forbidden = [p, q, phi, seen["b"]]
    for number in forbidden:
        assert format(number, "x") not in text and str(number) not in text
    for e in ENTRIES:
        assert e["secret"].lower() not in text
        assert json.dumps(e["secret"])[1:-1].lower() not in text
    assert "secret" not in text  # not even the JSON key


def test_mid_solve_progress_holds_no_secrets(tmp_path, monkeypatch):
    path = str(tmp_path / "v.tlp")
    make_vault(path)
    monkeypatch.setattr(tl, "CHECKPOINT_SECONDS", 0)
    real, calls = tl.square_chain, {"n": 0}

    def stop_soon(x, steps, n):
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt
        return real(x, steps, n)

    monkeypatch.setattr(tl, "square_chain", stop_soon)
    with pytest.raises(KeyboardInterrupt):
        tl.solve_vault(path)
    text = open(path + ".progress", encoding="utf-8").read()
    for e in ENTRIES:
        assert e["secret"] not in text


def test_create_never_overwrites(tmp_path):
    make_vault(tmp_path / "v.tlp")
    before = (tmp_path / "v.tlp").read_bytes()
    with pytest.raises(tl.TimelockError, match="never overwrites"):
        make_vault(tmp_path / "v.tlp")
    assert (tmp_path / "v.tlp").read_bytes() == before


def test_create_moves_a_stale_progress_file_aside(tmp_path):
    (tmp_path / "v.tlp.progress").write_text('{"n": "0x5", "i": 99, "x": "0x2"}')
    make_vault(tmp_path / "v.tlp")
    assert not (tmp_path / "v.tlp.progress").exists()
    assert any(".stale-" in name for name in os.listdir(tmp_path))
    assert tl.vault_state(str(tmp_path / "v.tlp"), tl.load_vault(str(tmp_path / "v.tlp"))) == (0, "")


@pytest.mark.parametrize("hours", [0, -1, float("nan"), float("inf")])
def test_create_rejects_bad_hours(tmp_path, hours):
    with pytest.raises(tl.TimelockError, match="positive"):
        tl.create_vault(str(tmp_path / "v.tlp"), ENTRIES, hours, RATE, bits=512)


def test_create_needs_something_to_lock(tmp_path):
    with pytest.raises(tl.TimelockError, match="Nothing to lock"):
        tl.create_vault(str(tmp_path / "v.tlp"), [], 1, RATE, bits=512)


@pytest.mark.parametrize("bits", [512, 1024])
def test_modulus_has_exactly_the_requested_size(tmp_path, bits):
    for k in range(3):
        vault = tl.create_vault(str(tmp_path / f"{k}.tlp"), ENTRIES, 0.001, RATE, bits=bits)
        assert int(vault["n"], 16).bit_length() == bits


@pytest.mark.parametrize("edit, message", [
    (lambda v: v.update(version=99), "newer Timelock"),
    (lambda v: v.update(version="x"), "unknown format"),
    (lambda v: v.pop("tag"), "damaged"),
    (lambda v: v.update(n="not hex"), "damaged"),
    (lambda v: v.update(t=0), "damaged"),
    (lambda v: v.update(t=True), "damaged"),
    (lambda v: v.update(nonce="00"), "damaged"),
])
def test_damaged_vaults_are_recognised_before_solving(tmp_path, edit, message):
    vault = make_vault(tmp_path / "v.tlp")
    edit(vault)
    (tmp_path / "v.tlp").write_text(json.dumps(vault))
    with pytest.raises(tl.TimelockError, match=message):
        tl.load_vault(str(tmp_path / "v.tlp"))


def test_unreadable_vault(tmp_path):
    (tmp_path / "v.tlp").write_text("{not json")
    with pytest.raises(tl.TimelockError, match="Can't read"):
        tl.load_vault(str(tmp_path / "v.tlp"))
