"""Vault format v2: key derivation, authentication of the header, padding, checksum."""

import json
import os

import pytest

import timelock as tl
from helpers import ENTRIES, make_vault


def solved(tmp_path, **kw):
    """Make a vault, solve it, and return (vault, b) where b is the puzzle answer."""
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path, t=5_000, **kw)
    tl.solve_vault(path)
    with open(path + ".progress", encoding="utf-8") as f:
        return vault, int(json.load(f)["x"], 16)


def test_hkdf_matches_rfc5869_test_case_1():
    okm = tl.hkdf_sha256(bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_new_vaults_are_v2_with_a_checksum(tmp_path):
    vault = make_vault(tmp_path / "v.tlp")
    assert vault["version"] == 2 and vault["checksum"] == tl.checksum(vault)


def test_encryption_and_mac_keys_differ(tmp_path):
    vault, b = solved(tmp_path)
    enc_key, mac_key = tl._v2_keys(b, vault)
    assert len(enc_key) == len(mac_key) == 32 and enc_key != mac_key


def test_padding_hides_secret_length(tmp_path):
    short = make_vault(tmp_path / "a.tlp", entries=[{"label": "pw", "secret": "x"}])
    long = make_vault(tmp_path / "b.tlp", entries=[{"label": "pw", "secret": "x" * 60}])
    assert len(short["ciphertext"]) == len(long["ciphertext"]) == 2 * tl.PAD_TO


@pytest.mark.parametrize("field, value", [
    ("labels", ["Something else", "Notes 🔐"]),
    ("note", "go ahead, open it"),
    ("t", 4_999),
    ("base", 3),
    ("nonce", "00" * 16),
])
def test_header_is_authenticated(tmp_path, field, value):
    vault, b = solved(tmp_path, note="Are you sure?")
    assert tl.decrypt_entries(vault, b) == ENTRIES
    vault[field] = value
    with pytest.raises(tl.IntegrityError):
        tl.decrypt_entries(vault, b)


def test_tampered_ciphertext_fails_the_mac(tmp_path):
    vault, b = solved(tmp_path)
    ct = bytearray.fromhex(vault["ciphertext"])
    ct[5] ^= 0x80
    vault["ciphertext"] = ct.hex()
    with pytest.raises(tl.IntegrityError):
        tl.decrypt_entries(vault, b)


def test_wrong_answer_fails_the_mac(tmp_path):
    vault, b = solved(tmp_path)
    with pytest.raises(tl.IntegrityError):
        tl.decrypt_entries(vault, b + 1)


def test_deliberate_tampering_is_reported_after_solving(tmp_path, capsys):
    """Someone who edits a field AND fixes the checksum still can't fool the MAC."""
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path, t=5_000)
    vault["labels"] = ["Bank PIN", "Notes 🔐"]
    vault["checksum"] = tl.checksum(vault)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vault, f)
    with pytest.raises(tl.TimelockError, match="Unlock failed"):
        tl.solve_vault(path)


def test_accidental_damage_is_caught_before_any_work(tmp_path, monkeypatch):
    path = str(tmp_path / "v.tlp")
    make_vault(path)
    text = open(path, encoding="utf-8").read()
    i = text.index('"ciphertext": "') + 20
    damaged = text[:i] + ("0" if text[i] != "0" else "1") + text[i + 1:]  # one flipped hex digit
    with open(path, "w", encoding="utf-8") as f:
        f.write(damaged)
    monkeypatch.setattr(tl, "square_chain", lambda *a: pytest.fail("started a doomed solve"))
    with pytest.raises(tl.TimelockError, match="checksum"):
        tl.solve_vault(path)


def test_reformatted_json_still_opens(tmp_path):
    """The checksum and MAC use canonical JSON, so pretty-printing the file is harmless."""
    path = str(tmp_path / "v.tlp")
    vault = make_vault(path, t=5_000)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=4, ensure_ascii=False)
    assert tl.solve_vault(path) == ENTRIES


def test_v1_vaults_are_still_accepted():
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "v1_vault.json")
    with open(fixture, encoding="utf-8") as f:
        vault = json.load(f)
    assert tl.vault_problem(vault) is None and vault["version"] == 1
