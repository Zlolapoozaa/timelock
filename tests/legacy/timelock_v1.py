#!/usr/bin/env python3
"""
timelock.py - lock secrets behind hours of unavoidable computation.

Uses the Rivest-Shamir-Wagner time-lock puzzle: unlocking requires computing
2^(2^t) mod n by t sequential squarings. Each squaring needs the previous
result, so extra cores, GPUs, or AI can't speed it up. Creating the puzzle is
instant because the creator knows the factors of n (then throws them away).

Easiest: run it with no arguments (or double-click Timelock.bat on Windows)
to get a menu. No commands needed.

Commands (optional, for power users):
  python timelock.py genpass                     print a strong random password
  python timelock.py create vault.tlp --hours 48 lock secrets into vault.tlp
  python timelock.py solve vault.tlp             unlock (resumable, Ctrl+C safe)
  python timelock.py status vault.tlp            show progress without solving
  python timelock.py bench                       squarings/sec on this machine

Optional speedup: pip install gmpy2   (install it BEFORE `create` so the lock
is calibrated to the fastest speed you could ever solve at.)
"""

import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets
import signal
import string
import subprocess
import sys
import time
from types import SimpleNamespace

try:
    import gmpy2
    from gmpy2 import mpz
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False
    mpz = int

VERSION = 1
MODULUS_BITS = 2048
CHECKPOINT_SECONDS = 30
CHUNK = 20_000


# ---------------------------------------------------------------- primes

SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    if HAVE_GMPY2:
        while True:
            c = mpz(secrets.randbits(bits)) | (mpz(1) << (bits - 1)) | 1
            if gmpy2.is_prime(c, 50):
                return int(c)
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c


# ---------------------------------------------------------------- crypto

def keystream(key, nonce, length):
    return hashlib.shake_256(b"timelock-stream" + key + nonce).digest(length)


def derive_key(b):
    nbytes = (MODULUS_BITS + 7) // 8
    return hashlib.sha256(b"timelock-key" + int(b).to_bytes(nbytes, "big")).digest()


def seal(key, plaintext):
    nonce = secrets.token_bytes(16)
    ct = bytes(x ^ y for x, y in zip(plaintext, keystream(key, nonce, len(plaintext))))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return nonce, ct, tag


def unseal(key, nonce, ct, tag):
    expected = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("integrity check failed (wrong result or corrupted file)")
    return bytes(x ^ y for x, y in zip(ct, keystream(key, nonce, len(ct))))


# ---------------------------------------------------------------- helpers

def fmt_duration(seconds):
    seconds = int(max(0, seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def benchmark(seconds=5.0):
    """Squarings per second on this machine, same loop the solver uses."""
    p = random_prime(MODULUS_BITS // 2)
    q = random_prime(MODULUS_BITS // 2)
    n = mpz(p * q)
    x = mpz(2)
    count = 0
    start = time.perf_counter()
    while time.perf_counter() - start < seconds:
        for _ in range(2000):
            x = x * x % n
        count += 2000
    return count / (time.perf_counter() - start)


def progress_path(vault_path):
    return vault_path + ".progress"


def load_vault(path):
    with open(path, "r", encoding="utf-8") as f:
        v = json.load(f)
    if v.get("version") != VERSION:
        sys.exit("Unsupported vault version.")
    return v


def save_json_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------- commands

def make_password(groups=4):
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(groups))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def cmd_genpass(args):
    print(make_password(args.groups))


def cmd_bench(args):
    print(f"gmpy2: {'yes' if HAVE_GMPY2 else 'NO (pip install gmpy2 for the fast path)'}")
    print("Benchmarking for ~5 seconds...")
    rate = benchmark()
    print(f"{rate:,.0f} squarings/sec")
    print(f"48h lock = {int(rate * 48 * 3600):,} squarings on this machine")


def cmd_create(args):
    if os.path.exists(args.vault) and not args.force:
        sys.exit(f"{args.vault} already exists. Use --force to overwrite.")
    if not HAVE_GMPY2:
        print("WARNING: gmpy2 not installed. If you later solve WITH gmpy2, it will unlock")
        print("         several times faster than intended. Run `pip install gmpy2` first,")
        print("         or answer 'y' to continue anyway.")
        if input("Continue without gmpy2? [y/N] ").strip().lower() != "y":
            return

    print("\nEnter the secrets to lock. Input is hidden.")
    print("Leave the label empty when you're done.\n")
    entries = []
    while True:
        label = input(f"Label for secret #{len(entries) + 1} (e.g. 'Apple ID password'): ").strip()
        if not label:
            break
        value = getpass.getpass("  Secret (hidden): ")
        confirm = getpass.getpass("  Repeat secret:   ")
        if value != confirm:
            print("  Didn't match, try that one again.")
            continue
        if not value:
            print("  Empty secret skipped.")
            continue
        entries.append({"label": label, "secret": value})
    if not entries:
        sys.exit("Nothing to lock.")
    note = input("Optional note shown before unlocking (e.g. 'Are you sure?'): ").strip()

    print("\nBenchmarking this machine (~5s)...")
    rate = benchmark()
    t = max(1, int(rate * args.hours * 3600))
    print(f"  {rate:,.0f} squarings/sec  ->  t = {t:,} squarings (~{fmt_duration(t / rate)} here)")

    print(f"Generating {MODULUS_BITS}-bit modulus...")
    p = random_prime(MODULUS_BITS // 2)
    q = random_prime(MODULUS_BITS // 2)
    while q == p:
        q = random_prime(MODULUS_BITS // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Shortcut that only the creator has: reduce the exponent mod phi(n).
    e = pow(2, t, phi)
    b = pow(2, e, n)
    del p, q, phi, e

    key = derive_key(b)
    payload = json.dumps({"entries": entries}).encode("utf-8")
    nonce, ct, tag = seal(key, payload)
    assert json.loads(unseal(key, nonce, ct, tag))["entries"] == entries
    del b, key, payload

    vault = {
        "version": VERSION,
        "n": hex(n),
        "t": t,
        "base": 2,
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "tag": tag.hex(),
        "labels": [x["label"] for x in entries],
        "note": note,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "calibrated_rate": rate,
        "calibrated_hours": args.hours,
        "calibrated_with_gmpy2": HAVE_GMPY2,
    }
    save_json_atomic(args.vault, vault)
    print(f"\nLocked {len(entries)} secret(s) into {args.vault}")
    print(f"Estimated unlock time on this machine: {fmt_duration(t / rate)} of computing.")
    print("The shortcut has been discarded. Back up this file (USB / cloud) now.")


def cmd_status(args):
    v = load_vault(args.vault)
    t = v["t"]
    done = 0
    pp = progress_path(args.vault)
    if os.path.exists(pp):
        with open(pp, "r", encoding="utf-8") as f:
            done = json.load(f).get("i", 0)
    rate = v["calibrated_rate"]
    print(f"Vault:    {args.vault}  (created {v['created']})")
    print(f"Contains: {', '.join(v['labels'])}")
    print(f"Progress: {done:,} / {t:,}  ({100 * done / t:.2f}%)")
    print(f"Left:     ~{fmt_duration((t - done) / rate)} at the calibrated speed")


def cmd_solve(args):
    v = load_vault(args.vault)
    n = mpz(int(v["n"], 16))
    t = v["t"]
    pp = progress_path(args.vault)

    x, i = mpz(v["base"]), 0
    if os.path.exists(pp):
        with open(pp, "r", encoding="utf-8") as f:
            prog = json.load(f)
        if prog.get("n") == v["n"]:
            x, i = mpz(int(prog["x"], 16)), prog["i"]
            print(f"Resuming from {100 * i / t:.2f}%")
    else:
        if v.get("note"):
            print(f"\nNote from past you: {v['note']}\n")
        print(f"Unlocking {', '.join(v['labels'])}")
        print(f"Estimated: ~{fmt_duration(t / v['calibrated_rate'])} of computing. Ctrl+C to pause anytime.\n")

    if not HAVE_GMPY2:
        print("(gmpy2 not installed - this will be slower than calibrated if it was created with gmpy2)")

    stop = {"flag": False}

    def _stop(signum, frame):
        stop["flag"] = True
    for sig in ("SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), _stop)

    def checkpoint():
        save_json_atomic(pp, {"n": v["n"], "i": i, "x": hex(int(x))})

    last_save = time.monotonic()
    rate_start_t, rate_start_i = time.monotonic(), i
    while i < t:
        steps = min(CHUNK, t - i)
        y = x
        for _ in range(steps):
            y = y * y % n
        x, i = y, i + steps          # signals only set a flag, so this pair stays consistent
        now = time.monotonic()
        if stop["flag"]:
            checkpoint()
            print(f"\nPaused at {100 * i / t:.2f}%. Run solve again to resume.")
            return
        if now - last_save >= CHECKPOINT_SECONDS or i == t:
            checkpoint()
            last_save = now
            elapsed = now - rate_start_t
            rate = (i - rate_start_i) / elapsed if elapsed > 0 else 0
            eta = fmt_duration((t - i) / rate) if rate else "?"
            print(f"\r{100 * i / t:6.2f}%   {i:,}/{t:,}   ETA {eta}        ", end="", flush=True)

    print("\n")
    key = derive_key(x)
    try:
        payload = unseal(key, bytes.fromhex(v["nonce"]), bytes.fromhex(v["ciphertext"]), bytes.fromhex(v["tag"]))
    except ValueError:
        sys.exit(f"Unlock failed: the progress file is damaged. Delete '{pp}' and run solve again "
                 "(starts over from 0%). Your vault file itself is fine.")
    for entry in json.loads(payload)["entries"]:
        print(f"{entry['label']}: {entry['secret']}")
    print("\nDone. This vault is now spent (the progress file holds the answer).")
    print("To lock things up again: change the password(s), then create a NEW vault (menu option 2).")


# ---------------------------------------------------------------- menu

HERE = os.path.dirname(os.path.abspath(__file__))
HOUR_PRESETS = [("24 hours", 24), ("48 hours (recommended)", 48), ("72 hours", 72), ("1 week", 168)]


def _ansi():
    if os.name == "nt":
        os.system("")  # turns on color support in Windows terminals


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def bold(text):
    return f"\033[1m{text}\033[0m"


def dim(text):
    return f"\033[2m{text}\033[0m"


def pause():
    input(dim("\nPress Enter to go back to the menu..."))


def ask_choice(prompt, options):
    """options: list of labels. Returns index, or None for back."""
    for k, label in enumerate(options, 1):
        print(f"  {bold(str(k))}  {label}")
    print(f"  {bold('0')}  Back")
    while True:
        raw = input(f"\n{prompt} ").strip()
        if raw == "0" or raw == "":
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print("  Type one of the numbers above.")


def copy_to_clipboard(text):
    try:
        if os.name == "nt":
            subprocess.run("clip", input=text.encode("utf-16le"), check=True, shell=True)
        elif sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        else:
            subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True)
        return True
    except Exception:
        return False


def clear_clipboard():
    copy_to_clipboard(" ")


def find_vaults():
    found = []
    for folder in dict.fromkeys([HERE, os.getcwd()]):
        for name in sorted(os.listdir(folder)):
            if name.endswith(".tlp"):
                found.append(os.path.join(folder, name))
    return found


def pick_vault():
    vaults = find_vaults()
    if not vaults:
        print(f"No vault files (.tlp) found in:\n  {HERE}")
        print("Put your vault file in the same folder as timelock.py.")
        return None
    if len(vaults) == 1:
        return vaults[0]
    labels = []
    for p in vaults:
        try:
            v = load_vault(p)
            labels.append(f"{os.path.basename(p)}  {dim('(' + ', '.join(v['labels']) + ')')}")
        except Exception:
            labels.append(os.path.basename(p))
    idx = ask_choice("Which vault?", labels)
    return None if idx is None else vaults[idx]


def menu_password():
    clear()
    print(bold("Generate a password\n"))
    pw = make_password()
    if copy_to_clipboard(pw):
        print("A new strong password has been " + bold("copied to your clipboard") + ".")
        print("Paste it where you're changing the password (Ctrl+V / Cmd+V).")
        print(dim("It isn't shown on purpose, so you don't memorize it."))
        if input("\nShow it anyway? [y/N] ").strip().lower() == "y":
            print(f"\n  {pw}")
    else:
        print("Couldn't reach the clipboard, so here it is:\n")
        print(f"  {pw}\n")
        print("Select and copy it, then close this window after creating your vault.")
    pause()


def menu_create():
    clear()
    print(bold("Create a vault\n"))
    print("How long should unlocking take on this computer?\n")
    idx = ask_choice("Pick a length:", [label for label, _ in HOUR_PRESETS] + ["Custom"])
    if idx is None:
        return
    if idx == len(HOUR_PRESETS):
        raw = input("Hours: ").strip()
        try:
            hours = float(raw)
            assert hours > 0
        except Exception:
            print("That's not a number of hours.")
            pause()
            return
    else:
        hours = HOUR_PRESETS[idx][1]

    name = input(f"\nVault name {dim('[vault]')}: ").strip() or "vault"
    if not name.endswith(".tlp"):
        name += ".tlp"
    path = os.path.join(HERE, name)
    force = False
    if os.path.exists(path):
        if input(f"{name} already exists. Overwrite it? [y/N] ").strip().lower() != "y":
            return
        force = True

    print(dim("\nTip: to paste a hidden secret, use Ctrl+V (Windows) or Cmd+V (Mac), then Enter."))
    try:
        cmd_create(SimpleNamespace(vault=path, hours=hours, force=force))
    except SystemExit as e:
        if e.code:
            print(e.code)
        pause()
        return
    clear_clipboard()
    print("\nClipboard cleared.")
    if os.name == "nt":
        print(bold("Also press Win+V and choose 'Clear all'") + " - Windows keeps clipboard history.")
    print(f"\nYour vault: {path}")
    print(bold("Back it up now") + " (USB drive + Google Drive). Lose it = lose those secrets.")
    pause()


def menu_solve():
    clear()
    print(bold("Unlock a vault\n"))
    path = pick_vault()
    if not path:
        pause()
        return
    old = {sig: signal.getsignal(getattr(signal, sig))
           for sig in ("SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP") if hasattr(signal, sig)}
    print(dim("Press Ctrl+C anytime to pause. Progress is saved.\n"))
    try:
        cmd_solve(SimpleNamespace(vault=path))
    except SystemExit as e:
        if e.code:
            print(e.code)
    finally:
        for sig, handler in old.items():
            signal.signal(getattr(signal, sig), handler)
    pause()


def menu_status():
    clear()
    print(bold("Check progress\n"))
    path = pick_vault()
    if path:
        cmd_status(SimpleNamespace(vault=path))
    pause()


def menu_bench():
    clear()
    print(bold("Test this computer's speed\n"))
    cmd_bench(None)
    print(dim("\nRun this on each computer. Create your vault on the fastest one."))
    pause()


def menu_install_gmpy2():
    clear()
    print(bold("Install the speed library (gmpy2)\n"))
    print("Installing... this takes a minute.\n")
    cmd = [sys.executable, "-m", "pip", "install", "--user", "gmpy2"]
    result = subprocess.run(cmd)
    if result.returncode != 0:
        result = subprocess.run([sys.executable, "-m", "pip", "install", "gmpy2"])
    if result.returncode == 0:
        print("\nInstalled. Restarting the app...")
        time.sleep(1)
        os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)])
    print("\nInstall failed. Try running this in a terminal:  pip install gmpy2")
    pause()


def menu():
    _ansi()
    while True:
        clear()
        print(bold("=== Timelock Vault ===") + "   lock passwords behind hours of computing\n")
        if not HAVE_GMPY2:
            print("\033[33m! Speed library not installed. Install it (option 6) BEFORE creating a vault.\033[0m\n")
        vaults = find_vaults()
        if vaults:
            print(dim("Vaults here: " + ", ".join(os.path.basename(v) for v in vaults)) + "\n")
        options = [
            ("Generate a password", menu_password),
            ("Create a vault", menu_create),
            ("Unlock a vault", menu_solve),
            ("Check unlock progress", menu_status),
            ("Test this computer's speed", menu_bench),
        ]
        if not HAVE_GMPY2:
            options.append(("Install speed library (gmpy2)", menu_install_gmpy2))
        for k, (label, _) in enumerate(options, 1):
            print(f"  {bold(str(k))}  {label}")
        print(f"  {bold('0')}  Quit")
        raw = input("\nPick a number: ").strip()
        if raw == "0":
            clear()
            return
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            try:
                options[int(raw) - 1][1]()
            except KeyboardInterrupt:
                print("\nCancelled.")
                time.sleep(0.8)


def main():
    if len(sys.argv) == 1:
        try:
            menu()
        except (KeyboardInterrupt, EOFError):
            print()
        return
    ap = argparse.ArgumentParser(description="Time-lock puzzle vault.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genpass", help="print a strong random password")
    g.add_argument("--groups", type=int, default=4, help="5-char groups (default 4)")
    g.set_defaults(func=cmd_genpass)

    b = sub.add_parser("bench", help="measure squarings/sec")
    b.set_defaults(func=cmd_bench)

    c = sub.add_parser("create", help="lock secrets into a vault file")
    c.add_argument("vault")
    c.add_argument("--hours", type=float, required=True, help="unlock time on this machine")
    c.add_argument("--force", action="store_true")
    c.set_defaults(func=cmd_create)

    s = sub.add_parser("solve", help="unlock a vault (resumable)")
    s.add_argument("vault")
    s.set_defaults(func=cmd_solve)

    st = sub.add_parser("status", help="show unlock progress")
    st.add_argument("vault")
    st.set_defaults(func=cmd_status)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
