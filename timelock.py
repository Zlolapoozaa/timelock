#!/usr/bin/env python3
"""
timelock - lock secrets behind hours of unavoidable computation.

Uses the Rivest-Shamir-Wagner (1996) time-lock puzzle: unlocking requires
computing 2^(2^t) mod n with t sequential squarings. Each squaring needs the
previous result, so extra cores or GPUs don't help. Creating the puzzle is
instant because the creator knows the factors of n (and then throws them away).

Easiest: run it with no arguments (or double-click Timelock.bat on Windows,
Timelock.command on macOS) to get a menu. No commands needed.

Commands (optional, for power users):
  timelock genpass                       print a strong random password
  timelock create vault.tlp --hours 48   lock secrets into vault.tlp
  timelock solve vault.tlp               unlock (resumable, Ctrl+C safe)
  timelock status vault.tlp              show progress without solving
  timelock bench                         squarings/sec on this machine
`python timelock.py ...` and `python -m timelock ...` work the same way.

Optional speedup: pip install gmpy2. Install it BEFORE `create`, so the lock is
calibrated to the fastest speed this machine could ever solve it at.
"""

import argparse
import getpass
import hashlib
import hmac
import importlib
import json
import math
import os
import secrets
import signal
import site
import string
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from types import SimpleNamespace

try:
    import gmpy2
except ImportError:
    gmpy2 = None

__version__ = "1.0.0"

HAVE_GMPY2 = gmpy2 is not None
FORMAT_VERSION = 2             # vault format written by `create`
READABLE_VERSIONS = (1, 2)     # vault formats `solve` and `status` understand
MODULUS_BITS = 2048
CHECKPOINT_SECONDS = 10
CHUNK = 20_000                 # squarings between checks for a pause request
STOP_SIGNALS = ("SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP")


class TimelockError(Exception):
    """A problem to show the user as a plain message, without a traceback."""


class IntegrityError(TimelockError):
    """The puzzle answer doesn't open the vault (wrong answer or altered file)."""


class ProgressError(TimelockError):
    """The .progress file is unreadable or inconsistent."""


class ProgressMismatch(ProgressError):
    """The .progress file belongs to a different vault."""


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
    """Random prime with its top two bits set, so a product of two has exactly 2*bits bits."""
    top = 3 << (bits - 2)
    while True:
        c = secrets.randbits(bits) | top | 1
        if gmpy2.is_prime(c, 50) if HAVE_GMPY2 else is_probable_prime(c):
            return c


# ---------------------------------------------------------------- squaring

def to_num(x):
    """The fastest integer type available: gmpy2's mpz if installed, else int."""
    return gmpy2.mpz(x) if HAVE_GMPY2 else int(x)


def square_chain(x, steps, n):
    """Return x^(2^steps) mod n, i.e. `steps` sequential modular squarings.

    One modular exponentiation by 2^steps performs exactly those squarings
    without Python's per-step overhead (about 20% faster than a Python loop with
    gmpy2). The speed test uses this same function, so locks are calibrated to the
    fastest path this program has, not a slower one someone could easily beat."""
    if HAVE_GMPY2:
        return gmpy2.powmod(x, gmpy2.mpz(1) << steps, n)
    return pow(x, 1 << steps, n)


def benchmark(seconds=2.0, bits=MODULUS_BITS):
    """Squarings per second on this machine, through the solver's own code path."""
    n = to_num(secrets.randbits(bits) | (1 << (bits - 1)) | 1)  # any odd modulus this size is as fast
    x = to_num(secrets.randbits(bits - 1))
    done = 0
    start = time.perf_counter()
    while True:
        x = square_chain(x, CHUNK, n)
        done += CHUNK
        elapsed = time.perf_counter() - start
        if elapsed >= seconds:
            return done / elapsed


def calibrate(runs=3, seconds=2.0):
    """Best of several runs: the lock should match the fastest this machine can
    go, not a moment when something else was keeping it busy."""
    return max(benchmark(seconds) for _ in range(runs))


# ---------------------------------------------------------------- crypto
#
# b = 2^(2^t) mod n is the puzzle answer; the payload is the secrets as JSON.
#
# Format v2 (written by create since 1.0.0), standard library only:
#   enc_key, mac_key = HKDF-SHA256(b, salt="timelock-v2", info="encryption" / "authentication")
#   payload     = JSON padded with spaces to a multiple of 128 bytes (hides secret lengths)
#   ciphertext  = payload XOR SHAKE-256("timelock-v2-stream" || enc_key || nonce)
#   tag         = HMAC-SHA256(mac_key, "timelock-v2-mac" || len(header) || header || ciphertext)
#                 where header = canonical JSON of version, n, t, base, nonce, labels, note
#   checksum    = SHA-256 of the file's canonical JSON. Not a security feature: it catches
#                 accidental damage before a long solve instead of after it.
#
# Format v1 (still read, no longer written):
#   key         = SHA-256("timelock-key" || b as 256 big-endian bytes)
#   ciphertext  = payload XOR SHAKE-256("timelock-stream" || key || nonce)
#   tag         = HMAC-SHA256(key, nonce || ciphertext)
#
# Both are encrypt-then-MAC: the tag is checked, in constant time, before decrypting.

V1_KEY_BYTES = 256
PAD_TO = 128
V2_HEADER = ("version", "n", "t", "base", "nonce", "labels", "note")


def _xor(data, stream):
    return bytes(a ^ b for a, b in zip(data, stream))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def hkdf_sha256(ikm, salt, info, length=32):
    """HKDF (RFC 5869) with SHA-256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def checksum(vault):
    """SHA-256 over everything in the vault except the checksum itself."""
    return hashlib.sha256(_canonical({k: v for k, v in vault.items() if k != "checksum"})).hexdigest()


def _v1_key(b):
    return hashlib.sha256(b"timelock-key" + int(b).to_bytes(V1_KEY_BYTES, "big")).digest()


def _v2_keys(b, vault):
    n = int(vault["n"], 16)
    ikm = int(b).to_bytes((n.bit_length() + 7) // 8, "big")
    return (hkdf_sha256(ikm, b"timelock-v2", b"encryption"),
            hkdf_sha256(ikm, b"timelock-v2", b"authentication"))


def _v2_tag(mac_key, vault, ct):
    header = _canonical({k: vault[k] for k in V2_HEADER})
    message = b"timelock-v2-mac" + len(header).to_bytes(8, "big") + header + ct
    return hmac.new(mac_key, message, hashlib.sha256).digest()


def _seal(vault, b, entries):
    """Encrypt `entries` into a v2 `vault` (adds nonce, ciphertext, tag, checksum)."""
    enc_key, mac_key = _v2_keys(b, vault)
    payload = json.dumps({"entries": entries}).encode("utf-8")
    payload += b" " * (-len(payload) % PAD_TO)
    nonce = secrets.token_bytes(16)
    ct = _xor(payload, hashlib.shake_256(b"timelock-v2-stream" + enc_key + nonce).digest(len(payload)))
    vault["nonce"] = nonce.hex()
    vault["ciphertext"] = ct.hex()
    vault["tag"] = _v2_tag(mac_key, vault, ct).hex()
    vault["checksum"] = checksum(vault)


def decrypt_entries(vault, b):
    """Open a vault with its puzzle answer b and return the list of secrets.
    Raises IntegrityError if b is wrong or the file was altered."""
    nonce, ct, tag = (bytes.fromhex(vault[k]) for k in ("nonce", "ciphertext", "tag"))
    if vault["version"] == 1:
        key = _v1_key(b)
        expected, seed = hmac.new(key, nonce + ct, hashlib.sha256).digest(), b"timelock-stream" + key + nonce
    else:
        enc_key, mac_key = _v2_keys(b, vault)
        expected, seed = _v2_tag(mac_key, vault, ct), b"timelock-v2-stream" + enc_key + nonce
    if not hmac.compare_digest(expected, tag):
        raise IntegrityError("integrity check failed (wrong answer or altered file)")
    payload = _xor(ct, hashlib.shake_256(seed).digest(len(ct)))
    return json.loads(payload.decode("utf-8"))["entries"]


# ---------------------------------------------------------------- files

def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def vault_problem(vault):
    """Describe what is wrong with a parsed vault, or return None if it looks fine."""
    if not isinstance(vault, dict):
        return "is not a vault file."
    version = vault.get("version")
    if not _is_int(version) or version not in READABLE_VERSIONS:
        if _is_int(version) and version > max(READABLE_VERSIONS):
            return f"was made by a newer Timelock (vault format {version}). Update Timelock to open it."
        return "is not a vault file (unknown format)."
    try:
        n = int(vault["n"], 16)
        t, base = vault["t"], vault["base"]
        ok = (n > 3 and n % 2 == 1
              and _is_int(t) and t >= 1 and _is_int(base) and 1 < base < n
              and len(bytes.fromhex(vault["nonce"])) == 16
              and len(bytes.fromhex(vault["tag"])) == 32
              and len(bytes.fromhex(vault["ciphertext"])) > 0
              and isinstance(vault["labels"], list) and all(isinstance(s, str) for s in vault["labels"])
              and (version == 1 or isinstance(vault["note"], str)))
    except (KeyError, TypeError, ValueError, AttributeError):
        ok = False
    if not ok:
        return "is damaged (missing or malformed fields). Use your backup copy."
    if version >= 2 and vault.get("checksum") != checksum(vault):
        return "is damaged (its checksum doesn't match, so it was changed or corrupted). Use your backup copy."
    return None


def load_vault(path):
    try:
        with open(path, encoding="utf-8") as f:
            vault = json.load(f)
    except FileNotFoundError:
        raise TimelockError(f"There is no vault file at {path}.") from None
    except (OSError, ValueError) as e:
        raise TimelockError(f"Can't read {path} as a vault ({e}). If it is damaged, use your backup copy.") from None
    problem = vault_problem(vault)
    if problem:
        raise TimelockError(f"{path} {problem}")
    return vault


def save_json_atomic(path, data, attempts=8):
    """Write JSON so that `path` always holds either the old or the new content.

    The temp file has a unique name, so two processes can't mix their writes, and
    the final rename is retried because Windows refuses it while another program
    (antivirus, cloud sync, a second Timelock window) has the file open."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(attempts):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == attempts - 1:
                    raise
                time.sleep(0.05 * 2 ** attempt)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def move_aside(path, tag):
    """Rename `path` out of the way (never delete anything) and return the new name."""
    root, ext = os.path.splitext(path)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    candidate, k = f"{root}.{tag}-{stamp}{ext}", 1
    while os.path.exists(candidate):
        k += 1
        candidate = f"{root}.{tag}-{stamp}-{k}{ext}"
    os.replace(path, candidate)
    return candidate


def progress_path(vault_path):
    return str(vault_path) + ".progress"


def _progress_check(n_hex, i, x_hex):
    return hashlib.sha256(f"timelock-progress|{n_hex}|{i}|{x_hex}".encode()).hexdigest()


def write_progress(pp, vault, i, x):
    x_hex = hex(int(x))
    save_json_atomic(pp, {"n": vault["n"], "i": i, "x": x_hex, "check": _progress_check(vault["n"], i, x_hex)})


def read_progress(pp, vault):
    """Return (i, x) from a progress file, or (0, None) if there is none.

    Progress files from before the "check" field existed are still accepted."""
    if not os.path.exists(pp):
        return 0, None
    damaged = ProgressError(f"The progress file {pp} is damaged. If you have a copy of it, put it back; "
                            "otherwise rename or delete it and unlock again to start over from 0%.")
    try:
        with open(pp, encoding="utf-8") as f:
            p = json.load(f)
        n_hex, i, x_hex = p["n"], p["i"], p["x"]
        n, x = int(vault["n"], 16), int(x_hex, 16)
        same_vault = int(n_hex, 16) == n
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise damaged from None
    if not same_vault:
        raise ProgressMismatch(f"The progress file {pp} belongs to a different vault.")
    if "check" in p and p["check"] != _progress_check(n_hex, i, x_hex):
        raise damaged
    if not (_is_int(i) and 0 <= i <= vault["t"] and 0 < x < n) or (i == 0 and x != vault["base"]):
        raise damaged
    return i, x


def vault_state(path, vault):
    """(squarings done, problem description or "") for display."""
    try:
        return read_progress(progress_path(path), vault)[0], ""
    except ProgressMismatch:
        return 0, "a progress file from a different vault will be ignored"
    except ProgressError:
        return 0, "the progress file is damaged"


# ---------------------------------------------------------------- create / solve

def create_vault(path, entries, hours, rate, note="", bits=None):
    """Lock `entries` ([{"label": ..., "secret": ...}, ...]) into a new vault file at
    `path`, so that opening it takes about `hours` at `rate` squarings per second.
    Never overwrites an existing file. Returns the vault."""
    bits = bits or MODULUS_BITS
    if not (isinstance(hours, (int, float)) and math.isfinite(hours) and hours > 0):
        raise TimelockError("The unlock time must be a positive number of hours.")
    if not entries:
        raise TimelockError("Nothing to lock.")
    if os.path.exists(path):
        raise TimelockError(f"{path} already exists, and Timelock never overwrites a vault.")
    t = max(1, int(rate * hours * 3600))

    p = random_prime(bits // 2)
    q = random_prime(bits // 2)
    while q == p:
        q = random_prime(bits // 2)
    n, phi = p * q, (p - 1) * (q - 1)
    # Check the shortcut against plain squaring on a small case first: a wrong phi
    # (e.g. a "prime" that wasn't) would make the vault impossible to open.
    if pow(2, pow(2, 1000, phi), n) != square_chain(to_num(2), 1000, to_num(n)):
        raise TimelockError("Internal self-check failed, so nothing was written. Please report this.")
    # The shortcut only the creator has: reduce the exponent 2^t modulo phi(n).
    b = pow(2, pow(2, t, phi), n)
    del p, q, phi  # drops our references; Python can't actually wipe memory

    vault = {
        "version": FORMAT_VERSION,
        "n": hex(n),
        "t": t,
        "base": 2,
        "labels": [e["label"] for e in entries],
        "note": note,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "calibrated_rate": rate,
        "calibrated_hours": hours,
        "calibrated_with_gmpy2": HAVE_GMPY2,
    }
    _seal(vault, b, entries)
    stale = progress_path(path)
    if os.path.exists(stale):
        move_aside(stale, "stale")
    save_json_atomic(path, vault)
    # Read it back from disk and open it before telling anyone it worked.
    if decrypt_entries(load_vault(path), b) != entries:
        raise TimelockError("The new vault didn't verify after saving. Don't rely on it; please report this.")
    return vault


UNLOCK_FAILED = (
    "Unlock failed: the computed answer doesn't match this vault's integrity check, so the\n"
    "progress file or the vault file was damaged or edited. Try, in order:\n"
    "  1. Restore the vault file from a backup and unlock again (progress is reused).\n"
    "  2. Rename '{pp}' and unlock again to start over from 0%."
)


def solve_vault(path, start_over=False):
    """Run or resume the puzzle for the vault at `path`.

    Returns the list of secrets, or None if paused (Ctrl+C, Ctrl+Break, closing
    the terminal, SIGTERM). Progress is saved every CHECKPOINT_SECONDS and on
    pause. With start_over, a damaged progress file is moved aside instead of
    stopping with an error."""
    vault = load_vault(path)
    n, t = to_num(int(vault["n"], 16)), vault["t"]
    rate = vault.get("calibrated_rate") or 0
    pp = progress_path(path)
    try:
        i, x = read_progress(pp, vault)
    except ProgressMismatch:
        print(f"Moved aside a progress file that belongs to a different vault: {move_aside(pp, 'other')}")
        i, x = 0, None
    except ProgressError:
        if not start_over:
            raise
        print(f"Kept the damaged progress file as {move_aside(pp, 'damaged')}")
        i, x = 0, None

    if x is None:
        x = vault["base"]
        if vault.get("note"):
            print(f"\nNote from past you: {vault['note']}\n")
        print(f"Unlocking: {', '.join(vault['labels'])}")
        if rate:
            print(f"Estimated: ~{fmt_duration(t / rate)} of computing at the calibrated speed.")
        print("Press Ctrl+C to pause anytime; progress is saved.\n")
    else:
        print(f"Resuming from {100 * i / t:.2f}%")
    if not HAVE_GMPY2 and vault.get("calibrated_with_gmpy2"):
        print("(gmpy2 isn't installed here, so this will take several times longer than estimated.)")

    stop = SimpleNamespace(requested=False, saved=threading.Event())
    restore = _install_stop_handlers(stop)
    release = _hold_console_close(stop)
    try:
        i, x = _run(pp, vault, n, t, i, to_num(x), stop)
    finally:
        stop.saved.set()
        release()
        restore()
    if i < t:
        return None
    try:
        return decrypt_entries(vault, x)
    except IntegrityError:
        raise TimelockError(UNLOCK_FAILED.format(pp=pp)) from None


def _run(pp, vault, n, t, i, x, stop):
    last_save = start = time.monotonic()
    start_i = i
    while i < t:
        steps = min(CHUNK, t - i)
        # A pause request only sets a flag (see _install_stop_handlers), so x and i
        # always advance together and every checkpoint is consistent.
        x, i = square_chain(x, steps, n), i + steps
        now = time.monotonic()
        if stop.requested and i < t:
            saved = _checkpoint(pp, vault, i, x)
            stop.saved.set()  # a closing console window may be waiting for this
            if saved:
                print(f"\nPaused at {100 * i / t:.2f}%. Unlock again to resume.")
            break
        if now - last_save >= CHECKPOINT_SECONDS or i == t:
            if _checkpoint(pp, vault, i, x):
                last_save = now
            speed = (i - start_i) / (now - start) if now > start else 0
            eta = fmt_duration((t - i) / speed) if speed else "?"
            print(f"\r{100 * i / t:6.2f}%   {i:,}/{t:,}   ETA {eta}        ", end="", flush=True)
    if i == t:
        print("\n")
    return i, x


def _checkpoint(pp, vault, i, x):
    try:
        write_progress(pp, vault, i, x)
        return True
    except OSError as e:
        print(f"\n(Couldn't save progress: {e}. Will try again.)")
        return False


def _install_stop_handlers(stop):
    """Make Ctrl+C, Ctrl+Break, closing the terminal (SIGHUP) and SIGTERM request a
    pause instead of killing the process. Returns a function that undoes this."""
    def request_stop(signum, frame):
        stop.requested = True

    previous = {}
    for name in STOP_SIGNALS:
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            previous[sig] = signal.signal(sig, request_stop)
        except (ValueError, OSError):  # not the main thread, or not supported here
            pass

    def restore():
        for sig, handler in previous.items():
            if handler is not None:
                signal.signal(sig, handler)
    return restore


def _hold_console_close(stop):
    """Windows only. Closing the console window (or logging off) ends the process as
    soon as its console handlers return, before Python ever acts on the SIGBREAK it
    is sent, so the last checkpoint would be all that's kept. This handler requests
    a pause and holds the close until the solve loop has saved (Windows allows about
    5 seconds). Returns a function that removes it."""
    if os.name != "nt":
        return lambda: None
    import ctypes
    from ctypes import wintypes

    close_events = (2, 5, 6)  # CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT
    handler_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetConsoleCtrlHandler.argtypes = [handler_type, wintypes.BOOL]

    @handler_type
    def on_console_event(event):  # runs on a thread Windows creates
        if event in close_events:
            stop.requested = True
            stop.saved.wait(4.0)
        return False  # then let Python's own handler run as usual (Ctrl+C, Ctrl+Break)

    if not kernel32.SetConsoleCtrlHandler(on_console_event, True):
        return lambda: None
    return lambda: kernel32.SetConsoleCtrlHandler(on_console_event, False)  # also keeps the callback alive


# ---------------------------------------------------------------- shared UI

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


def make_password(groups=4):
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(groups))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


GMPY2_WARNING = """\
WARNING: the speed library gmpy2 is not installed.
  The lock is calibrated to how fast this computer runs Timelock right now.
  With gmpy2 the same computer is typically 5-10x faster (8x when we
  measured it), so a vault made now for 48 hours could be opened in roughly
  5-10 hours just by installing gmpy2. Install it first (menu option 6, or
  `pip install gmpy2`)."""


def confirm_without_gmpy2():
    print(GMPY2_WARNING)
    return input("Create the vault anyway, without gmpy2? [y/N] ").strip().lower() == "y"


def ask_secrets():
    """Ask for labelled secrets (hidden input) and an optional note."""
    print("\nEnter the secrets to lock. Input is hidden.")
    print("Leave the label empty when you're done.\n")
    entries = []
    while True:
        label = input(f"Label for secret #{len(entries) + 1} (e.g. 'Apple ID password'): ").strip()
        if not label:
            break
        value = getpass.getpass("  Secret (hidden): ")
        if not value:
            print("  Empty secret skipped.")
            continue
        if getpass.getpass("  Repeat secret:   ") != value:
            print("  Didn't match, try that one again.")
            continue
        entries.append({"label": label, "secret": value})
    note = ""
    if entries:
        note = input("Optional note shown before unlocking (e.g. 'Are you sure?'): ").strip()
    return entries, note


def measure_speed():
    print("\nMeasuring this computer's speed (~6 s). For an accurate lock, keep it")
    print("plugged in and close heavy programs while this runs.")
    rate = calibrate()
    print(f"  {rate:,.0f} squarings/sec")
    return rate


def report_created(path, vault, rate):
    t = vault["t"]
    print(f"\nLocked {len(vault['labels'])} secret(s) into {path}")
    print(f"t = {t:,} squarings: about {fmt_duration(t / rate)} of computing on this machine.")
    print("A faster computer can open it sooner (see the README for rough numbers).")
    print("The shortcut has been discarded. If you lose this file, you lose these secrets.")


def show_secrets(path, entries):
    for entry in entries:
        print(f"{entry['label']}: {entry['secret']}")
    print(f"\nThis vault is now spent: {progress_path(path)} holds the answer,")
    print("so anyone with both files can read these secrets instantly.")
    print("To lock things up again: change the password(s), create a NEW vault, then")
    print("delete this vault and its .progress file.")


# ---------------------------------------------------------------- commands

def cmd_genpass(args):
    print(make_password(args.groups))
    return 0


def cmd_bench(args):
    print(f"gmpy2: {'yes' if HAVE_GMPY2 else 'NO (pip install gmpy2 for the fast path)'}")
    print("Measuring for ~6 seconds...")
    rate = calibrate()
    print(f"{rate:,.0f} squarings/sec")
    print(f"A 48-hour lock = {int(rate * 48 * 3600):,} squarings on this machine")
    return 0


def cmd_create(args):
    path = args.vault
    if os.path.exists(path) and not args.force:
        raise TimelockError(f"{path} already exists. Pick another name, or add --force to keep the "
                            "old vault as a backup copy and create a new one in its place.")
    if not HAVE_GMPY2 and not confirm_without_gmpy2():
        print("Cancelled. Nothing was created.")
        return 1
    entries, note = ask_secrets()
    if not entries:
        raise TimelockError("Nothing to lock.")
    rate = measure_speed()
    if os.path.exists(path):  # --force: keep the old vault (and its progress) under a new name
        backup = move_aside(path, "bak")
        if os.path.exists(progress_path(path)):
            os.replace(progress_path(path), progress_path(backup))
        print(f"Kept the old vault as {backup}")
    print(f"Generating a {MODULUS_BITS}-bit modulus...")
    vault = create_vault(path, entries, args.hours, rate, note)
    report_created(path, vault, rate)
    print("Back it up now (e.g. USB drive + cloud).")
    return 0


def cmd_status(args):
    vault = load_vault(args.vault)
    t = vault["t"]
    done, problem = vault_state(args.vault, vault)
    rate = vault.get("calibrated_rate") or 0
    print(f"Vault:    {args.vault}  (created {vault.get('created', '?')}, format v{vault['version']})")
    print(f"Contains: {', '.join(vault['labels'])}")
    print(f"Progress: {done:,} / {t:,}  ({100 * done / t:.2f}%)" + (f"  [{problem}]" if problem else ""))
    if done >= t:
        print("State:    UNLOCKED. The progress file holds the answer: anyone with both files")
        print("          can read the secrets instantly.")
    elif rate:
        print(f"Left:     ~{fmt_duration((t - done) / rate)} at the calibrated speed")
    return 0


def cmd_solve(args):
    entries = solve_vault(args.vault)
    if entries is not None:
        show_secrets(args.vault, entries)
    return 0


# ---------------------------------------------------------------- menu

HOUR_PRESETS = [("24 hours", 24), ("48 hours (recommended)", 48), ("72 hours", 72), ("1 week", 168)]


def vault_dir():
    """Where the menu keeps vaults: next to timelock.py when it was downloaded as a
    single file, or the current folder when Timelock was installed with pip."""
    here = os.path.dirname(os.path.abspath(__file__))
    parts = set(here.replace("\\", "/").lower().split("/"))
    return os.getcwd() if parts & {"site-packages", "dist-packages"} else here


def _ansi():
    if os.name == "nt":
        os.system("")  # turns on color support in Windows terminals


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def bold(text):
    return f"\033[1m{text}\033[0m"


def dim(text):
    return f"\033[2m{text}\033[0m"


def yellow(text):
    return f"\033[33m{text}\033[0m"


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
    """Put `text` on the clipboard ("" empties it). Returns True on success.

    On Windows the text is marked so clipboard history (Win+V) and cloud clipboard
    sync skip it. macOS and Linux have no standard way to ask that, so clipboard
    managers or Universal Clipboard may still see it (see the README)."""
    if os.name == "nt":
        try:
            _windows_set_clipboard(text)
            return True
        except OSError:
            return False
    return _copy_with_commands(text, _clipboard_commands(sys.platform, os.environ))


def clear_clipboard():
    return copy_to_clipboard("")


def _clipboard_commands(platform, environ):
    """Clipboard programs to try, in order, on macOS and Linux."""
    if platform == "darwin":
        return [["pbcopy"]]
    wayland = [["wl-copy"]] if environ.get("WAYLAND_DISPLAY") else []
    return wayland + [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]


def _copy_with_commands(text, commands):
    for command in commands:
        try:  # xclip/xsel/wl-copy stay in the background to serve the clipboard: don't wait on their output
            subprocess.run(command, input=text.encode("utf-8"), check=True, timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def _windows_set_clipboard(text):
    """Set (or with "" empty) the Windows clipboard via the Win32 API, marked so that
    clipboard history and cloud clipboard ignore it. Raises OSError on failure."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                       ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                       wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]

    def check(result):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def put(fmt, data):
        handle = check(kernel32.GlobalAlloc(0x0002, len(data)))  # GMEM_MOVEABLE
        ctypes.memmove(check(kernel32.GlobalLock(handle)), data, len(data))
        kernel32.GlobalUnlock(handle)
        if not user32.SetClipboardData(fmt, handle):  # on success Windows owns the memory
            kernel32.GlobalFree(handle)
            check(0)

    # Windows wants a window to own the clipboard; a hidden one is enough.
    hwnd = check(user32.CreateWindowExW(0, "STATIC", None, 0, 0, 0, 0, 0, None, None, None, None))
    try:
        for _ in range(50):  # another program may have the clipboard open for a moment
            if user32.OpenClipboard(hwnd):
                break
            time.sleep(0.02)
        else:
            check(0)
        try:
            check(user32.EmptyClipboard())
            if text:
                put(13, (text + "\0").encode("utf-16-le"))  # CF_UNICODETEXT
                for name in ("ExcludeClipboardContentFromMonitorProcessing",
                             "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
                    put(check(user32.RegisterClipboardFormatW(name)), b"\0\0\0\0")  # DWORD 0 = "no"
        finally:
            user32.CloseClipboard()
    finally:
        user32.DestroyWindow(hwnd)


def find_vaults():
    found = []
    for folder in dict.fromkeys([vault_dir(), os.getcwd()]):
        try:
            names = sorted(os.listdir(folder))
        except OSError:
            continue
        found += [os.path.join(folder, name) for name in names if name.endswith(".tlp")]
    return found


def describe_vault(path):
    try:
        vault = load_vault(path)
    except TimelockError:
        return f"{os.path.basename(path)}  {dim('(unreadable)')}"
    done, _ = vault_state(path, vault)
    t = vault["t"]
    state = "unlocked" if done >= t else f"{100 * done / t:.0f}% done" if done else "locked"
    return f"{os.path.basename(path)}  {dim('(' + ', '.join(vault['labels']) + ' - ' + state + ')')}"


def pick_vault():
    vaults = find_vaults()
    if not vaults:
        print(f"No vault files (.tlp) found in:\n  {vault_dir()}")
        print("Put your vault file in the same folder as timelock.py.")
        return None
    if len(vaults) == 1:
        return vaults[0]
    idx = ask_choice("Which vault?", [describe_vault(p) for p in vaults])
    return None if idx is None else vaults[idx]


def ask_vault_name(folder):
    """Ask for a new vault file name that doesn't exist yet. Returns the name."""
    while True:
        raw = input(f"\nVault name {dim('[vault]')}: ").strip() or "vault"
        name = raw if raw.lower().endswith(".tlp") else raw + ".tlp"
        if os.path.basename(name) != name or name.startswith(".") or any(
                c in '<>:"/\\|?*' or ord(c) < 32 for c in name):
            print("  Use a plain name made of letters, numbers, spaces or dashes.")
            continue
        if not os.path.exists(os.path.join(folder, name)):
            return name
        stem, k = name[:-4], 2
        while os.path.exists(os.path.join(folder, f"{stem}-{k}.tlp")):
            k += 1
        print(f"  There's already a vault called {name}, and Timelock never overwrites vaults.")
        print(f"  Pick another name, for example {stem}-{k}.")


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
    if not HAVE_GMPY2 and not confirm_without_gmpy2():
        print("\nNothing was created.")
        pause()
        return
    print("How long should unlocking take on this computer?\n")
    idx = ask_choice("Pick a length:", [label for label, _ in HOUR_PRESETS] + ["Custom"])
    if idx is None:
        return
    if idx == len(HOUR_PRESETS):
        try:
            hours = float(input("Hours: ").strip())
        except ValueError:
            hours = float("nan")
        if not (math.isfinite(hours) and hours > 0):
            print("That's not a number of hours.")
            pause()
            return
    else:
        hours = HOUR_PRESETS[idx][1]

    folder = vault_dir()
    path = os.path.join(folder, ask_vault_name(folder))
    print(dim("\nTip: to paste a hidden secret, use Ctrl+V (Windows) or Cmd+V (Mac), then Enter."))
    print(dim("Nothing appears on screen while you type or paste. That's normal."))
    entries, note = ask_secrets()
    if not entries:
        print("\nNothing to lock, so no vault was created.")
        pause()
        return
    rate = measure_speed()
    print(f"Generating a {MODULUS_BITS}-bit modulus...")
    vault = create_vault(path, entries, hours, rate, note)
    report_created(path, vault, rate)
    # Only now: if creating failed, the generated password must stay on the clipboard.
    if clear_clipboard():
        print("\nClipboard cleared.")
    print(f"\nYour vault: {path}")
    print(bold("Back it up now") + " (e.g. USB drive + cloud). Lose it = lose those secrets.")
    pause()


def menu_solve():
    clear()
    print(bold("Unlock a vault\n"))
    path = pick_vault()
    if not path:
        pause()
        return
    try:
        entries = solve_vault(path)
    except ProgressError as e:
        print(e)
        if input("\nStart over from 0%? The damaged file is kept, not deleted. [y/N] ").strip().lower() != "y":
            pause()
            return
        entries = solve_vault(path, start_over=True)
    if entries is not None:
        show_secrets(path, entries)
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
    print(dim("\nRun this on each computer you own. Create your vault on the fastest one."))
    pause()


def _activate_gmpy2():
    """Start using gmpy2 right after installing it, without restarting."""
    global gmpy2, HAVE_GMPY2
    importlib.invalidate_caches()
    try:
        site.addsitedir(site.getusersitepackages())  # may not have existed at startup
    except Exception:
        pass
    try:
        gmpy2 = importlib.import_module("gmpy2")
    except ImportError:
        return False
    HAVE_GMPY2 = True
    return True


def menu_install_gmpy2():
    clear()
    print(bold("Install the speed library (gmpy2)\n"))
    print("Installing from PyPI... this can take a minute.\n")
    command = [sys.executable, "-m", "pip", "install", "gmpy2"]
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    ok = (not in_venv and subprocess.run(command + ["--user"]).returncode == 0) \
        or subprocess.run(command).returncode == 0
    if ok and _activate_gmpy2():
        print("\nInstalled and ready.")
    elif ok:
        print("\nInstalled. Close this window and open Timelock again to use it.")
    else:
        print("\nInstall failed. In a terminal, run:  python3 -m pip install --user gmpy2")
    pause()


def run_menu_action(action):
    try:
        action()
    except KeyboardInterrupt:
        print("\nCancelled.")
        time.sleep(0.8)
    except EOFError:
        raise
    except TimelockError as e:
        print(f"\n{e}")
        pause()
    except Exception:
        traceback.print_exc()
        print("\nSomething went wrong (details above). Please report it: see the README.")
        pause()


def menu():
    _ansi()
    while True:
        clear()
        print(bold("=== Timelock Vault ===") + "   lock passwords behind hours of computing\n")
        if not HAVE_GMPY2:
            print(yellow("! Speed library not installed. Install it (option 6) BEFORE creating a vault.") + "\n")
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
            run_menu_action(options[int(raw) - 1][1])


# ---------------------------------------------------------------- main

def positive_hours(text):
    try:
        hours = float(text)
    except ValueError:
        hours = float("nan")
    if not (math.isfinite(hours) and hours > 0):
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive number of hours")
    return hours


def positive_int(text):
    if not text.isdigit() or int(text) < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive whole number")
    return int(text)


def build_parser():
    ap = argparse.ArgumentParser(prog="timelock",
                                 description="Time-lock puzzle vault. Run with no arguments for a menu.")
    ap.add_argument("--version", action="version", version=f"timelock {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genpass", help="print a strong random password")
    g.add_argument("--groups", type=positive_int, default=4, help="5-character groups (default 4)")
    g.set_defaults(func=cmd_genpass)

    b = sub.add_parser("bench", help="measure squarings/sec")
    b.set_defaults(func=cmd_bench)

    c = sub.add_parser("create", help="lock secrets into a vault file")
    c.add_argument("vault")
    c.add_argument("--hours", type=positive_hours, required=True, help="unlock time on this machine")
    c.add_argument("--force", action="store_true",
                   help="if the vault exists, keep it as a .bak-<date>.tlp copy and create a new one")
    c.set_defaults(func=cmd_create)

    s = sub.add_parser("solve", help="unlock a vault (resumable)")
    s.add_argument("vault")
    s.set_defaults(func=cmd_solve)

    st = sub.add_parser("status", help="show unlock progress")
    st.add_argument("vault")
    st.set_defaults(func=cmd_status)
    return ap


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    for stream in (sys.stdout, sys.stderr):
        try:  # never crash at the very end of a long solve over an unprintable character
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    if not argv:
        try:
            menu()
        except (KeyboardInterrupt, EOFError):
            print()
        return 0
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TimelockError as e:
        print(f"timelock: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
