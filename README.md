# Timelock

Lock a secret behind hours of computing that can't be skipped, so you can always
get it back, just not on impulse.

Timelock encrypts secrets such as passwords into a vault file. Opening the vault
means running a calculation that takes, say, 48 hours on your computer. Nobody
can make it go faster by adding cores, GPUs or cloud machines, and that includes
you. It's a [time-lock puzzle](#prior-art-and-credits) (Rivest, Shamir and
Wagner, 1996) packaged as a small, single-file Python tool with a numbered menu.

> **Read [Threat model and limitations](#threat-model-and-limitations) before you
> rely on it.** If you lose the vault file, you lose the secret. A faster computer
> opens it sooner. The code has not been audited.

## Why

Willpower is weakest in the moment. A password you could look up in ten seconds
doesn't protect you from yourself, and a password you threw away can't be
recovered when you really need it. Timelock sits in between: the secret is always
recoverable, but only after a delay you chose while thinking clearly. The impulse
passes long before the vault opens.

Typical uses:

- the recovery password behind an iPhone **Screen Time** passcode ([guide below](#example-iphone-screen-time-passcode)),
- passwords for social media, games or shopping accounts you want to use less,
- anything you want to keep, but don't want to reach in a weak moment.

## How it works

1. **The puzzle.** Start with the number 2. Square it and take the remainder
   after dividing by a big number *n*. Do that again with the result, and again,
   *t* times. Each step needs the result of the one before, so the work can't be
   split across cores or machines. A computer can only do it as fast as one core
   can go.
2. **The creator's shortcut.** *n* is the product of two secret prime numbers
   (1024 bits each). Knowing those primes, the creator can use a little number
   theory (Euler's theorem) to compute the final result instantly. Timelock does
   that while creating the vault, then forgets the primes.
3. **Locking.** The final result becomes the key that encrypts your secrets. The
   vault file stores *n*, *t* and the encrypted secrets, but never the primes,
   the result or the key.
4. **Calibration.** Before locking, Timelock measures how many squarings per
   second this computer does and sets *t = speed × hours*.
5. **Unlocking.** Timelock does the *t* squarings, saving progress every 10
   seconds. You can pause (Ctrl+C, or close the window) and continue later, even
   on another computer, by bringing the `.progress` file along.

Opening a vault without doing the work would mean factoring a 2048-bit number,
which is far out of reach, or finding a faster way to do repeated squaring
without the factors, which nobody knows how to do.

## Install

You need Python 3.9 or newer. Nothing else is required.
[gmpy2](https://pypi.org/project/gmpy2/) is an optional speed library, but you
should install it **before creating a vault** (see [why](#threat-model-and-limitations)).

### Download and double-click (no install)

1. Install Python if you don't have it:
   - **Windows:** get it from [python.org](https://www.python.org/downloads/) and tick
     **"Add python.exe to PATH"** during setup.
   - **macOS:** get it from [python.org](https://www.python.org/downloads/), or use the
     built-in `python3` (macOS offers to install it the first time).
   - **Linux:** usually already installed (`python3`).
2. Download `timelock-1.0.0-standalone.zip` from the
   [latest release](https://github.com/Zlolapoozaa/timelock/releases/latest) and unzip
   it into a folder of its own. Your vaults will be kept in that folder.
3. Open it:
   - **Windows:** double-click `Timelock.bat`. If Windows warns about a downloaded
     file, choose *More info → Run anyway* (or *Run*).
   - **macOS:** double-click `Timelock.command`. The first time, macOS may block it.
     If so, open *System Settings → Privacy & Security* and click *Open Anyway*
     (on older macOS: right-click the file → *Open*).
   - **Linux:** run `python3 timelock.py` in that folder.
4. In the menu, pick **Install speed library (gmpy2)** if it is offered.

### With pip

```sh
python -m pip install "timelock-vault[fast] @ git+https://github.com/Zlolapoozaa/timelock@v1.0.0"
timelock            # the menu
python -m timelock  # same thing
```

The `[fast]` extra installs gmpy2. When Timelock is installed this way, the menu
keeps vaults in the folder you run it from.

## Quick start (menu)

Run Timelock with no arguments, or double-click it. You get a numbered menu:

```
=== Timelock Vault ===   lock passwords behind hours of computing

  1  Generate a password
  2  Create a vault
  3  Unlock a vault
  4  Check unlock progress
  5  Test this computer's speed
  0  Quit
```

1. **Test your computers (5).** Run this on each computer you own. Create vaults
   on the fastest one, plugged in, so the lock holds even on your best hardware.
2. **Generate a password (1).** A strong random password is copied to your
   clipboard. It isn't shown, so you don't memorize it. Paste it as the new
   password of the account you want to lock away.
3. **Create a vault (2).** Choose how long unlocking should take (48 hours is a
   good start), give the vault a name, then paste the same password as the secret
   (it stays hidden while you type or paste) and give it a label. You can add a
   note for your future self. The clipboard is cleared afterwards.
4. **Back up the `.tlp` file**, for example to a USB stick and to cloud storage.
   That file is now the only copy of the password.
5. **To get the password back, choose Unlock a vault (3)** and leave the computer
   running. Press Ctrl+C or close the window to pause, then choose Unlock again
   to continue where you left off. **Check unlock progress (4)** shows how far
   along it is.
6. **After unlocking:** change the password, create a new vault, then delete the
   old vault and its `.progress` file.

## Command line

```sh
timelock genpass                        # print a strong random password
timelock create vault.tlp --hours 48    # lock secrets (asks for them, hidden)
timelock solve vault.tlp                # unlock: resumable, Ctrl+C pauses
timelock status vault.tlp               # progress, without solving
timelock bench                          # squarings per second on this machine
```

If you downloaded the single file, use `python timelock.py ...` (or `python3`)
in place of `timelock`. `create` never overwrites a vault. `create --force` keeps
the old vault and its progress as `name.bak-<date>.tlp` before writing the new
one.

## Example: iPhone Screen Time passcode

The goal is a Screen Time passcode you don't know, which you can still reset
after a deliberate 48-hour wait. Apple renames these menus from time to time, so
check Apple's support article *"If you forgot your Screen Time passcode"* for
the current wording.

1. **Create a second Apple Account** that you use only for this. Don't sign in
   to it on any of your devices.
2. **Set a Screen Time passcode you don't know.** On the iPhone, go to
   *Settings → Screen Time → Lock Screen Time Settings* (or *Use Screen Time
   Passcode*). Ideally have someone else type the passcode. Four digits you chose
   yourself are easy to remember.
3. **Use the second account for passcode recovery.** When iOS asks for an Apple
   Account for *Screen Time Passcode Recovery*, sign in with the second account,
   not your main one.
4. **Give the second account a password you've never seen.** In Timelock choose
   *Generate a password (1)*. On [account.apple.com](https://account.apple.com),
   change the second account's password by pasting it in. Then, straight away,
   choose *Create a vault (2)* and paste the same password as the secret.
5. **Close the side doors.** Anything that can reset the second account's
   password is a way around the vault: its trusted phone number, any trusted
   devices, a recovery contact, a recovery key. One option is to use the phone
   number of someone you trust. Check what Apple offers for that account and
   decide what you are comfortable with.
6. **Back up the vault file.**

To get back in: unlock the vault in Timelock and wait. Then, on the iPhone, go to
*Screen Time → Change Screen Time Passcode → Forgot Passcode?* and sign in with
the second account's password.

## Threat model and limitations

**What it does:** anyone who has the vault file, including you, has to spend
hours of computing before reading the secrets. Nothing more.

**What it doesn't do:**

- **It can't stop you from getting the secret another way.** The vault only
  guards its own copy. Account recovery (see step 5 above), a password saved in a
  browser or password manager, a note on paper, or another person who knows it
  are all ways around it.
- **A faster computer opens it sooner.** The lock is calibrated on the computer
  that creates it. Rough numbers, measured on an AMD Ryzen 7 5800X (2048-bit
  squarings: about 139,000 per second in pure Python and about 1,180,000 per
  second with gmpy2):

  | How the 48-hour vault (made on that PC with gmpy2) is opened | Rough speed | Opens in about |
  |---|---|---|
  | Same PC, Timelock with gmpy2 | 1× | 48 h |
  | Same PC, without gmpy2 | 0.12× | 17 days |
  | A top current desktop CPU | 1.3–2× | 24–37 h |
  | Custom FPGA hardware, as used on the LCS35 puzzle | ~10× or more | 5 h or less |

  **If you create a vault without gmpy2, installing gmpy2 later makes it open
  about 8× sooner:** a "48-hour" vault opens in about 6 hours. Timelock warns
  about this. For a real-world comparison, MIT's LCS35 puzzle was designed in
  1999 to take about 35 years. In 2019 one person solved it with about 3.5 years
  of computing on a single CPU core, and a team using FPGAs finished after about
  two months of computing
  ([LCS35](https://en.wikipedia.org/wiki/LCS35), [Rivest 2019](https://people.csail.mit.edu/rivest/pubs/Riv19f.pdf)).
  The FPGA route takes expertise and money, so it isn't an impulse purchase, but
  don't use Timelock against an adversary who has those.
- **If you lose the vault file, you lose the secret.** There is no recovery and
  no backdoor. Keep backups in more than one place. Losing a `.progress` file
  only loses progress.
- **A finished `.progress` file is the key.** Once a vault has been unlocked,
  anyone with the vault and its `.progress` file can read the secrets instantly.
  Delete both once you've changed the passwords.
- **Labels and the note are not secret.** They are stored in plain text so the
  menu can show them. Version 2 vaults authenticate them, so they can't be
  changed without detection, but anyone can read them.
- **Memory isn't wiped.** Python can't reliably erase memory. While a vault is
  being created, what you typed and the creator's shortcut may stay in RAM, in
  the swap or page file, or in a hibernation file until that memory is reused.
  Create vaults on a computer you trust.
- **Clipboard.** On Windows, passwords copied by Timelock are marked to skip
  clipboard history (Win+V) and cloud clipboard. A password you copy yourself
  with Ctrl+C is not protected that way. On macOS, Universal Clipboard can send
  the clipboard to your other Apple devices, including the iPhone you're
  locking, so turn Handoff off while you do this, or choose "show it" instead.
  On Linux, clipboard managers may keep a copy.
- **Sleep pauses the work.** The vault opens after hours of *computing*, not
  hours on the clock. A computer that sleeps, or a paused unlock, takes longer.
- **Not audited.** This is a small personal project. The cryptography uses
  well-known building blocks from Python's standard library (see below), but
  nobody has formally reviewed it. The whole program is one file, so please read
  it.
- **Quantum computers.** A large enough quantum computer could factor *n* and
  skip the work. None exists today.

## Files

| File | What it is |
|---|---|
| `name.tlp` | The vault. Keep it, and back it up. |
| `name.tlp.progress` | Unlock progress, saved every 10 seconds and when you pause. Once unlocking is finished, it contains the key. |
| `name.bak-<date>.tlp` | An old vault kept by `create --force`. |
| `*.damaged-*`, `*.other-*`, `*.stale-*` | Progress files Timelock moved aside instead of deleting them. |

Vaults are JSON. Format version 2 (written since 1.0.0) does the following:

- derives separate encryption and MAC keys from the puzzle answer with HKDF-SHA256;
- encrypts with a SHAKE-256 keystream;
- authenticates the header (n, t, labels, note…) together with the ciphertext
  using HMAC-SHA256 (encrypt-then-MAC);
- pads secrets so their length doesn't show;
- adds a checksum that catches accidental damage before a long unlock starts.

Version 1 vaults, made by earlier unreleased versions, still open. The exact
construction is documented at the top of the crypto section in `timelock.py`.

## Prior art and credits

- R. L. Rivest, A. Shamir and D. A. Wagner, *Time-lock puzzles and timed-release
  crypto*, MIT/LCS/TR-684, 1996. Timelock is a direct implementation of their
  repeated-squaring puzzle. All credit for the idea is theirs.
- R. L. Rivest, [LCS35](https://en.wikipedia.org/wiki/LCS35) (1999), the famous
  real-world instance of the same puzzle.
- [gmpy2](https://github.com/aleaxit/gmpy) / GMP for the fast arithmetic.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report security problems privately
as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Luca Pessoa
