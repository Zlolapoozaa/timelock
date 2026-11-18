# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

The app version and the vault format version are separate numbers: Timelock
1.0.0 writes vault format 2 and still reads format 1.

## [1.0.0] - 2026-11-17

First public release.

### Added
- Installable package: `pip install`, a `timelock` command and `python -m timelock`.
  The single-file `timelock.py` with `Timelock.bat` / `Timelock.command` still works
  on its own.
- Vault format 2, standard library only: separate HKDF-SHA256 encryption and MAC
  keys, a MAC that also covers the header (labels, note, n, t…), padding that hides
  secret lengths, and a checksum that catches a damaged file before a long unlock.
- On Windows, closing the console window while unlocking now saves progress first.
- On Windows, generated passwords skip clipboard history (Win+V) and cloud
  clipboard. On Linux, `wl-copy` and `xsel` are tried as well as `xclip`.
- The menu shows each vault's state (locked, % done, unlocked).
- `--version`.
- Test suite (pytest) and CI on Windows, macOS and Linux, plus README, security
  policy and contributing guide.

### Changed
- Unlocking and calibration compute each chunk as one modular exponentiation
  instead of a Python loop. This is about 1.2× faster with gmpy2, so **vaults made
  by earlier versions open about 16% sooner** (a 48-hour vault in about 40 hours on
  the machine that made it). The lock is now calibrated to the fastest path this
  program has.
- Calibration takes the best of three runs.
- Progress is saved every 10 seconds instead of every 30.
- Moduli are exactly 2048 bits (previously 2047 or 2048).
- Clearer gmpy2 warning, with measured numbers.

### Fixed
- Vaults could be overwritten from the menu or with `--force`. Now the menu
  never overwrites, and `--force` keeps the old vault and its progress as a
  `.bak-<date>.tlp` copy.
- A damaged or truncated progress file crashed the program or was used for a
  whole unlock. Progress files now carry a checksum and are checked before any
  work. Old progress files without a checksum still resume.
- A progress file from another vault was ignored without a word by `solve`,
  and `status` reported it as this vault's progress.
- On Windows, a progress save could crash the unlock while another program
  (antivirus, cloud sync, a second window) had the file open. Saves now retry,
  and a failed save no longer stops the unlock.
- Two processes writing the same progress file could mix their writes. Each
  save now uses its own temporary file.
- Declining the gmpy2 warning in the menu still printed "Your vault: …".
- "Install gmpy2" failed to restart on Windows when a path contained spaces. It
  now activates gmpy2 without restarting.
- `--hours` accepted zero, negative or non-finite values (zero or less gave a
  vault that opened instantly).
- An unexpected error in the menu closed the window before it could be read,
  and `Timelock.bat` started Python a second time after any error.
- A non-ASCII secret printed to a redirected output could crash the program at
  the very end of an unlock.
- Creating a vault now checks the shortcut against plain squaring, and re-reads
  and opens the saved file before reporting success.

### Compatibility
- Vaults (format 1) and progress files made by earlier versions still open. The
  test suite keeps a frozen copy of that code and checks this on every run.

[1.0.0]: https://github.com/Zlolapoozaa/timelock/releases/tag/v1.0.0
