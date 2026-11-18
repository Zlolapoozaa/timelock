# Security policy

## Reporting a problem

Please report security problems **privately** through GitHub:
**[Report a vulnerability](https://github.com/Zlolapoozaa/timelock/security/advisories/new)**
(the repository's *Security* tab → *Report a vulnerability*).

Please don't open a public issue for these, and never attach a real vault,
progress file or password. A minimal script that reproduces the problem with a
throwaway vault is ideal.

This is a personal project maintained in spare time. Expect an acknowledgement
within about a week. Fixes are best effort. Once a fix is released, you'll be
credited in the advisory unless you'd rather not be.

## What counts

Examples of what we want to hear about:

- reading a vault's secrets without doing (close to) the *t* squarings it was
  calibrated for, through a flaw in this code or its use of the cryptography,
- changing a vault without the MAC noticing,
- secrets, the puzzle answer, the primes or φ(n) ending up on disk or in output
  where they shouldn't,
- a crash or bug that could destroy a vault or make it impossible to open.

These are known limitations, not vulnerabilities (see the
[threat model](README.md#threat-model-and-limitations)):

- a faster computer, better code or special hardware opening a vault sooner,
- getting the secret some other way, such as account recovery,
- secrets lingering in memory, swap or hibernation files while a vault is being
  created,
- a finished `.progress` file letting anyone open its vault instantly.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | yes |
| older, unreleased versions | no, but their vaults (format 1) keep opening in 1.x |
