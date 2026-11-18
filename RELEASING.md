# Releasing

Commands are for PowerShell on Windows, run from the repository folder with the
dev environment active (`.venv\Scripts\activate`). Most of them work unchanged
in bash.

## Checklist (every release)

- [ ] `__version__` in `timelock.py` is the new version, and `CHANGELOG.md` has
      its heading, date and link.
- [ ] Release notes are in `.github/release-notes/v<version>.md`.
- [ ] Tests and lint pass: `python -m pytest`, `ruff check .`
- [ ] Windows-only desktop tests pass. They touch the clipboard and open a
      console window:
      `$env:TIMELOCK_TEST_CLIPBOARD=1; $env:TIMELOCK_TEST_CONSOLE=1; python -m pytest tests/test_clipboard.py tests/test_signals.py -rs`
- [ ] Manual clipboard check: menu → *Generate a password*, then press Win+V.
      The password must **not** be in clipboard history.
- [ ] Your own real vaults still load: `python timelock.py status <your vault>.tlp`
      (this only reads them).
- [ ] No vaults or progress files are tracked: `git ls-files "*.tlp" "*.progress*"`
      prints nothing, and `git status --short` is clean.
- [ ] CI is green on `main`.
- [ ] Build the files: `python -m build` and `python scripts/make_standalone_zip.py`.
- [ ] Try the standalone zip as a new user would: unzip it into an empty folder,
      double-click the launcher, create a vault with a custom time of `0.001`
      hours, unlock it, then delete it.
- [ ] Tag, push the tag, and create the GitHub release (commands below).
- [ ] Open the release page and download each asset once.

## First release (1.0.0): exact commands

Nothing below has been run yet. These steps publish the repository, so check
each one before running it.

```powershell
# 1. Final local checks
python -m pytest
ruff check .
git status --short
git ls-files "*.tlp" "*.progress*"   # must print nothing

# 2. Create the public GitHub repository from this folder and push main
gh repo create Zlolapoozaa/timelock --public --source . --remote origin --description "Lock secrets behind hours of unavoidable computation (RSW time-lock puzzle)"
git push -u origin main

# 3. Turn on private vulnerability reporting (SECURITY.md links to it)
gh api -X PUT repos/Zlolapoozaa/timelock/private-vulnerability-reporting

# 4. Wait for CI on main to pass
gh run list --workflow ci.yml --limit 1
gh run watch <run-id-from-the-line-above> --exit-status

# 5. Build the release files
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
python -m build
python scripts/make_standalone_zip.py

# 6. Tag and publish the release
git tag -a v1.0.0 -m "Timelock 1.0.0"
git push origin v1.0.0
gh release create v1.0.0 dist/timelock-1.0.0-standalone.zip dist/timelock_vault-1.0.0-py3-none-any.whl dist/timelock_vault-1.0.0.tar.gz timelock.py --title "Timelock 1.0.0" --notes-file .github/release-notes/v1.0.0.md --verify-tag
```

Optional, later: publish to PyPI as `timelock-vault` (for example with
`twine upload dist/timelock_vault-1.0.0*`, or a trusted-publishing workflow),
then simplify the pip line in the README to `pip install "timelock-vault[fast]"`.

## Later releases

1. Add a new heading to `CHANGELOG.md`, bump `__version__`, and write
   `.github/release-notes/v<version>.md`.
2. Commit, push, and wait for CI.
3. Repeat steps 5–6 above with the new version number.
