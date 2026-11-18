import importlib.util

import pytest

import timelock as tl

HAS_GMPY2 = importlib.util.find_spec("gmpy2") is not None


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Keep every test inside its own temp folder (never near real vaults), with
    small chunks so even tiny puzzles run through the loop many times."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tl, "vault_dir", lambda: str(tmp_path))
    monkeypatch.setattr(tl, "CHUNK", 1000)


@pytest.fixture(params=["python", "gmpy2"])
def backend(request, monkeypatch):
    """Run a test once with the pure-Python math and once with gmpy2."""
    if request.param == "gmpy2":
        if not HAS_GMPY2:
            pytest.skip("gmpy2 is not installed")
        import gmpy2
        monkeypatch.setattr(tl, "gmpy2", gmpy2)
        monkeypatch.setattr(tl, "HAVE_GMPY2", True)
    else:
        monkeypatch.setattr(tl, "HAVE_GMPY2", False)
    return request.param

