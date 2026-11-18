"""Build dist/timelock-<version>-standalone.zip: the files for people who just want to
double-click, in a folder of their own. Marks Timelock.command and timelock.py as
executable inside the zip, so they run straight after unzipping on macOS and Linux
(a plain download of Timelock.command loses that bit).

    python scripts/make_standalone_zip.py
"""

import os
import re
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = {  # name: (unix permissions, line ending)
    "timelock.py": (0o755, b"\n"),
    "Timelock.command": (0o755, b"\n"),
    "Timelock.bat": (0o644, b"\r\n"),
    "README.md": (0o644, b"\n"),
    "LICENSE": (0o644, b"\n"),
}


def main():
    with open(os.path.join(ROOT, "timelock.py"), encoding="utf-8") as f:
        version = re.search(r'^__version__ = "([^"]+)"', f.read(), re.MULTILINE).group(1)
    folder = f"timelock-{version}"
    out = os.path.join(ROOT, "dist", f"{folder}-standalone.zip")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with zipfile.ZipFile(out, "w") as z:
        for name, (mode, eol) in FILES.items():
            with open(os.path.join(ROOT, name), "rb") as f:
                data = f.read().replace(b"\r\n", b"\n").replace(b"\n", eol)
            info = zipfile.ZipInfo(f"{folder}/{name}", date_time=time.localtime()[:6])
            info.create_system = 3  # Unix, so unzip tools honour the permissions below
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    print(out)


if __name__ == "__main__":
    main()
