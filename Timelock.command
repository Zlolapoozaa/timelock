#!/bin/bash
# Double-click to open Timelock on macOS.
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then
  python3 timelock.py
else
  echo "Python 3 is not installed. Get it from https://www.python.org/downloads/"
  read -r -p "Press Enter to close..." _
fi
