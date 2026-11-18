@echo off
rem Double-click to open Timelock on Windows.
title Timelock Vault
cd /d "%~dp0"
where py >nul 2>nul && goto run_py
where python >nul 2>nul && goto run_python
echo Python 3 is not installed.
echo Get it from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
echo then double-click Timelock.bat again.
pause
exit /b 1

:run_py
py -3 timelock.py
goto done

:run_python
python timelock.py

:done
rem Keep the window open if Python reported a problem, so it can be read.
if errorlevel 1 pause
