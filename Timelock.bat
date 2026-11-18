@echo off
title Timelock Vault
cd /d "%~dp0"
where py >nul 2>nul && (py timelock.py) || (python timelock.py)
