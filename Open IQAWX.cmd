@echo off
cd /d "%~dp0"
if exist "iqaw.exe" (
  "iqaw.exe"
) else if exist "target\release\iqaw.exe" (
  "target\release\iqaw.exe"
) else (
  echo Run the installer first: powershell -File scripts\install.ps1
  pause
)
