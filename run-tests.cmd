@echo off
setlocal
cd /d "%~dp0"
set "CODEX_NODE_BIN=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin"
where node >nul 2>nul
if errorlevel 1 set "PATH=%CODEX_NODE_BIN%;%PATH%"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js was not found. Install Node.js or add it to PATH, then run this file again.
  exit /b 1
)
call "%~dp0node_modules\.bin\playwright.cmd" install chromium
if errorlevel 1 exit /b 1
call "%~dp0node_modules\.bin\playwright.cmd" test
if errorlevel 1 exit /b 1
"%~dp0.venv\Scripts\python.exe" -m pytest -q
exit /b %errorlevel%

