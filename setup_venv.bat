@echo off
REM Creates / updates the virtual environment in .venv (called by run.bat and the other scripts).
REM Uses requirements-dev.txt when present (QA version), otherwise requirements.txt (prod version).
REM Reinstalls only when a requirements file changed since the last successful install.
setlocal
cd /d "%~dp0"

set "REQ=requirements.txt"
if exist "requirements-dev.txt" set "REQ=requirements-dev.txt"

set "UPTODATE="
if exist ".venv\Scripts\python.exe" (
    fc /b "%REQ%" ".venv\installed-requirements.txt" >nul 2>&1 && fc /b "requirements.txt" ".venv\installed-runtime.txt" >nul 2>&1 && set "UPTODATE=1"
)
if defined UPTODATE exit /b 0

set "PY="
py -3.12 -c "import sys" >nul 2>&1 && set "PY=py -3.12"
if not defined PY (
    python -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo ERROR: AutoLogger requires Python 3.12 or newer.
    echo Please install Python 3.12 and update your PATH.
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment in .venv ...
    %PY% -m venv .venv || exit /b 1
)
echo Installing dependencies from %REQ% ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q --upgrade pip || exit /b 1
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r "%REQ%" || exit /b 1
copy /y "%REQ%" ".venv\installed-requirements.txt" >nul
copy /y "requirements.txt" ".venv\installed-runtime.txt" >nul
exit /b 0
