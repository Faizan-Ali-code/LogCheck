@echo off
REM Runs LogCheck from the current folder, so relative paths work as typed:
REM     run.bat scan D:\logs
REM     run.bat scan D:\logs --config logcheck.toml --out D:\reports\today
REM Creates .venv on the first run. Changes nothing outside this folder.
setlocal
call "%~dp0setup_venv.bat"
if errorlevel 1 (
    pause
    exit /b 1
)
set "PYTHONPATH=%~dp0"
"%~dp0.venv\Scripts\python.exe" -m logcheck %*
set "RC=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %RC%
