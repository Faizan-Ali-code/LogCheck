@echo off
setlocal
cd /d "%~dp0"
call "%~dp0setup_venv.bat"
if errorlevel 1 (
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m autologger.tools.encrypt_password
pause
