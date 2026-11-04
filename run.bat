@echo off
setlocal
cd /d "%~dp0"

REM Disable QuickEdit (prevents mouse selection/pause behavior) - same as the Java launcher
reg add "HKEY_CURRENT_USER\Console" /v QuickEdit /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Console" /v ExtendedEditKey /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Console" /v QuickEditForceOn /t REG_DWORD /d 0 /f >nul 2>&1

call "%~dp0setup_venv.bat"
if errorlevel 1 (
    echo.
    pause
    exit /b 1
)

REM Optional: Java is only needed for Card No database checks (Informix JDBC through JPype).
REM Arguments are passed through, e.g.  run.bat --cli   or   run.bat -Dautologger.scan.processes=4
".venv\Scripts\python.exe" -m autologger %*

pause
