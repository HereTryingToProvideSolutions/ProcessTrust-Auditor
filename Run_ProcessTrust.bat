@echo off
setlocal
cd /d "%~dp0"
title ProcessTrust - Easy Audit
 echo.
echo ============================================
echo       ProcessTrust - Windows PC Audit
echo ============================================
echo.
echo This tool checks running processes, signatures,
echo and current network connections.
echo It does not remove files or block connections.
echo.
echo Reports will be saved in your user profile:
echo %USERPROFILE%\ProcessTrust
echo.
echo Note: Run as administrator for better visibility.
echo Network lookups may contact public RDAP/DNS services.
echo.
pause
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ProcessTrust_v1_3.ps1"
if errorlevel 1 (
 echo.
 echo Audit encountered an error. Read the messages above.
) else (
 echo.
 echo Audit finished. Open the reports folder to view results.
 choice /C YN /M "Open the reports folder now"
 if not errorlevel 2 explorer.exe "%USERPROFILE%\ProcessTrust"
)
echo.
pause
endlocal
