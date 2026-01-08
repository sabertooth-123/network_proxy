@echo off
title View Proxy Logs
color 0F
echo.
echo ========================================
echo   Proxy Server Logs
echo ========================================
echo.

if not exist logs\proxy.log (
    echo No log file found.
    echo Start the proxy first: run_proxy.bat
    pause
    exit /b 1
)

REM Show last 50 lines
powershell Get-Content logs\proxy.log -Tail 50

echo.
echo ========================================
echo   End of Logs
echo ========================================
echo.
echo To watch live: powershell Get-Content logs\proxy.log -Wait
echo.
pause