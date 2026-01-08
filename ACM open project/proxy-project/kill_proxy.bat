@echo off
title Kill Proxy Server
color 0C
echo.
echo ========================================
echo   Killing Proxy Server Processes
echo ========================================
echo.

REM Find processes using port 8888
echo Looking for processes on port 8888...
netstat -ano | findstr :8888
if errorlevel 1 (
    echo No processes found on port 8888
) else (
    echo.
    echo Found processes. Attempting to kill...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8888') do (
        taskkill /PID %%a /F
    )
)

echo.
echo Done!
echo.
pause