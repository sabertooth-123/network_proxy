@echo off
title Proxy Server
color 0A
echo.
echo ========================================
echo   Custom Network Proxy Server
echo ========================================
echo.
echo Starting proxy on localhost:8888
echo Press Ctrl+C to stop
echo.
echo ========================================
echo.
python src\proxy_server_with_parser.py
if errorlevel 1 (
    color 0C
    echo.
    echo ERROR: Failed to start proxy server
    echo Make sure Python is installed and proxy_server.py exists
    pause
)
