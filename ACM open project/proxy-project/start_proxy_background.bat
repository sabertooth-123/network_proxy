@echo off
title Start Proxy (Background)
echo.
echo Starting proxy in background...
start /MIN "Proxy Server" python src\proxy_server_with_parser.py
echo.
echo Proxy started in minimized window
echo Use kill_proxy.bat to stop it
echo.
timeout /t 3