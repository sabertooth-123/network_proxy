@echo off
title Proxy Server Help
color 0F
echo.
echo ========================================
echo   Proxy Server - Help
echo ========================================
echo.
echo Available batch files:
echo.
echo   setup.bat       - Initial setup and checks
echo   run_proxy.bat   - Start the proxy server
echo   test_proxy.bat  - Run test suite
echo   clean.bat       - Clean logs and cache
echo   help.bat        - Show this help
echo.
echo ========================================
echo   Manual Commands
echo ========================================
echo.
echo Start proxy:
echo   python src\proxy_server.py
echo.
echo Test with curl:
echo   curl.exe -x localhost:8888 http://example.com
echo.
echo View logs:
echo   type logs\proxy.log
echo   powershell Get-Content logs\proxy.log -Tail 50
echo.
echo Custom port:
echo   python src\proxy_server.py --port 9999
echo.
echo ========================================
echo   Configuration
echo ========================================
echo.
echo Config file:     config\proxy_config.json
echo Blocked domains: config\blocked_domains.txt
echo Logs:            logs\proxy.log
echo.
pause