@echo off
title Proxy Test Suite
color 0B
echo.
echo ========================================
echo   Proxy Server Test Suite
echo ========================================
echo.
echo Testing proxy at localhost:8888
echo Make sure the proxy is running first!
echo.
pause

REM Check if curl exists
where curl.exe >nul 2>nul
if errorlevel 1 (
    echo ERROR: curl.exe not found
    echo Please install curl or use Windows 10/11 which includes it
    pause
    exit /b 1
)

echo.
echo [Test 1] Basic HTTP GET
curl.exe -x localhost:8888 http://example.com -s -o nul -w "Status: %%{http_code}\n"

echo.
echo [Test 2] HTTPS Request
curl.exe -x localhost:8888 https://example.com -s -o nul -w "Status: %%{http_code}\n"

echo.
echo [Test 3] POST Request
curl.exe -x localhost:8888 -X POST http://httpbin.org/post -d "test=data" -s -o nul -w "Status: %%{http_code}\n"

echo.
echo [Test 4] HEAD Request
curl.exe -x localhost:8888 --head http://example.com -s -o nul -w "Status: %%{http_code}\n"

echo.
echo ========================================
echo   Tests Complete!
echo ========================================
echo Check logs\proxy.log for details
echo.
pause