@echo off
title Proxy Server Setup
color 0B
echo.
echo ========================================
echo   Proxy Server Setup
echo ========================================
echo.

REM Create directories
echo Creating directory structure...
if not exist src mkdir src
if not exist config mkdir config
if not exist tests mkdir tests
if not exist docs mkdir docs
if not exist logs mkdir logs
echo [OK] Directories created
echo.

REM Check Python
echo Checking Python installation...
python --version >nul 2>nul
if errorlevel 1 (
    color 0C
    echo [ERROR] Python not found!
    echo Please install Python 3.7+ from python.org
    pause
    exit /b 1
)

python --version
echo [OK] Python found
echo.

REM Check curl
echo Checking curl...
where curl.exe >nul 2>nul
if errorlevel 1 (
    color 0E
    echo [WARNING] curl.exe not found
    echo Install curl or use Windows 10/11 which includes it
) else (
    curl.exe --version | findstr "curl"
    echo [OK] curl found
)
echo.

REM Check if files exist
echo Checking project files...
if exist src\proxy_server_with_parser.py (
    echo [OK] proxy_server_with_parser.py found
) else (
    echo [WARNING] proxy_server_with_parser.py not found in src\
)

if exist config\proxy_config.json (
    echo [OK] proxy_config.json found
) else (
    echo [WARNING] proxy_config.json not found in config\
)

if exist config\blocked_domains.txt (
    echo [OK] blocked_domains.txt found
) else (
    echo [WARNING] blocked_domains.txt not found in config\
)
echo.

echo ========================================
echo   Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Copy proxy_server_with_parser.py to src\
echo 2. Copy config files to config\
echo 3. Run run_proxy.bat to start
echo.
pause