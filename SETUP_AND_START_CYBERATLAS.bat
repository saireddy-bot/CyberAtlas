@echo off
title CyberAtlas - Automated Setup & Launcher
color 0b

echo ===============================================================
echo        CYBERATLAS SOC PLATFORM - PARTNER SETUP & RUN
echo ===============================================================
echo.

cd /d "%~dp0Backend"

echo [*] Step 1: Checking Python Virtual Environment...
if not exist "venv\Scripts\python.exe" (
    echo [*] Creating virtual environment (venv)...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [!] Python is not installed or not in PATH. Please install Python 3.10+ from python.org.
        pause
        exit /b 1
    )
)

echo [*] Step 2: Installing Python Dependencies...
.\venv\Scripts\pip install -r requirements.txt --quiet --disable-pip-version-check
if %errorlevel% neq 0 (
    echo [!] Failed to install dependencies. Retrying with basic requirements...
    .\venv\Scripts\pip install fastapi uvicorn httpx sqlalchemy python-dotenv pydantic
)

echo.
echo ===============================================================
echo  [+] Setup Complete! Launching CyberAtlas Enterprise SOC...
echo ===============================================================
echo.
echo  - Local Dashboard : http://localhost:8000
echo.

start "" http://localhost:8000
.\venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

pause
