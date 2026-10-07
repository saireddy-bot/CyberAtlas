@echo off
title CyberAtlas Autonomous SOC Application
color 0b

echo ===============================================================
echo        CYBERATLAS AUTONOMOUS ENTERPRISE SOC APPLICATION
echo            (Native Standalone Desktop Application)
echo ===============================================================
echo.
echo [1/2] Verifying CyberAtlas Security Engine & Core APIs...
start "CyberAtlas Security Engine" /min cmd /c "cd /d "%~dp0Backend" && .\venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

timeout /t 2 /nobreak >nul

echo [2/2] Launching CyberAtlas Native Desktop Application...
cd /d "%~dp0Frontend"
call npx.cmd electron electron/main.cjs

echo.
echo [!] CyberAtlas Application closed. Shutting down background engine...
taskkill /f /im uvicorn.exe >nul 2>&1
exit
