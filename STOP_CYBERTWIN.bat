@echo off
title Stop CyberTwin Platform
color 0c

echo ===============================================================
echo                STOPPING CYBERTWIN PLATFORM
echo ===============================================================
echo.
echo Stopping any running Python/Uvicorn Backend on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do taskkill /f /pid %%a >nul 2>&1

echo Stopping any running Vite Frontend on port 5173...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173" ^| findstr "LISTENING"') do taskkill /f /pid %%a >nul 2>&1

echo Stopping any running Cloudflare Tunnels...
taskkill /f /im cloudflared.exe >nul 2>&1

echo.
echo [DONE] CyberTwin Backend, Frontend, and Cloudflare tunnels stopped cleanly.
echo ===============================================================
pause
