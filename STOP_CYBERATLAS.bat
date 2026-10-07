@echo off
title Stop CyberAtlas Platform
color 0c

echo ===============================================================
echo                STOPPING CYBERATLAS PLATFORM
echo ===============================================================
echo.
echo Stopping any running Python/Uvicorn Backend on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do taskkill /f /pid %%a >nul 2>&1

echo Stopping any running Vite Frontend on port 5173...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5173" ^| findstr "LISTENING"') do taskkill /f /pid %%a >nul 2>&1

echo Stopping any running Cloudflare Tunnels...
taskkill /f /im cloudflared.exe >nul 2>&1

echo.
echo [DONE] CyberAtlas Backend, Frontend, and Cloudflare tunnels stopped cleanly.
echo ===============================================================
pause
