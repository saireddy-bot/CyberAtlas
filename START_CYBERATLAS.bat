@echo off
title CyberAtlas Enterprise SOC Platform Launcher (Live HTTPS 🔒)
color 0b

echo ===============================================================
echo     CYBERATLAS ENTERPRISE SOC PLATFORM (LIVE HTTPS 🔒)
echo ===============================================================
echo.
echo [1/2] Starting Unified Enterprise Platform (FastAPI + React UI on Port 8000)...
start "CyberAtlas Enterprise SOC" cmd /k "cd /d "%~dp0Backend" && .\venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak >nul

echo [2/2] Starting Secure Cloudflare Enterprise Tunnel (HTTP/2 Stable)...
start "CyberAtlas Cloudflare Live HTTPS Tunnel" cmd /k ""C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --protocol http2 --url http://127.0.0.1:8000"

timeout /t 4 /nobreak >nul

echo.
echo ===============================================================
echo  CyberAtlas is now LIVE with REAL HTTPS DOMAIN (No Localhost):
echo.
echo  - Live Public HTTPS: Check the Cloudflare Tunnel Window for your link
echo  - Enterprise LAN IP: http://10.104.57.193:8000
echo ===============================================================
echo.
pause
