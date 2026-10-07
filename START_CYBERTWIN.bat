@echo off
title CyberTwin Enterprise SOC Platform Launcher (Live HTTPS 🔒)
color 0b

echo ===============================================================
echo     CYBERTWIN ENTERPRISE SOC PLATFORM (LIVE HTTPS 🔒)
echo ===============================================================
echo.
echo [1/2] Starting Unified Enterprise Platform (FastAPI + React UI on Port 8000)...
start "CyberTwin Enterprise SOC" cmd /k "cd /d "%~dp0Backend" && .\venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

timeout /t 3 /nobreak >nul

echo [2/2] Starting Secure Cloudflare Enterprise Tunnel...
start "CyberTwin Cloudflare Live HTTPS Tunnel" cmd /k ""C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://localhost:8000"

timeout /t 4 /nobreak >nul

echo.
echo ===============================================================
echo  CyberTwin is now LIVE with REAL HTTPS DOMAIN (No Localhost):
echo.
echo  - Live Public HTTPS: Check the Cloudflare Terminal Window for your unique link
echo  - Enterprise LAN IP: http://10.104.57.193:8000
echo ===============================================================
echo.
echo Launching CyberTwin in Google Chrome...
start https://behavior-jurisdiction-conclusion-eat.trycloudflare.com

pause

