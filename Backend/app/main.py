from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import threading

from . import models
from .database import Base, engine
from .routes import router as asset_router
from .user_management import router as user_router
from .auth import router as auth_router
from .integrations import router as integrations_router
from .monitor import start_monitoring

# Create database tables automatically
Base.metadata.create_all(bind=engine)





# ============================================================
# CYBERTWIN APPLICATION
# ============================================================

app = FastAPI(
    title="CyberAtlas API",
    description="CyberAtlas Enterprise Security Posture & Threat Intelligence Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:; frame-ancestors 'self'; object-src 'none'"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
        return response

app.add_middleware(SecurityHeadersMiddleware)



# ============================================================
# BACKGROUND MONITORING
# ============================================================

@app.on_event("startup")
def start_background_monitor():
    monitoring_thread = threading.Thread(
        target=start_monitoring,
        args=(60,),
        daemon=True,
        name="CyberTwin-Monitor"
    )
    monitoring_thread.start()


# ============================================================
# ROUTES
# ============================================================

app.include_router(asset_router)
app.include_router(user_router)
app.include_router(auth_router)
app.include_router(integrations_router)





# ============================================================
# HEALTH CHECK & API STATUS
# ============================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "platform": "CyberAtlas Enterprise SOC"
    }


# ============================================================
# UNIFIED FRONTEND SERVING (SINGLE-PORT ENTERPRISE MODE)
# ============================================================

import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "Frontend", "dist"))

if os.path.exists(frontend_dist):
    ui_assets_dir = os.path.join(frontend_dist, "ui_assets")
    if os.path.exists(ui_assets_dir):
        app.mount("/ui_assets", StaticFiles(directory=ui_assets_dir), name="ui_assets")

    @app.get("/")
    def serve_frontend_root():
        return FileResponse(os.path.join(frontend_dist, "index.html"))

    @app.get("/{full_path:path}")
    def serve_frontend_spa(full_path: str):
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
else:
    @app.get("/")
    def root():
        return {
            "project": "CyberAtlas",
            "status": "online",
            "message": "CyberAtlas backend is running (Frontend not yet compiled)"
        }
