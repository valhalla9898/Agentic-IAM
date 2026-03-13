"""
Simplified Agentic-IAM API Server - No circular imports
"""
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from starlette.responses import JSONResponse

# settings
from config.settings import get_settings

settings = get_settings()

# Create the FastAPI app
app = FastAPI(
    title="Agentic-IAM API",
    description="Comprehensive Agent Identity & Access Management Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from utils.cert_validation import validate_pem_certificate

import os
from fastapi.staticfiles import StaticFiles
from fastapi import APIRouter, Body


@app.middleware("http")
async def mtls_middleware(request: Request, call_next):
    """Enforce mTLS for configured endpoints when enabled in settings.

    This middleware expects a TLS-terminating proxy to forward client
    certificate verification status via headers like `x-ssl-client-verify`
    or `x-forwarded-client-cert`. In environments without a proxy, this
    will only act when `settings.enable_mtls` is True and headers are present.
    """
    if settings.enable_mtls:
        path = request.url.path
        for prefix in settings.mtls_required_endpoints:
            if path.startswith(prefix):
                # Check common headers set by proxies/ingress
                verify = request.headers.get("x-ssl-client-verify")
                forwarded_cert = request.headers.get("x-forwarded-client-cert")
                client_cert = request.headers.get("x-client-cert")

                # Consider verification successful if header indicates SUCCESS
                if verify and verify.upper() == "SUCCESS":
                    return await call_next(request)

                # If a client cert is forwarded, validate its PEM when possible
                if forwarded_cert:
                    try:
                        # Some ingress controllers forward a PEM block, others forward subject string.
                        # Try lightweight PEM validation first; fall back to CN regex.
                        ok = validate_pem_certificate(forwarded_cert, require_cn=True)
                        if ok:
                            return await call_next(request)

                        # Fallback: attempt to extract CN from forwarded subject string
                        import re
                        s = forwarded_cert
                        m = re.search(r'CN=([^,;/\n\r]+)', s)
                        if m and m.group(1).strip():
                            return await call_next(request)

                    except Exception:
                        return JSONResponse(status_code=403, content={"detail": "mTLS client certificate validation failed"})

                if client_cert:
                    try:
                        if validate_pem_certificate(client_cert, require_cn=False):
                            return await call_next(request)
                    except Exception:
                        return JSONResponse(status_code=403, content={"detail": "mTLS client certificate validation failed"})

                return JSONResponse(status_code=403, content={"detail": "mTLS required for this endpoint"})
    return await call_next(request)


# -- Reports static files + API -------------------------------------------------
# Serve scan reports saved under project-root/data/reports at /reports/static/...
reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "reports"))
os.makedirs(reports_dir, exist_ok=True)
app.mount("/reports/static", StaticFiles(directory=reports_dir), name="reports_static")

reports_router = APIRouter(prefix="/reports", tags=["reports"])


@reports_router.get("/list")
async def list_reports():
    """Return JSON index of reports and files."""
    result = []
    for target in sorted(os.listdir(reports_dir)):
        target_path = os.path.join(reports_dir, target)
        if not os.path.isdir(target_path):
            continue
        for ts in sorted(os.listdir(target_path), reverse=True):
            rep_path = os.path.join(target_path, ts)
            if not os.path.isdir(rep_path):
                continue
            files = []
            for root, _, filenames in os.walk(rep_path):
                for f in filenames:
                    rel = os.path.relpath(os.path.join(root, f), reports_dir)
                    files.append({
                        "name": f,
                        "path": rel.replace(os.path.sep, "/"),
                        "url": f"/reports/static/{rel.replace(os.path.sep, '/')}"
                    })
            result.append({
                "target": target,
                "timestamp": ts,
                "files": files
            })
    return {"reports": result}


@reports_router.post("/notify")
async def notify_report(payload: dict = Body(...)):
    """Lightweight notify endpoint called after importing a scan.

    Payload: { "target": "juice-shop", "timestamp": "YYYYMMDD_HHMMSS" }
    """
    target = payload.get("target")
    timestamp = payload.get("timestamp")
    # For now this is a simple acknowledgement endpoint. Integration with
    # WebSocket dashboard or additional processing can be added later.
    return {"status": "notified", "target": target, "timestamp": timestamp}


app.include_router(reports_router)

# Root endpoint
@app.get("/")
async def root():
    return {
        "name": "Agentic-IAM API",
        "version": "1.0.0",
        "description": "Comprehensive Agent Identity & Access Management Platform",
        "docs": "/docs",
        "health": "/health",
        "graphql": "/graphql",
        "mobile": "/api/v1/mobile"
    }

# Health endpoint
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "agentic-iam-api"}

# GraphQL endpoint stub
@app.get("/graphql")
async def graphql_playground():
    return {
        "message": "GraphQL endpoint available",
        "schema": "Query { agents, agent, trustScore }",
        "documentation": "See /docs for details"
    }

# Mobile API endpoints
@app.post("/api/v1/mobile/register")
async def mobile_register(agent_name: str, platform: str = "mobile"):
    """Register a mobile agent"""
    agent_id = f"agent_mobile_{agent_name}_{hash(agent_name) & 0xffffffff:x}"
    return {
        "agent_id": agent_id,
        "registration_id": f"reg_{agent_id}",
        "status": "registered"
    }

@app.post("/api/v1/mobile/heartbeat")
async def mobile_heartbeat(agent_id: str):
    """Mobile agent heartbeat"""
    return {
        "status": "ok",
        "agent_id": agent_id,
        "timestamp": "2025-12-28T00:00:00Z"
    }

# API info endpoint
@app.get("/api/v1")
async def api_info():
    return {
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "mobile": "/api/v1/mobile",
            "graphql": "/graphql"
        },
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc"
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "api.app:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
