"""
Agentic-IAM: FastAPI Application

Main FastAPI application with comprehensive middleware, routing, and integration
with the Agent Identity Framework.
"""

import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from config.settings import Settings
from core.agentic_iam import AgenticIAM
from utils.logger import get_logger, setup_logging

# Add core modules to path
sys.path.append(str(Path(__file__).parent.parent / "core"))
sys.path.append(str(Path(__file__).parent.parent.parent))


# Import routers defensively (some optional routers may be missing)
try:
    from api.routers import health
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'health' not available")
    health = None

try:
    from api.routers import agents
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'agents' not available")
    agents = None

try:
    from api.routers import authentication
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'authentication' not available")
    authentication = None

try:
    from api.routers import authorization
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'authorization' not available")
    authorization = None

try:
    from api.routers import sessions
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'sessions' not available")
    sessions = None

try:
    from api.routers import intelligence
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'intelligence' not available")
    intelligence = None

try:
    from api.routers import audit
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'audit' not available")
    audit = None

try:
    from api.routers import mobile
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'mobile' not available")
    mobile = None

try:
    from api.routers import qa
except (ImportError, ModuleNotFoundError):
    import logging

    logging.getLogger(__name__).debug("Optional router 'qa' not available")
    qa = None

# Global instances
iam_instance: Optional[AgenticIAM] = None
settings_instance: Optional[Settings] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events"""
    global iam_instance, settings_instance

    # Startup
    logger = get_logger("api")
    logger.info("Starting Agentic-IAM API server...")

    try:
        # Initialize settings
        settings_instance = Settings()

        # Setup logging
        setup_logging(log_level=settings_instance.log_level, log_file=settings_instance.log_file, enable_console=True)

        # Initialize IAM system
        iam_instance = AgenticIAM(settings_instance)
        await iam_instance.initialize()

        logger.info("API server started successfully")

        yield

    except Exception as e:
        logger.error(f"Failed to start API server: {str(e)}")
        raise
    finally:
        # Shutdown
        logger.info("Shutting down Agentic-IAM API server...")

        if iam_instance:
            await iam_instance.shutdown()

        logger.info("API server shutdown complete")


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""

    app = FastAPI(
        title="Agentic-IAM API",
        description="Comprehensive Agent Identity & Access Management Platform",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Add middleware
    setup_middleware(app)

    # Add routers
    setup_routers(app)

    # Add exception handlers
    setup_exception_handlers(app)

    return app


def setup_middleware(app: FastAPI):
    """Configure application middleware"""
    settings = Settings()

    # CORS middleware
    if settings.enable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Trusted host middleware
    if settings.is_production:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=[settings.api_host, "localhost", "127.0.0.1"])

    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        if settings.require_tls:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

    # Request logging middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        logger = get_logger("api.requests")
        start_time = asyncio.get_event_loop().time()

        # Log request
        logger.info(
            f"Request: {request.method} {request.url}",
            extra={
                "method": request.method,
                "url": str(request.url),
                "client_ip": request.client.host,
                "user_agent": request.headers.get("user-agent"),
            },
        )

        response = await call_next(request)

        # Log response
        duration = asyncio.get_event_loop().time() - start_time
        logger.info(
            f"Response: {response.status_code} in {duration:.3f}s",
            extra={"status_code": response.status_code, "duration": duration},
        )

        return response

    # Admin API key protection middleware
    @app.middleware("http")
    async def require_admin_api_key(request: Request, call_next):
        """Protect admin/reporting endpoints when an admin API key is configured"""
        admin_key = getattr(settings, "admin_api_key", None)
        if admin_key:
            path = request.url.path
            protected_prefixes = ["/reports", "/alerts"]
            for prefix in protected_prefixes:
                if path.startswith(prefix):
                    key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
                    if not key or key != admin_key:
                        return JSONResponse(
                            status_code=401, content={"detail": "Unauthorized - missing or invalid API key"}
                        )
                    break
        return await call_next(request)

    # Static reports access: require signed URLs when configured
    @app.middleware("http")
    async def validate_signed_static_url(request: Request, call_next):
        """Validate signed URLs for static report access"""
        import hashlib
        import hmac
        import time

        path = request.url.path
        if path.startswith("/reports/static"):
            signing_key = getattr(settings, "static_url_signing_key", None)
            if signing_key:
                q = request.query_params
                expires = q.get("expires")
                sig = q.get("sig")
                try:
                    if not expires or not sig:
                        raise ValueError("missing signature or expires")
                    now = int(time.time())
                    exp = int(expires)
                    if now > exp:
                        return JSONResponse(status_code=401, content={"detail": "URL signature expired"})

                    msg = f"{path}|{expires}".encode("utf-8")
                    expected = hmac.new(signing_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(expected, sig):
                        return JSONResponse(status_code=401, content={"detail": "Invalid URL signature"})
                except (ValueError, TypeError):
                    return JSONResponse(status_code=401, content={"detail": "Invalid signed URL"})
        return await call_next(request)

    # mTLS middleware for secure endpoints
    @app.middleware("http")
    async def mtls_middleware(request: Request, call_next):
        """Enforce mTLS for configured endpoints when enabled in settings"""
        if getattr(settings, "enable_mtls", False):
            path = request.url.path
            mtls_endpoints = getattr(settings, "mtls_required_endpoints", [])
            for prefix in mtls_endpoints:
                if path.startswith(prefix):
                    verify = request.headers.get("x-ssl-client-verify")
                    forwarded_cert = request.headers.get("x-forwarded-client-cert")
                    client_cert = request.headers.get("x-client-cert")

                    if verify and verify.upper() == "SUCCESS":
                        return await call_next(request)

                    if forwarded_cert or client_cert:
                        return await call_next(request)

                    return JSONResponse(status_code=403, content={"detail": "mTLS required for this endpoint"})
        return await call_next(request)


def setup_routers(app: FastAPI):
    """Configure API routers"""

    # Health and monitoring
    if health is not None:
        app.include_router(health.router, prefix="/health", tags=["Health & Monitoring"])

    # Core agent management
    if agents is not None:
        app.include_router(agents.router, prefix="/api/v1/agents", tags=["Agent Management"])

    # Authentication
    if authentication is not None:
        app.include_router(authentication.router, prefix="/api/v1/auth", tags=["Authentication"])

    # Authorization
    if authorization is not None:
        app.include_router(authorization.router, prefix="/api/v1/authz", tags=["Authorization"])

    # Session management
    if sessions is not None:
        app.include_router(sessions.router, prefix="/api/v1/sessions", tags=["Session Management"])

    # Intelligence & trust scoring
    if intelligence is not None:
        app.include_router(intelligence.router, prefix="/api/v1/intelligence", tags=["Intelligence & Trust"])

    # Audit & compliance
    if audit is not None:
        app.include_router(audit.router, prefix="/api/v1/audit", tags=["Audit & Compliance"])

    # Mobile endpoints
    if mobile is not None:
        app.include_router(mobile.router, prefix="/api/v1/mobile", tags=["Mobile"])

    # Q&A System
    if qa is not None:
        app.include_router(qa.router, tags=["Q&A System - "])

    # Reports and alerts (from legacy api.app)
    _setup_reports_and_alerts_routers(app)


def _setup_reports_and_alerts_routers(app: FastAPI):
    """Setup reports and alerts routers (legacy endpoints from api.app)"""
    import hashlib
    import hmac
    import os
    import time

    from fastapi import APIRouter, Body
    from fastapi.staticfiles import StaticFiles

    settings = Settings()

    # -- Reports static files + API -------------------------------------------------
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "reports"))
    os.makedirs(reports_dir, exist_ok=True)

    try:
        app.mount("/reports/static", StaticFiles(directory=reports_dir), name="reports_static")
    except Exception as e:
        logger = get_logger("api.startup")
        logger.debug("Reports static mount skipped: %s", e)

    reports_router = APIRouter(prefix="/reports", tags=["Reports"])

    @reports_router.get("/list")
    async def list_reports():
        """Return JSON index of reports and files"""
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
                        files.append(
                            {
                                "name": f,
                                "path": rel.replace(os.path.sep, "/"),
                                "url": f"/reports/static/{rel.replace(os.path.sep, '/')}",
                            }
                        )
                result.append({"target": target, "timestamp": ts, "files": files})
        return {"reports": result}

    @reports_router.post("/notify")
    async def notify_report(payload: dict = Body(...)):
        """Lightweight notify endpoint called after importing a scan"""
        target = payload.get("target")
        timestamp = payload.get("timestamp")
        return {"status": "notified", "target": target, "timestamp": timestamp}

    @reports_router.post("/sign")
    async def sign_report_url(payload: dict = Body(...), request: Request = None):
        """Generate a signed URL for a static report path"""
        path = payload.get("path")
        expires_in = int(payload.get("expires_in", 3600))
        if not path or not path.startswith("/reports/static"):
            raise HTTPException(status_code=400, detail="path must start with /reports/static")

        signing_key = getattr(settings, "static_url_signing_key", None)
        if not signing_key:
            raise HTTPException(status_code=400, detail="Static URL signing not configured")

        admin_key = getattr(settings, "admin_api_key", None)
        if admin_key:
            key = request.headers.get("x-api-key") or request.headers.get("X-API-KEY")
            if not key or key != admin_key:
                raise HTTPException(status_code=401, detail="Unauthorized")

        exp = int(time.time()) + expires_in
        msg = f"{path}|{exp}".encode("utf-8")
        sig = hmac.new(signing_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()

        host = getattr(settings, "api_host", "127.0.0.1")
        port = getattr(settings, "api_port", 8000)
        base = f"http://{host}:{port}"
        signed = f"{base}{path}?expires={exp}&sig={sig}"
        return {"signed_url": signed, "expires": exp, "sig": sig}

    app.include_router(reports_router)

    # -- Alerts API ---------------------------------------------------------------
    alerts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "alerts"))
    os.makedirs(alerts_dir, exist_ok=True)

    alerts_router = APIRouter(prefix="/alerts", tags=["Alerts"])

    @alerts_router.post("/")
    async def create_alert(payload: dict = Body(...)):
        """Receive an alert about a possible compromise or incident"""
        import json

        target = payload.get("target", "unknown")
        severity = payload.get("severity", "info")
        message = payload.get("message", "")
        details = payload.get("details", {})

        ts = time.strftime("%Y%m%d_%H%M%S")
        filename = f"alert_{target}_{ts}.json"
        path = os.path.join(alerts_dir, filename)
        record = {
            "target": target,
            "severity": severity,
            "message": message,
            "details": details,
            "timestamp": ts,
            "evidence_urls": payload.get("evidence_urls", []),
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)

        return {
            "status": "ok",
            "file": os.path.relpath(path, start=os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))),
        }

    @alerts_router.get("/list")
    async def list_alerts():
        """List all alerts"""
        import json

        items = []
        for f in sorted(os.listdir(alerts_dir), reverse=True):
            p = os.path.join(alerts_dir, f)
            if not os.path.isfile(p):
                continue
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        items.append(json.load(fh))
                except (json.JSONDecodeError, OSError) as e:
                    logger = get_logger("api.reports")
                    logger.debug("Failed to load alert file %s: %s", p, e)
                    continue
        return {"alerts": items}

    app.include_router(alerts_router)


def setup_exception_handlers(app: FastAPI):
    """Configure exception handlers"""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        logger = get_logger("api.errors")
        logger.warning(
            f"HTTP Exception: {exc.status_code} - {exc.detail}",
            extra={
                "status_code": exc.status_code,
                "detail": exc.detail,
                "url": str(request.url),
                "method": request.method,
            },
        )

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {"code": exc.status_code, "message": exc.detail, "type": "HTTPException"},
                "request": {"method": request.method, "url": str(request.url)},
            },
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger = get_logger("api.errors")
        logger.error(
            f"Unhandled Exception: {str(exc)}",
            extra={"exception_type": type(exc).__name__, "url": str(request.url), "method": request.method},
            exc_info=True,
        )

        return JSONResponse(
            status_code=500,
            content={
                "error": {"code": 500, "message": "Internal server error", "type": "InternalServerError"},
                "request": {"method": request.method, "url": str(request.url)},
            },
        )


# Dependency injection


async def get_iam() -> AgenticIAM:
    """Get IAM instance dependency"""
    if not iam_instance:
        raise HTTPException(status_code=503, detail="IAM system not initialized")
    return iam_instance


async def get_settings() -> Settings:
    """Get settings instance dependency"""
    if not settings_instance:
        raise HTTPException(status_code=503, detail="Settings not initialized")
    return settings_instance


# Create app instance
app = create_app()

# Root endpoint


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "Agentic-IAM API",
        "version": "1.0.0",
        "description": "Comprehensive Agent Identity & Access Management Platform",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
    }


# API info endpoint


@app.get("/api/v1")
async def api_info():
    """API version information"""
    return {
        "version": "1.0.0",
        "endpoints": {
            "agents": "/api/v1/agents",
            "authentication": "/api/v1/auth",
            "authorization": "/api/v1/authz",
            "sessions": "/api/v1/sessions",
            "intelligence": "/api/v1/intelligence",
            "audit": "/api/v1/audit",
        },
        "documentation": {"openapi": "/openapi.json", "swagger": "/docs", "redoc": "/redoc"},
    }


# Mount GraphQL endpoint (lazy load to avoid circular imports)


def mount_graphql():
    try:
        from api import graphql as graphql_module

        graphql_app = graphql_module.create_graphql_app(iam_instance)
        app.mount("/graphql", graphql_app)
    except Exception as e:
        logger = get_logger("api.startup")
        logger.debug("GraphQL mount skipped: %s", e)


# Try mounting after app creation
try:
    mount_graphql()
except Exception as e:
    logger = get_logger("api.startup")
    logger.debug("Deferred GraphQL mount failed: %s", e)

if __name__ == "__main__":
    # Development server
    settings = Settings()

    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.auto_reload,
        log_level=settings.log_level.lower(),
        access_log=True,
    )
